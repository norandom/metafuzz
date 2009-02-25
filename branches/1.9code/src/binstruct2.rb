require 'fields'
require 'objhax'

class Binstruct

    class Bitfield < Binstruct
    end
    attr_reader :groups, :endian
    attr_accessor :fields
    #---------------CONSTRUCTION-------------------
    def endian( sym )
        unless sym==:little || sym==:big
            raise RuntimeError, "BinStruct: Construction: Unknown endianness #{sym.to_s}"
        end
        @endian=sym
        meta_def :endian do sym end
        meta_def :endianness do sym end
    end

    def bitfield(buf, len, &blk)
        @bs||=buf.unpack('B*').first
        if @endian==:little
            unless len==16||len==32||len==64
                raise RuntimeError, "Binstruct: Bitfield: Don't know how to endian swap #{len} bits. :("
            end
            instr=@bs.slice!(0,len).scan(/.{8}/).reverse.join.reverse
        else
            instr=@bs.slice!(0,len)
        end
        new=Bitfield.new([instr].pack('B*'), &blk)
        if @endian==:little
            new.instance_variable_set :@endian_flip_hack, true
        end
        @fields << new
        new.fields.each {|f| 
            unless f.is_a? Fields::Field
                raise RuntimeError, "Binstruct: Construction: Illegal content #{f.class} in bitfield - use only Fields"
            end
            @hash_references[f.name]=f
            meta_def f.name do f.get_value end
            meta_def (f.name.to_s + '=').to_sym do |val| f.set_value(val) end
        }
    end

    def substruct(buf, name, len, klass)
        @bs||=buf.unpack('B*').first
        new=klass.new([@bs.slice!(0,len)].pack('B*'))
        @fields << new
        @hash_references[name]=new
        meta_def name do new end
        # More informative than the NoMethodError they would normally get.
        meta_def (name.to_s + '=').to_sym do raise NoMethodError, "Binstruct: Illegal call of '=' on a substruct." end
    end

    #fieldtype builders
    Fields::Field_Subtypes.each {|fieldname|
        field_klass=Fields.const_get(fieldname.capitalize.to_s+"Field")
        define_method fieldname do |*args|
            buffer, name, len, desc=args
            @bs||=buffer.unpack('B*').first
            @fields << thisfield=field_klass.new(@bs.slice!(0,len),name,len,desc,nil,@endian||:big)
            @hash_references[name.to_sym]=thisfield
            meta_def name do thisfield.get_value end
            meta_def (name.to_s + '=').to_sym do |val| thisfield.set_value(val) end
        end
    }

    def group( groupname, *fieldsyms )
        @groups[groupname] << fieldsyms
    end

    class << self
        attr_reader :init_block
    end
    def self.parse( &blk )
        @init_block=blk
    end
    #------------END CONSTRUCTION------------------
    def initialize(*args, &blk)
        @fields=[]
        @hash_references={}
        @endian_flip_hack=false
        @groups=Hash.new {|h,k| h[k]=[]}
        args<<"" if args.empty?
        if block_given?
            instance_exec(*args, &blk)
        else
            instance_exec(*args, &self.class.init_block)
        end
        endian :big unless @endian
        @groups.each {|group, contents|
            unless contents.flatten.all? {|sym| @hash_references.keys.any? {|othersym| othersym==sym}}
                raise RuntimeError, "Binstruct: Construction: group #{group} contains invalid field name(s)"
            end
        }
    end
    #----------------INSTANCE----------------------
    def[]( sym )
        # return an object, specified by symbol. May be a field or a substruct.
        # not designed for bitfields, since they're supposed to be invisible
        # containers.
        @hash_references[sym]
    end

    def each( &blk )
        # yield each object to the block. This is a little messy, because
        # substructs are not Fields::Field types. For Bitfields, just silently
        # yield each component, not the container field. The upshot of all this
        # is that the caller needs to be prepared for a Field or a Binstruct in the
        # block. This is the 'shallow' each.
        @fields.each {|atom|
            if atom.is_a? Bitfield
                atom.fields.each {|f| yield f}
            else
                yield atom
            end
        }

    end

    def deep_each( &blk )
        # yield all fields in the structure, entering nested substructs as neccessary
        @fields.each {|atom|
            if atom.is_a? Bitfield
                atom.fields.each {|f| yield f}
            elsif atom.is_a? Binstruct # but not a Bitfield
                atom.deep_each &blk
            else
                yield atom
            end
        }
    end

    def to_s
        #pack current struct as a string - for Fields, it will use the bitstring, for
        #anything else (including Bitfields and Binstructs) it will use to_s.unpack('B*')
        bits=@fields.inject("") {|str,field| 
            field.kind_of?(Fields::Field) ?  str << field.bitstring : str << field.to_s.unpack('B*').join
        } 
        unless bits.length % 8 == 0
            puts "Warning, structure not byte aligned, right padding with 0"
        end
        bits=bits.reverse if @endian_flip_hack
        bytearray=bits.scan(/.{1,8}/)
        bytearray.last << '0'*(8-bytearray.last.length) if bytearray.last.length < 8
        bytearray=bytearray.reverse if @endian_flip_hack
        bytearray.map {|byte| "" << byte.to_i(2)}.join
    end

    def length
        self.to_s.length
    end
end


class WordDgg < Binstruct
    parse{ |buffer|
        endian :little
        bitfield(buffer, 16) do |buf|
            unsigned buf, :type, 4, "Object type, 0xF for container"
            unsigned buf, :oid, 12, "Object Identifier"
        end
        unsigned buffer, :content_length, 32, "Content length"
        if self.type==0xF
            substruct(buffer, :contents, self.content_length, WordDgg)
        else
            hexstring buffer, :contents, self.content_length, "Contents"
        end
        if buffer ==""
            self.type=0xF
            self.oid=0x222
            self.content_length=0
        end
    }
end

if __FILE__==$0
    puts "Starting tests..."
    w=WordDgg.new("\x0f\x00\xf0\x00\x00\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    p w.to_s.length
    p w.type
    p w.content_length
    p w[:contents].contents
    w.deep_each {|atom| puts "#{atom.class}, #{atom.name}"}
end
