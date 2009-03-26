require 'fields'
require 'objhax'

class BinStruct

    class Bitfield < BinStruct
    end
    attr_reader :groups
    attr_accessor :fields, :endian
    #---------------CONSTRUCTION-------------------
    def endian( sym )
        unless sym==:little || sym==:big
            raise RuntimeError, "BinStruct: Construction: Unknown endianness #{sym.to_s}"
        end
        @endian=sym
        meta_def :endian do @endian end
        meta_def :endianness do @endian end
    end

    def bitfield(bitbuf, len, &blk)
        if @endian==:little
            unless len==16||len==32||len==64
                raise RuntimeError, "BinStruct: Bitfield: Don't know how to endian swap #{len} bits. :("
            end
            instr=bitbuf.slice!(0,len).scan(/.{8}/).reverse.join
        else
            instr=bitbuf.slice!(0,len)
        end
        new=Bitfield.new([instr].pack('B*'), &blk)
        if @endian==:little
            # This is so we know to flip the bytes back in #to_s
            new.instance_variable_set :@endian_flip_hack, true
        end
        @fields << new
        # Add direct references and accessor methods to the containing Binstruct
        new.fields.each {|f| 
            unless f.is_a? Fields::Field
                raise RuntimeError, "BinStruct: Construction: Illegal content #{f.class} in bitfield - use only Fields"
            end
            @hash_references[f.name]=f
            meta_def f.name do f.get_value end
            meta_def (f.name.to_s + '=').to_sym do |val| f.set_value(val) end
        }
    end

    def substruct(strbuf, name, len, klass)
        new=klass.new(strbuf)
        @fields << new
        @hash_references[name]=new
        meta_def name do new end
        # More informative than the NoMethodError they would normally get.
        meta_def (name.to_s + '=').to_sym do raise NoMethodError, "BinStruct: Illegal call of '=' on a substruct." end
    end

    #fieldtype builders
    Fields::Field_Subtypes.each {|fieldname|
        field_klass=Fields.const_get(fieldname.capitalize.to_s+"Field")
        define_method fieldname do |*args|
            bitbuf, name, len, desc=args
            @fields << thisfield=field_klass.new(bitbuf.slice!(0,len),name,len,desc,nil,@endian||:big)
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
    def initialize(buffer=nil, &blk)
        @fields=[]
        @hash_references={}
        @endian_flip_hack=false
        @groups=Hash.new {|h,k| h[k]=[]}
        buffer||=""
        @bitbuf=buffer.unpack('B*').join
        if block_given?
            instance_exec(@bitbuf, &blk)
        elsif self.class.init_block
            instance_exec(@bitbuf, &self.class.init_block)
        else
            # do nothing, user probably just wants a blank struct to manually add fields.
        end
        endian :big unless @endian
        @groups.each {|group, contents|
            unless contents.flatten.all? {|sym| @hash_references.keys.any? {|othersym| othersym==sym}}
                raise RuntimeError, "BinStruct: Construction: group #{group} contains invalid field name(s)"
            end
        }
        # This is not ideal for structures that aren't byte aligned, but raising an exception 
        # would be less flexible.
        buffer.replace @bitbuf.scan(/.{8}/).map {|e| e.to_i(2).chr}.join unless buffer.nil?
    end
    #----------------INSTANCE----------------------
    def []( sym )
        # return an object, specified by symbol. May be a field or a substruct.
        # not designed for bitfields, since they're supposed to be invisible
        # containers.
        @hash_references[sym]
    end

    def each( &blk )
        # yield each object to the block. This is a little messy, because
        # substructs are not Fields::Field types. For Bitfields, just silently
        # yield each component, not the container field. The upshot of all this
        # is that the caller needs to be prepared for a Field or a BinStruct in the
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
        # yield all fields in the structure, entering nested substructs as necessary
        @fields.each {|atom|
            if atom.is_a? BinStruct
                atom.deep_each &blk unless atom.fields.empty?
            else
                yield atom
            end
        }
    end

    def replace(oldthing, newthing)
        k,v=@hash_references.select {|k,v| v==oldthing}.flatten
        @hash_references[k]=newthing
        @fields.map! {|atom|
            if atom==oldthing
                newthing
            else
                if atom.is_a? BinStruct
                    atom.replace(oldthing,newthing)
                end
                atom
            end
        }
    end

    def flatten
        a=[]
        self.deep_each {|f| a << f}
        a
    end

    def to_s
        #pack current struct as a string - for Fields, it will use the bitstring, for
        #anything else (including Bitfields and BinStructs) it will use to_s.unpack('B*')
        bits=@fields.inject("") {|str,field| 
            field.kind_of?(Fields::Field) ?  str << field.bitstring : str << field.to_s.unpack('B*').join
        } 
        unless bits.length % 8 == 0
            #puts "Warning, structure not byte aligned, right padding with 0"
        end
        return "" if bits.empty?
        bytearray=bits.scan(/.{1,8}/)
        # If not byte aligned, right pad with 0
        bytearray.last << '0'*(8-bytearray.last.length) if bytearray.last.length < 8
        bytearray=bytearray.reverse if @endian_flip_hack
        bytearray.map {|byte| "" << byte.to_i(2)}.join
    end

    def length
        self.to_s.length
    end
    
    def inspect
        self.flatten.map {|field| "<IDX:#{self.flatten.index(field)}><#{field.class.to_s.match(/::(.+)Field/)[1]}><#{field.name}><#{field.length}><#{field.to_s[0..12].each_byte.to_a.map {|b| "%.2x" % b}.join(' ') + (field.to_s.length>12?"...":"")}>"}
    end
end


