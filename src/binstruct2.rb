require 'objhax'

class Binstruct

    #---------------CONSTRUCTION-------------------
    #fieldtype builders
    def endian( sym )
        unless sym==:little || sym==:big
            raise RuntimeError, "BinStruct: Construction: Unknown endianness #{sym.to_s}"
        end
        meta_def :endian do sym end
    end

    def group( groupname, *fieldsyms )
    end
    #------------END CONSTRUCTION------------------


    #----------------INSTANCE----------------------
    def[]
        # return an object, specified by symbol. May be a field or a substruct.
        # not designed for bitfields, since they're supposed to be invisible
        # containers.
    end

    def each( &blk )
        # yield each object to the block. This is a little messy, because
        # substructs are not Fields::Field types. For Bitfields, just silently
        # yield each component, not the container field. The upshot of all this
        # is that the caller needs to be prepared for a Field or a Binstruct in the
        # block. This is the 'shallow' each.
    end
    
    def deep_each( depth=0, &blk )
        # yield each field, recursing through substructs.
    end
    
    def to_s
        #pack current struct as a string - for Fields, it will use the bitstring, for
        #anything else it will use to_s.unpack('B*')
    end

    def length
        self.to_s.length
    end
end

class FooStruct < Binstruct
    def initialize( buf )
        endian :big
    end
end
=begin
def WordDgg < Binstruct
    define {|buffer|
        endian :big
        bitfield(buffer, 16) do |buf|
            unsigned buf, :type, 4, "Object type, 0xF for container"
            unsigned buf, :oid, 12, "Object Identifier"
        end
        unsigned buffer, :content_length, 32, "Content length"
        if self.type==0xF
            substruct(buffer, :contents, self.content_length) do |instr|
                WordDgg.new(instr)
            end
        else
            hexstring buffer, :contents, self.content_length, "Contents"
        end
        if buffer ==""
            self.type=0xF
            self.oid=0x200
            self.length=0
            self.contents=""
        end
    }
end
=end

if __FILE__==$0
    puts "Starting tests..."
    f=FooStruct.new("foo")
    p f.endian
end
