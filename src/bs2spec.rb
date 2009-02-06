class ODgg < BinStruct2
    parse {|buf|
        endian :big
        bitfield(buf, 16) {|s|
            unsigned :recver, s, 4
            unsigned :recinstance, s, 12
        }
        unsigned :rectype, buf, 16
        unsigned :reclen, buf, 32
        if self.recver==0xf
            hexstring :contents, buf, @reclen*8
            substruct(:contents, ODgg)
        else
            hexstring :contents, buf, @reclen*8
        end
    }
end
