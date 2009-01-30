require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'
require 'thread'
require 'fuzzer'
require 'fib'
require 'diff/lcs'
require 'wordstruct'
require 'ole/storage'
require 'mutations'
require 'tempfile'

module Producer

    Template=File.open( 'c:\share\boof.doc',"rb") {|io| io.read}

    def each_item
        begin
            unmodified_file=Template
            header,raw_fib,rest=""
            temp_file=Tempfile.new('wordfuzz')
            File.open(temp_file.path,"wb+") {|io| io.write Template}
            File.open(temp_file.path, "rb") {|io| 
                header=io.read(512)
                raw_fib=io.read(1472)
                rest=io.read
            }
            raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == unmodified_file
            fib=WordStructures::WordFIB.new(raw_fib)
            # Open the file, get a copy of the table stream
            ole=Ole::Storage.open('c:\share\boof.doc','rb')
            table_stream=ole.file.read("1Table")
            ole.close
            fib.groups[:ol][15..-1].each {|fc,lcb|
                next if fib.send(lcb)==0
                #get the head, fuzztarget and rest from the table stream
                puts "Starting #{fc.to_s}, #{lcb.to_s}, #{fib.send(lcb)}"
                ts_head=table_stream[0,fib.send(fc)]
                fuzztarget=table_stream[fib.send(fc),fib.send(lcb)]
                ts_rest=table_stream[fib.send(fc)+fib.send(lcb)..-1]
                raise RuntimeError, "Data Corruption" unless (ts_head+fuzztarget+ts_rest)==table_stream
                raise RuntimeError, "Data Corruption" unless fib.send(lcb)==fuzztarget.length
                #create a new Fuzzer using the fuzztarget
                bs=Fuzzer.string_to_binstruct(fuzztarget,16)
                raise RuntimeError, "Data Corruption" unless bs.to_s == fuzztarget
                f=Fuzzer.new(bs)
                #puts "Expecting #{f.count_tests(1024,false)} tests..."
                f.basic_tests(1024,false) {|fuzz|
                    #head+fuzzed+rest
                    fuzzed_table=ts_head+fuzz.to_s+ts_rest
                    #write the modified stream
                    Ole::Storage.open(temp_file.path,'rb+') {|ole|
                        ole.file.open("1Table","wb+") {|f| f.write( fuzzed_table )}
                    }
                    # Read in the new file contents
                    File.open( temp_file.path,"rb") {|io| 
                        header=io.read(512)
                        raw_fib=io.read(1472)
                        rest=io.read
                    }
                    newfib=WordStructures::WordFIB.new(raw_fib)
                    #adjust the lcb
                    newfib.send((lcb.to_s+'=').to_sym, fuzz.length)
                    #adjust the offsets for all subsequent structures
                    extra=fuzz.length-fuzztarget.length
                    if extra > 0
                        fib.groups[:ol].each {|off,len|
                            if (fib.send(off) > fib.send(fc)) and fib.send(len) > 0
                                newfib.send((off.to_s+'=').to_sym, fib.send(off)+extra)
                            end
                        }
                    end
                    #add to the queue
                    yield( (header+newfib.to_s+rest) )
                }
            }
        rescue
            puts "Production failed: #{$!}";$stdout.flush
            exit
        end
    end

    module_function :each_item

end
