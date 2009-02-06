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
require 'generators'

class Producer < Generators::NewGen

    START_AT=190000

    Template=File.open( File.join(Config["WORK DIR"],"boof.doc"),"rb") {|io| io.read}

    def hexdump(str)
        ret=""
        str.unpack('H*').first.scan(/.{2}/).each_slice(16) {|s| 
            ret << "%-50s" % s.join(' ') 
            ret << s.map {|e| e.hex}.pack('c*').tr("\000-\037\177-\377",'.')
            ret << "\n"
        }
        ret
    end

    def initialize
        @block=Fiber.new do
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
                fib=WordStructures::WordFIB.new(raw_fib.clone)
                raise RuntimeError, "Data Corruption - fib.to_s not raw_fib" unless fib.to_s == raw_fib
                # Open the file, get a copy of the table stream
                ole=Ole::Storage.open(File.join(Config["WORK DIR"],"boof.doc"),'rb')
                table_stream=ole.file.read("1Table")
                ole.close
                fib.groups[:ol][50..-1].each {|fc,lcb|
                    next if fib.send(lcb)==0
                    #get the head, fuzztarget and rest from the table stream
                    puts "Starting #{fc.to_s}, #{lcb.to_s}, #{fib.send(lcb)}"
                    ts_head=table_stream[0,fib.send(fc)]
                    fuzztarget=table_stream[fib.send(fc),fib.send(lcb)]
                    ts_rest=table_stream[fib.send(fc)+fib.send(lcb)..-1]
                    raise RuntimeError, "Data Corruption - TS corrupt" unless (ts_head+fuzztarget+ts_rest)==table_stream
                    raise RuntimeError, "Data Corruption - LCB / fuzztarget length mismatch" unless fib.send(lcb)==fuzztarget.length
                    #create a new Fuzzer using the fuzztarget
                    bs=Fuzzer.string_to_binstruct(fuzztarget,16)
                    raise RuntimeError, "Data Corruption - Binstruct.to_s not fuzztarget" unless bs.to_s == fuzztarget
                    f=Fuzzer.new(bs)
                    f.preserve_length=true
                    puts "Expecting #{f.count_tests(1024,false)} tests..." rescue puts $!
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
                        Fiber.yield( (header+newfib.to_s+rest) )
                    }
                }
            rescue
                puts "Production failed: #{$!}";$stdout.flush
                exit
            end
            false
        end
        START_AT.times do @block.resume end
        super
    end


end
