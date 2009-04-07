require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'
require 'thread'
require 'fuzzer'
require 'wordstruct'
require 'ole/storage'
require 'mutations'

class Producer < Generators::NewGen

    Template=File.open( File.expand_path('~/wordcrashes/boof.doc'),"rb") {|io| io.read}
    Template.freeze

    def initialize
        @block=Fiber.new do
            begin
                io=StringIO.new(Template.clone)
                header, raw_fib, rest=io.read(512), io.read(1472), io.read
                fib=WordStructures::WordFIB.new(raw_fib)
                # Open the file, get a copy of the table stream
                io.rewind
                ole=Ole::Storage.open(io)
                table_stream=ole.file.read(fib.fWhichTblStm.to_s+"Table")
                ole.close
                fib.groups[:ol][0..-1].each {|fc,lcb|
                    next if fib.send(lcb)==0
                    #get the head, fuzztarget and rest from the table stream
                    puts "Starting #{fc.to_s}, #{lcb.to_s}, #{fib.send(lcb)}"
                    ts_head=table_stream[0,fib.send(fc)]
                    fuzztarget=table_stream[fib.send(fc),fib.send(lcb)]
                    ts_rest=table_stream[fib.send(fc)+fib.send(lcb)..-1]
                    raise RuntimeError, "Data Corruption" unless (ts_head+fuzztarget+ts_rest)==table_stream
                    raise RuntimeError, "Data Corruption" unless fib.send(lcb)==fuzztarget.length
                    #create a new Fuzzer using the fuzztarget
                    bs=Fuzzer.string_to_binstruct(fuzztarget,16,:little)
                    raise RuntimeError, "Data Corruption" unless bs.to_s == fuzztarget
                    f=Fuzzer.new(bs)
                    #puts "Expecting #{f.count_tests(10000,false)} tests..."
                    f.basic_tests(10000,false) {|fuzz|
                        #head+fuzzed+rest
                        fuzzed_table=ts_head+fuzz.to_s+ts_rest
                        #write the modified stream
                        io.rewind
                        Ole::Storage.open(io) {|ole|
                            ole.file.open(fib.fWhichTblStm.to_s+"Table","wb+") {|f| f.write( fuzzed_table )}
                        }
                        io.rewind
                        # Read in the new file contents
                        header, raw_fib, rest=io.read(512), io.read(1472), io.read
                        newfib=WordStructures::WordFIB.new(raw_fib)
                        #adjust the lcb
                        newfib.send((lcb.to_s+'=').to_sym, fuzz.length)
                        #adjust the offsets for all subsequent structures
                        delta=fuzz.to_s.length-fuzztarget.length
                        unless delta == 0
                            fib.groups[:ol].each {|off,len|
                                if (fib.send(off) > fib.send(fc)) and fib.send(len) > 0
                                    newfib.send((off.to_s+'=').to_sym, fib.send(off)+delta)
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
        super
    end

end
