require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'
require 'thread'
require 'fuzzer'

prod_queue=SizedQueue.new(20)
# Quickly patch the queue object to add a finished? method
# Couldn't think of anything more elegant.
class << prod_queue
    def finish 
        Thread.critical=true
        @finished=true
    ensure
        Thread.critical=false
    end
    def finished?
        Thread.critical=true
        @finished||=false
    ensure
        Thread.critical=false
    end
end

prod_thread=Thread.new do
    begin
        puts "Production thread starting..."
        unmodified_file=File.open( 'c:\share\boof.doc',"rb") {|io| io.read}
        header,raw_fib,rest=""
        File.open( 'c:\share\boof.doc',"rb") {|io| 
            header=io.read(512)
            raw_fib=io.read(1472)
            rest=io.read
        }
        raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == unmodified_file
        g=Generators::RollingCorrupt.new(raw_fib,8,3)
        while g.next?
            fuzzed=g.next
            raise RuntimeError, "Data Corruption" unless fuzzed.length==raw_fib.length
            prod_queue << (header+fuzzed+rest)
        end
        prod_queue.finish
        Thread.current.exit	
    rescue
        puts "Production failed: #{$!}";$stdout.flush
        exit
    end
end

module FuzzServer

    def post_init
        @handler=NetStringTokenizer.new
    end

    def spit_results
        @result_mutex.synchronize {
            succeeded=@results.select {|k,v| v=="SUCCESS"}.length
            hangs=@results.select {|k,v| v=="HANG"}.length
            fails=@results.select {|k,v| v=="FAIL"}.length
            crashes=@results.select {|k,v| v=="CRASH"}.length
            unknown=@results.select {|k,v| v=="CHECKED OUT"}.length
            puts "Results: crash: #{crashes}, hang: #{hangs}, fail: #{fails}, success: #{succeeded}, no result: #{unknown}."
            @sent_mutex.synchronize {
                puts "(#{@sent} sent, #{@results.length} in result hash.)"
            }
        }
    end

    def initialize(prod_queue,result_hash,result_mutex)
        @production_queue=prod_queue
        @sent=0
        @sent_mutex=Mutex.new
        @results={}
        @result_mutex=result_mutex
        EM.add_periodic_timer(30) {spit_results}
        at_exit {spit_results}
    end

    def receive_data(data)
        @handler.parse(data).each do |m| 
            msg=FuzzMessage.new(m)
            puts msg.verb
            puts msg.data.inspect
            puts m.inspect
            if msg.verb=="CLIENT READY"
                if msg.data
                    result_id,result_status=msg.data.split(':')
                    @result_mutex.synchronize {
                        @results[result_id]=result_status
                    }
                end
                if @production_queue.empty? and @production_queue.finished?
                    send_data(@handler.pack(FuzzMessage.new({:verb=>"SERVER FINISHED"}).to_yaml))
                else
                    # define a block to prepare the response
                    get_data=proc do
                        # This pop will block until data is available
                        # but since we are using EM.defer that's OK
                        my_data=@production_queue.pop
                        # This is what will be passed to the callback
                        @sent_mutex.synchronize {
                            msg_id=@sent
                            @result_mutex.synchronize {
                                @results[@sent]="CHECKED OUT"
                            }
                            @sent+=1
                        }
                        @handler.pack(FuzzMessage.new({:verb=>"DELIVER",:data=>my_data,:id=>@sent}).to_yaml)
                    end
                    # This callback will be invoked once the response is ready.
                    callback=proc do |data|
                        send_data data
                    end
                    # Send the work to the thread queue, so we are ready for more connections.
                    EM.defer(get_data, callback)
                end
            end
        end
    end

end

EventMachine::run {
    EventMachine::start_server("0.0.0.0", 10000, FuzzServer, prod_queue)
}
