require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'
require 'thread'
require 'fuzzer'
require 'fib'
require 'diff/lcs'

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
    def template=(data)
        Thread.critical=true
        @template=data
    ensure
        Thread.critical=false
    end
    def template
        Thread.critical=true
        @template||=""
    ensure
        Thread.critical=false
    end
end
production=Thread.new do
    begin
        header,raw_fib,rest=""
        unmodified_file=File.open( 'c:\share\boof.doc',"rb") {|io| io.read}
        File.open( 'c:\share\boof.doc',"rb") {|io| 
            header=io.read(512)
            raw_fib=io.read(1472)
            rest=io.read
        }
        raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == unmodified_file
        prod_queue.template=unmodified_file
        g=Generators::RollingCorrupt.new(raw_fib,8,8)
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
=begin
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
        fib=WordFIB.new(raw_fib)
        fib.fcSttbfffn=0xffffffff
        32768.times do |i|
            fib.fcSttbfffn=0xffffffff - ((16*i)+1)
            fuzzed=fib.to_s
            prod_queue << (header+fuzzed+rest)
        end
        prod_queue.finish
        Thread.current.exit	
    rescue
        puts "Production failed: #{$!}";$stdout.flush
        exit
    end
end
=end
class ResultTracker
    def initialize
        @sent=0
        @mutex=Mutex.new
        @results={}
        @time_mark=Time.now
        @sent_mark=0
    end

    def increment_sent
        Thread.critical
        @sent+=1
    ensure
        Thread.critical=false
    end

    def add_result(id, status)
        Thread.critical
        unless @results[id]=="CHECKED OUT"
            raise RuntimeError, "RT: The id not checked out yet?"
        end
        @results[id]=status
    ensure
        Thread.critical=false
    end

    def check_out
        Thread.critical
        increment_sent
        @results[@sent]="CHECKED OUT"
        @sent
    ensure
        Thread.critical=false
    end

    def spit_results
        Thread.critical
        succeeded=@results.select {|k,v| v=="SUCCESS"}.length
        hangs=@results.select {|k,v| v=="HANG"}.length
        fails=@results.select {|k,v| v=="FAIL"}.length
        crashes=@results.select {|k,v| v=="CRASH"}.length
        unknown=@results.select {|k,v| v=="CHECKED OUT"}.length
        if @sent%100==0
            @sent_mark=@sent
            @time_mark=Time.now
        end
        puts "Results: crash: #{crashes}, hang: #{hangs}, fail: #{fails}, success: #{succeeded}, no result: #{unknown}."
        puts "(#{@sent} sent, #{@results.length} in result hash. Performance: #{"%.2f"%((@sent-@sent_mark)/(Time.now-@time_mark).to_f)}/s)"
    ensure
        Thread.critical=false
    end
end

module FuzzServer

    def initialize(prod_queue, rt)
        @production_queue=prod_queue
        @template=@production_queue.template
        @result_tracker=rt
        @handler=NetStringTokenizer.new
        @clients=0
        EM.add_periodic_timer(30) {@result_tracker.spit_results}
        at_exit {@result_tracker.spit_results}
    end

    def handle_client_ready(msg)
        unless msg.data.empty? # first request
            result_id,result_status=msg.data.split(':')
            @result_tracker.add_result(Integer(result_id),result_status)
        end
        if @production_queue.empty? and @production_queue.finished?
            send_data(@handler.pack(FuzzMessage.new({:verb=>"SERVER FINISHED"}).to_yaml))
            @clients-=1
            EventMachine::stop_event_loop if clients <= 0
        else
            # define a block to prepare the response
            get_data=proc do
                # This pop will block until data is available
                # but since we are using EM.defer that's OK
                my_data=@production_queue.pop
                id=@result_tracker.check_out
                # This is what will be passed to the callback
                diffs=Diff::LCS.diff(@template,my_data)
                @handler.pack(FuzzMessage.new({:verb=>"DELIVER",:data=>diffs,:id=>id}).to_yaml)
            end
            # This callback will be invoked once the response is ready.
            callback=proc do |data|
                send_data data
            end
            # Send the work to the thread queue, so we are ready for more connections.
            EM.defer(get_data, callback)
        end
    end

    def handle_client_startup
        send_data @handler.pack(FuzzMessage.new({:verb=>"TEMPLATE",:data=>@template}).to_yaml)
        @clients+=1
    end

    def handle_client_shutdown
        @clients-=1
    end

    def receive_data(data)
        @handler.parse(data).each do |m| 
            msg=FuzzMessage.new(m)
            case msg.verb
            when "CLIENT READY"
                handle_client_ready(msg)
            when "CLIENT STARTUP"
                handle_client_startup
            when "CLIENT SHUTDOWN"
                handle_client_shutdown
            end
        end
    end

end

rt=ResultTracker.new
EventMachine::run {
    EventMachine::start_server("0.0.0.0", 10000, FuzzServer, prod_queue, rt)
}
rt.spit_results
