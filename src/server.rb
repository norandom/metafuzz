require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'
require 'thread'
require 'fuzzer'
require 'fib'
require 'diff/lcs'


default_config={"AGENT NAME"=>"SERVER",
    "SERVER IP"=>"0.0.0.0",
    "SERVER PORT"=>10000,
    "WORK DIR"=>'C:\fuzzserver',
    "CONFIG DIR"=>'C:\fuzzserver',
    "COMPRESSION"=>false,
    "SEND DIFFS ONLY"=>false,
    "USE THREADPOOL"=>true,
    "POLL INTERVAL"=>5
}

config_file=ARGV[0]
if config_file and not File.exists? config_file
    puts "FuzzServer: Bad config file #{config_file}, using default config."
    config=default_config
elsif not config_file
    puts "FuzzServer: Using default config."
    config=default_config
else
    begin
        config_data=File.open(config_file, "r") {|io| io.read}
        config=YAML::load(config_data)
    rescue
        puts "FuzzServer: Bad config file #{config_file}, using default config."
        config=default_config
    end
end

["CONFIG DIR","WORK DIR"].each { |dirname|
    unless File.directory? config[dirname]
        print "Directory #{dirname} doesn't exist. Create it? [y/n]: "
        answer=STDIN.gets.chomp
        if answer =~ /^[yY]/
            begin
                Dir.mkdir(config[dirname])
            rescue
                raise RuntimeError, "FuzzServer: Couldn't create directory: #{$!}"
            end
        else
            raise RuntimeError, "FuzzServer: #{dirname} unavailable. Exiting."
        end
    end
}

at_exit {
    print "Saving config to #{config["CONFIG DIR"]}..."
    begin
        File.open(File.join(config["CONFIG DIR"],"fuzzserver_config.txt"),"w+") { |io|
            io.write(YAML::dump(config))
        }
    rescue
        puts "FuzzServer: Couldn't write out config."
    end
    print "Done. Exiting.\n"
}

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
        unmodified_file=File.open( 'c:\share\boof.doc',"rb") {|io| io.read}
=begin
        header,raw_fib,rest=""
        File.open( 'c:\share\boof.doc',"rb") {|io| 
            header=io.read(512)
            raw_fib=io.read(1472)
            rest=io.read
        }
        raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == unmodified_file
=end
        prod_queue.template=unmodified_file
        loop do
            insertion_start=rand(unmodified_file.length)
            insertion_finish=insertion_start+rand(256)+1
            head=unmodified_file[0..insertion_start-1]
            fuzz=unmodified_file[insertion_start..insertion_finish]
            tail=unmodified_file[insertion_finish+1..-1]
            raise RuntimeError, "Data Corruption" unless head+fuzz+tail == unmodified_file
            g=Generators::RollingCorrupt.new(fuzz,16,16,16)
            while g.next?
                fuzz=g.next
                prod_queue << (head+fuzz+tail)
            end
            gJunk=Mutations.create_string_generator(Array((0..255)).map {|e| "" << e},5000)
            gLetters=Mutations.create_string_generator(['p'],5000)
            gInject=Generators::Chain.new(gJunk,gLetters)
            while gInject.next
                prod_queue << (head+gInject.next+tail)
            end
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
    # This is bloat, but rewriting it as a nested loop would be a pain and
    # probably 5 levels deep
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
        fib.groups[:ol].each {|fc,lcb|
            orig_fc, orig_lcb=fib.send(fc), fib.send(lcb)
            # rand, rand
            32.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, rand(2**fib[fc].length))
                    fib.send((lcb.to_s+'=').to_sym, rand(2**fib[lcb].length))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            # + +
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc+i)
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb+i)
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc+((i*4)-1))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb+((i*4)-1))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc+(i*4))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb+(i*4))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc+((i*16)-1))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb+((i*16)-1))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc+(i*16))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb+(i*16))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc+((i*32)-1))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb+((i*32)-1))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc+(i*32))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb+(i*32))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            # + -
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc+i)
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb-i)
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc+((i*4)-1))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb-((i*4)-1))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc+(i*4))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb-(i*4))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc+((i*16)-1))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb-((i*16)-1))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc+(i*16))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb-(i*16))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc+((i*32)-1))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb-((i*32)-1))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc+(i*32))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb-(i*32))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            # - +
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc-i)
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb+i)
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc-((i*4)-1))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb+((i*4)-1))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc-(i*4))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb+(i*4))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc-((i*16)-1))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb+((i*16)-1))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc-(i*16))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb+(i*16))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc-((i*32)-1))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb+((i*32)-1))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc-(i*32))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb+(i*32))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            # - -
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc-i)
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb-i)
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc-((i*4)-1))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb-((i*4)-1))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc-(i*4))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb-(i*4))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc-((i*16)-1))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb-((i*16)-1))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc-(i*16))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb-(i*16))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end
            16.times do |i|
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc-((i*32)-1))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb-((i*32)-1))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
                begin
                    fib.send((fc.to_s+'=').to_sym, orig_fc-(i*32))
                    fib.send((lcb.to_s+'=').to_sym, orig_lcb-(i*32))
                rescue
                    next
                end
                fuzzed=fib.to_s
                prod_queue << (header+fuzzed+rest)
            end

            fib.send((fc.to_s+'=').to_sym, orig_fc)
            fib.send((lcb.to_s+'=').to_sym, orig_lcb)
            raise RuntimeError, "Data Corruption" unless header+fib.to_s+rest == unmodified_file

        }
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
        @clients=0
        @mutex=Mutex.new
        @results={}
        @time_mark=Time.now
        @sent_mark=0
    end

    def add_client
        Thread.critical=true
        @clients+=1
    ensure
        Thread.critical=false
    end

    def remove_client
        Thread.critical=true
        @clients-=1
    ensure
        Thread.critical=false
    end

    def add_result(id, status)
        Thread.critical=true
        unless @results[id]=="CHECKED OUT"
            raise RuntimeError, "RT: The id not checked out yet?"
        end
        @results[id]=status
    ensure
        Thread.critical=false
    end

    def check_out
        Thread.critical=true
        @sent+=1
        @results[@sent]="CHECKED OUT"
        @sent
    ensure
        Thread.critical=false
    end

    def spit_results
        Thread.critical=true
        succeeded=@results.select {|k,v| v=="SUCCESS"}.length
        hangs=@results.select {|k,v| v=="HANG"}.length
        fails=@results.select {|k,v| v=="FAIL"}.length
        crashes=@results.select {|k,v| v=="CRASH"}.length
        unknown=@results.select {|k,v| v=="CHECKED OUT"}.length
        if @sent%100==0
            @sent_mark=@sent
            @time_mark=Time.now
        end
        print "\r"
        print "Crash: #{crashes}, Fail: #{fails}, Success: #{succeeded}, #{@sent} currently @ #{"%.2f"%((@sent-@sent_mark)/(Time.now-@time_mark).to_f)}/s"
    ensure
        Thread.critical=false
    end
end

module FuzzServer

    def initialize(prod_queue, rt, config)
        @config=config
        @production_queue=prod_queue
        @template=@production_queue.template
        @result_tracker=rt
        @handler=NetStringTokenizer.new
        EM.add_periodic_timer(30) {@result_tracker.spit_results}
        at_exit {@result_tracker.spit_results}
    end


    def handle_client_result(msg)
        result_id,result_status=msg.data.split(':')
        begin
            @result_tracker.add_result(Integer(result_id),result_status)
        rescue
            sleep 1
            @result_tracker.add_result(Integer(result_id),result_status)
        end
    end

    def handle_client_ready
        if @production_queue.empty? and @production_queue.finished?
            send_data(@handler.pack(FuzzMessage.new({:verb=>"SERVER FINISHED"}).to_yaml))
        else
            unless @config["USE THREADPOOL"]
                my_data=@production_queue.pop
                id=@result_tracker.check_out
                if @config["SEND DIFFS"]
                    diffs=Diff::LCS.diff(@template,my_data)
                    send_data @handler.pack(FuzzMessage.new({:verb=>"DELIVER",:data=>diffs,:id=>id}).to_yaml)
                else
                    send_data @handler.pack(FuzzMessage.new({:verb=>"DELIVER",:data=>my_data,:id=>id}).to_yaml)
                end
            else
                # define a block to prepare the response
                get_data=proc do
                    # This pop will block until data is available
                    # but since we are using EM.defer that's OK
                    my_data=@production_queue.pop
                    id=@result_tracker.check_out
                    # This is what will be passed to the callback
                    if @config["SEND DIFFS"]
                        diffs=Diff::LCS.diff(@template,my_data)
                        @handler.pack(FuzzMessage.new({:verb=>"DELIVER",:data=>diffs,:id=>id}).to_yaml)
                    else
                        @handler.pack(FuzzMessage.new({:verb=>"DELIVER",:data=>my_data,:id=>id}).to_yaml)
                    end
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

    def handle_client_startup
        send_data @handler.pack(FuzzMessage.new({:verb=>"TEMPLATE",:data=>@template}).to_yaml)
        @result_tracker.add_client
    end

    def handle_client_shutdown
        @result_tracker.remove_client
        if @production_queue.empty? and @production_queue.finished? and @result_tracker.clients <=0
            puts "All done, shutting down."
            EventMachine::stop_event_loop
        end
    end

    def receive_data(data)
        @handler.parse(data).each do |m| 
            msg=FuzzMessage.new(m)
            case msg.verb
            when "CLIENT RESULT"
                handle_client_result(msg)
            when "CLIENT READY"
                handle_client_ready
            when "CLIENT STARTUP"
                handle_client_startup
            when "CLIENT SHUTDOWN"
                handle_client_shutdown
            else
                #unknown command, real programmer would error handle.
                nil
            end
        end
    end

end

rt=ResultTracker.new
EventMachine::run {
    EventMachine::start_server(config["SERVER IP"], config["SERVER PORT"], FuzzServer, prod_queue, rt, config)
}
rt.spit_results
