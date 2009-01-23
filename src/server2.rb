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
require 'result_tracker'

default_config={"AGENT NAME"=>"SERVER",
    "SERVER IP"=>"0.0.0.0",
    "SERVER PORT"=>10001,
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
    if File.exists?(File.join(default_config["CONFIG DIR"],"fuzzserver_config.txt"))
        puts "FuzzServer: Loading from default config file."
        config_data=File.open(File.join(default_config["CONFIG DIR"],"fuzzserver_config.txt"), "r") {|io| io.read}
        config=YAML::load(config_data)
    else
        puts "Fuzzserver: Using default config."
        config=default_config
    end
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
                if dirname=="CONFIG DIR"
                    print "Saving config to #{config["CONFIG DIR"]}..."
                    begin
                        File.open(File.join(config["CONFIG DIR"],"fuzzserver_config.txt"),"w+") { |io|
                            io.write(YAML::dump(config))
                        }
                    rescue
                        puts "FuzzServer: Couldn't write out config."
                    end
                end
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

module FuzzServer

    def initialize(prod_queue, rt, config)
        @config=config
        @production_queue=prod_queue
        @template=false
        @result_tracker=rt
        @handler=NetStringTokenizer.new
        EM.add_periodic_timer(30) do 
            @result_tracker.spit_results
            if @production_queue.empty? and @production_queue.finished? and @result_tracker.results_outstanding==0
                puts "All done, shutting down."
                EventMachine::stop_event_loop
            end
        end
        at_exit {@result_tracker.spit_results}
    end


    def handle_result( msg )
        result_id,result_status=msg.id, msg.data
        begin
            @result_tracker.add_result(Integer(result_id),result_status)
        rescue
            sleep 1
            @result_tracker.add_result(Integer(result_id),result_status)
        end
    end

    # Only comes from fuzzclients.
    def handle_client_ready( msg )
        if @production_queue.empty? and @production_queue.finished?
            send_data(@handler.pack(FuzzMessage.new({:verb=>:server_bye}).to_yaml))
        else
            unless @config["USE THREADPOOL"]
                id, my_data=@production_queue.pop
                send_data @handler.pack(FuzzMessage.new({:verb=>:deliver,:data=>my_data,:id=>id}).to_yaml)
            else
                # define a block to prepare the response
                get_data=proc do
                    # This pop will block until data is available
                    # but since we are using EM.defer that's OK
                    id, my_data=@production_queue.pop
                    # This is what will be passed to the callback
                    @handler.pack(FuzzMessage.new({:verb=>:deliver,:data=>my_data,:id=>id}).to_yaml)
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

    def handle_client_startup( msg )
        case msg.client_type
        when :fuzz
            @result_tracker.add_fuzz_client
            if @config["SEND DIFFS"]
                # TODO: this probably won't work
                sleep 0.1 until @template # in case the fuzzclient starts up before the production client
                send_data @handler.pack(FuzzMessage.new({:verb=>:server_ready,:template=>@template}).to_yaml)
            else
                send_data @handler.pack(FuzzMessage.new({:verb=>:server_ready,:template=>false}).to_yaml)
            end
        when :production
            @result_tracker.add_production_client
            if @config["SEND DIFFS"]
                unless msg.template
                    raise RuntimeError, "FuzzServer: configured for diffs, production client sent no template?"
                end
                @template=msg.template
            end
            send_data @handler.pack(FuzzMessage.new({:verb=>:server_ready}).to_yaml)
        else
            raise RuntimeError, "FuzzServer: Bad client type #{msg.client_type}"
        end
    end

    def handle_new_test_case( msg )
        send_data @handler.pack(FuzzMessage.new({:verb=>:ack_case, :id=>msg.id}).to_yaml)
        unless @config["USE THREADPOOL"]
            server_id=@result_tracker.check_out
            @production_queue << [server_id, msg.data] # this blocks if the queue is full
            send_data @handler.pack(FuzzMessage.new({:verb=>:server_ready}).to_yaml)
        else
            # define a block to prepare the response
            get_data=proc do
                # This pop will block until data is available
                # but since we are using EM.defer that's OK
                server_id=@result_tracker.check_out
                @production_queue << [server_id, msg.data] # this blocks if the queue is full
                # This is what will be passed to the callback
                @handler.pack(FuzzMessage.new({:verb=>:server_ready}).to_yaml)
            end
            # This callback will be invoked once the response is ready.
            callback=proc do |data|
                send_data data
            end
            # Send the work to the thread queue, so we are ready for more connections.
            EM.defer(get_data, callback)
        end
    end

    def handle_client_bye( msg )
        @result_tracker.send("remove_"+msg.client_type+"_client")
        if @result_tracker.production_clients==0
            @production_queue.finish
        end
    end

    def method_missing( meth, *args )
        raise RuntimeError, "Unknown Command: #{meth.to_s}!"
    end

    def receive_data(data)
        @handler.parse(data).each {|m| 
            msg=FuzzMessage.new(m)
            self.send("handle_"+msg.verb.to_s, msg)
        }
    end

end

rt=ResultTracker.new

EventMachine::run {
    EventMachine::start_server(config["SERVER IP"], config["SERVER PORT"], FuzzServer, prod_queue, rt, config)
}
