require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'
require 'diff/lcs'
require 'ole/storage'
require 'rt2'

default_config={"AGENT NAME"=>"SERVER",
    "SERVER IP"=>"0.0.0.0",
    "SERVER PORT"=>10001,
    "WORK DIR"=>File.expand_path('~/fuzzserver/data'),
    "CONFIG DIR"=>File.expand_path('~/fuzzserver'),
    "DATABASE FILENAME"=>"metafuzz.db",
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


class TestCase < EventMachine::DefaultDeferrable
    attr_reader :data
    def initialize( data )
        @data=data
        super()
    end
    alias :get_new_case :succeed
end

module FuzzServer

    def initialize(template)
        @handler=NetStringTokenizer.new
        @template=template
        puts "FuzzServer: Starting up..."
    end

    def send_msg( msg_hash )
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_yaml)
    end

    def handle_result( msg )
        result_id,result_status,crashdata,crashfile=msg.id, msg.status, msg.data, msg.crashfile
        if result_status==:crash
            detail_path=File.join(ConfigHash["WORK DIR"],"detail-#{result_id}.txt")
            crashfile_path=File.join(ConfigHash["WORK DIR"],"crash-#{result_id}.doc")
            File.open(detail_path, "wb+") {|io| io.write(crashdata)}
            File.open(crashfile_path, "wb+") {|io| io.write(crashfile)}
        end
        ResultTracker.add_result(Integer(result_id),result_status,detail_path||=nil,crashfile_path||=nil)
    end

    # Only comes from fuzzclients.
    def handle_client_ready( msg )
        if DeliveryQueue.empty? and DeliveryQueue.finished?
            send_msg(:verb=>:server_bye)
        else
            unless DeliveryQueue.empty?
                id,test_case=DeliveryQueue.shift
                send_msg(:verb=>:deliver,:data=>test_case.data,:id=>id)
                test_case.get_new_case
            else
                waiter=EventMachine::DefaultDeferrable.new
                waiter.callback do |id, test_case|
                    send_msg(:verb=>:deliver,:data=>test_case.data,:id=>id)
                    test_case.get_new_case
                end
                WaitingForData << waiter
            end
        end
    end

    def handle_client_startup( msg )
        case msg.client_type
        when :fuzz
            ResultTracker.add_fuzz_client
            if ConfigHash["SEND DIFFS"]
                if @template
                    send_msg(:verb=>:server_ready,:template=>@template)
                else
                    waiter=EventMachine::DefaultDeferrable.new
                    waiter.callback do
                        send_msg(:verb=>:server_ready,:template=>@template)
                    end
                    WaitingForTemplate << waiter
                end
            else
                send_msg(:verb=>:server_ready,:template=>false)
            end
        when :production
            ResultTracker.add_production_client
            if ConfigHash["SEND DIFFS"]
                unless msg.template
                    raise RuntimeError, "FuzzServer: configured for diffs, production client sent no template?"
                end
                @template=msg.template
                WaitingForTemplate.each {|waiter| waiter.succeed}
                WaitingForTemplate.replace []
            end
            send_msg(:verb=>:server_ready)
        else
            raise RuntimeError, "FuzzServer: Bad client type #{msg.client_type}"
        end
    end

    def handle_new_test_case( msg )
        server_id=ResultTracker.check_out
        send_msg(:verb=>:ack_case, :id=>msg.id, :server_id=>server_id)
        test_case=TestCase.new(msg.data)
        test_case.callback do
            send_msg(:verb=>:server_ready)
        end
        if waiting=WaitingForData.shift
            waiting.succeed(server_id,test_case)
            send_msg(:verb=>:server_ready) unless DeliveryQueue.size > 20 # We're not keeping up, get a spare.
        else
            DeliveryQueue << [server_id, test_case]
        end
    end

    def handle_client_bye( msg )
        ResultTracker.send("remove_"+msg.client_type.to_s+"_client")
        if ResultTracker.production_clients==0
            DeliveryQueue.finish
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

prod_queue=[]
class << prod_queue
    def finished?
        @finished||=false
    end
    def finish
        @finished=true
    end
end

WaitingForTemplate=[]
WaitingForData=[]
DeliveryQueue=prod_queue
ResultTracker=ResultTracker2.new(File.join(config["WORK DIR"],config["DATABASE FILENAME"]))
ConfigHash=config
template=false

EM.epoll
EventMachine::run {
        EM.add_periodic_timer(30) do 
            if DeliveryQueue.empty? and DeliveryQueue.finished? and ResultTracker.fuzz_clients==0
                puts "All done, shutting down."
                EventMachine::stop_event_loop
            end
        end
    EventMachine::start_server(config["SERVER IP"], config["SERVER PORT"], FuzzServer, template)
}
