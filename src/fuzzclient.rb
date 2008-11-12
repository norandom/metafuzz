require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'


default_config={"AGENT NAME"=>"CLIENT1",
        "SERVER IP"=>"127.0.0.1",
        "SERVER PORT"=>10000,
        "WORK DIR"=>'C:\fuzzclient',
        "CONFIG DIR"=>'C:\fuzzclient',
        "POLL INTERVAL"=>5
}

config_file=ARGV[0]
if config_file and not File.exists? config_file
    puts "Fuzzclient: Bad config file #{config_file}, using default config."
    config=default_config
elsif not config_file
    puts "Fuzzclient: Using default config."
    config=default_config
else
    begin
        config_data=File.open(config_file, "r") {|io| io.read}
        config=YAML::load(config_data)
        config=default_config.merge config
    rescue
        puts "Fuzzclient: Bad config file #{config_file}, using default config."
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
                raise RuntimeError, "Fuzzclient: Couldn't create directory: #{$!}"
            end
        else
            raise RuntimeError, "Fuzzclient: #{dirname} unavailable. Exiting."
        end
    end
}

at_exit {
    print "Saving config to #{config["CONFIG DIR"]}..."
    begin
        File.open(File.join(config["CONFIG DIR"],"fuzzclient_config.txt"),"w+") { |io|
            io.write(YAML::dump(config))
        }
    rescue
        puts "Fuzzclient: Couldn't write out config."
    end
    print "Done. Exiting.\n"
}


module FuzzClient

    def initialize(config)
        @config=config
    end

    def send_client_ready
        self.reconnect(@config["SERVER IP"],@config["SERVER PORT"]) if self.error?
        send_data @ready_msg
        @connect=EventMachine::DefaultDeferrable.new
        @connect.timeout(5)
        @connect.errback do
           puts "Fuzzclient: Connection timed out. Retrying."
           send_client_ready
        end
    end

    def post_init
        @handler=NetStringTokenizer.new
        @ready_msg=@handler.pack(FuzzMessage.new({:verb=>"CLIENT READY",:station_id=>@config["AGENT NAME"]}).to_yaml)
        puts "FuzzClient: Starting up..."
        begin
        send_client_ready
        rescue
            puts $!
        end
    end

    def receive_data(data)
        @handler.parse(data).each {|m| 
            @connect.succeed
            msg=FuzzMessage.new(m)
            case msg.verb
                when "DELIVER"
                    # Deliver it here...
                    send_client_ready
                when "SERVER FINISHED"
                    puts "FuzzClient: Server is finished."
                    EventMachine::stop_event_loop
                else
                    raise RuntimeError, "Unknown Command!"
            end
        }
    end
end

EventMachine::run {
    EventMachine::connect(config["SERVER IP"],config["SERVER PORT"], FuzzClient, config)
}
puts "Event loop stopped. Shutting down."
