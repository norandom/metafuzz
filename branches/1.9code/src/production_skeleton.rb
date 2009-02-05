require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'
require 'connector'
require 'conn_office'
require 'conn_cdb'
require 'diff/lcs'
require 'fileutils'
require 'win32/registry'

default_config={"AGENT NAME"=>"PRODCLIENT1",
    "SERVER IP"=>"127.0.0.1",
    "SERVER PORT"=>10001,
    "WORK DIR"=>'C:\prodclient',
    "CONFIG DIR"=>'C:\prodclient',
    "POLL INTERVAL"=>5,
    "SEND DIFFS"=>false,
    "FUZZCODE FILE"=>'word_dggfuzz.rb'
}

# foo
config_file=ARGV[0]
if config_file and not File.exists? config_file
    puts "ProductionClient: Bad config file #{config_file}, using default config."
    config=default_config
elsif not config_file
    if File.exists?(File.join(default_config["CONFIG DIR"],"prodclient_config.txt"))
        puts "ProductionClient: Loading from default config file."
        config_data=File.open(File.join(default_config["CONFIG DIR"],"prodclient_config.txt"), "r") {|io| io.read}
        config=YAML::load(config_data)
    else
        puts "ProductionClient: Using default config."
        config=default_config
    end
else
    begin
        config_data=File.open(config_file, "r") {|io| io.read}
        config=YAML::load(config_data)
    rescue
        puts "ProductionClient: Bad config file #{config_file}, using default config."
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
                        File.open(File.join(config["CONFIG DIR"],"prodclient_config.txt"),"w+") { |io|
                            io.write(YAML::dump(config))
                        }
                    rescue
                        puts "ProductionClient: Couldn't write out config."
                    end
                end
            rescue
                raise RuntimeError, "ProductionClient: Couldn't create directory: #{$!}"
            end
        else
            raise RuntimeError, "ProductionClient: #{dirname} unavailable. Exiting."
        end
    end
}

at_exit {
    print "Saving config to #{config["CONFIG DIR"]}..."
    begin
        File.open(File.join(config["CONFIG DIR"],"prodclient_config.txt"),"w+") { |io|
            io.write(YAML::dump(config))
        }
    rescue
        puts "ProductionClient: Couldn't write out config."
    end
    print "Done. Exiting.\n"
}

require config["FUZZCODE FILE"]

module ProductionClient

    # Send methods...

    def send_test_case( tc, case_id )
        self.reconnect(@config["SERVER IP"],@config["SERVER PORT"]) if self.error?
        if @config["SEND DIFFS"]
            diffs=Diff::LCS.diff(@prodmodule::Template,tc)
            msg=@handler.pack(FuzzMessage.new({
                :verb=>:new_test_case,
                :data=>diffs,
                :station_id=>@config["AGENT NAME"],
                :id=>case_id}).to_yaml)
        else
            msg=@handler.pack(FuzzMessage.new({
                :verb=>:new_test_case,
                :station_id=>@config["AGENT NAME"],
                :id=>case_id,
                :data=>tc}).to_yaml)
        end
        send_data msg
    end

    def send_client_bye
        self.reconnect(@config["SERVER IP"],@config["SERVER PORT"]) if self.error?
        msg=@handler.pack(FuzzMessage.new({
            :verb=>:client_bye,
            :client_type=>:production,
            :station_id=>@config["AGENT NAME"],
            :data=>""}).to_yaml)
        send_data msg
    end

    def send_client_startup
        puts "ProdClient: Trying to connect to #{@config["SERVER IP"]} : #{@config["SERVER PORT"]}" 
        self.reconnect(@config["SERVER IP"],@config["SERVER PORT"]) if self.error?
        if @config["SEND DIFFS"]
            msg=@handler.pack(FuzzMessage.new({
                :verb=>:client_startup,
                :client_type=>:production,
                :station_id=>@config["AGENT NAME"],
                :template=>@prodmodule::Template,
                :data=>""}).to_yaml)
        else
            msg=@handler.pack(FuzzMessage.new({
                :verb=>:client_startup,
                :client_type=>:production,
                :template=>false,
                :station_id=>@config["AGENT NAME"],
                :data=>""}).to_yaml)
        end
        send_data msg
        @initial_connect=EventMachine::DefaultDeferrable.new
        @initial_connect.timeout(@config["POLL INTERVAL"])
        @initial_connect.errback do
            puts "ProdClient: Connection timed out. Retrying."
            send_client_startup
        end
    end

    # Receive methods...

    def handle_ack_case( msg )
        @idtracker.delete msg.id rescue nil
    end

    def handle_server_ready( msg )
        if @initial_connect
            @initial_connect.succeed
            @initial_connect=false
        end
        if @production_generator.next?
            @case_id+=1
            @idtracker << @case_id
            send_test_case @production_generator.next, @case_id
        else
            send_client_bye
        end
    end

    def handle_server_bye( msg )
    end

    def method_missing( meth, *args )
        raise RuntimeError, "Unknown Command: #{meth.to_s}!"
    end

    def initialize(config)
        @config=config
        @server_ready=false
        # The Producer module must be defined in the FUZZCODE FILE param of the config
        @production_generator=Generator.new {|g| Producer.each_item {|i| g.yield i}}
        @idtracker=[]
        @case_id=0
        @handler=NetStringTokenizer.new
    end

    def post_init
        send_client_startup
    end

    # FuzzMessage#verb returns a symbol, so self.send activates
    # the corresponding instance method above, and passes the message
    # itself as a parameter.
    def receive_data(data)
        @handler.parse(data).each {|m| 
            msg=FuzzMessage.new(m)
            self.send("handle_"+msg.verb.to_s, msg)
        }
    end
end

EventMachine::run {
    EventMachine::connect(config["SERVER IP"],config["SERVER PORT"], ProductionClient, config)
}
puts "Event loop stopped. Shutting down."
