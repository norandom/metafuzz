require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'
require 'connector'
require 'conn_office'


default_config={"AGENT NAME"=>"CLIENT1",
    "SERVER IP"=>"192.168.241.2",
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

    def send_client_ready(data='')
        self.reconnect(@config["SERVER IP"],@config["SERVER PORT"]) if self.error?
        ready_msg=@handler.pack(FuzzMessage.new({
            :verb=>"CLIENT READY",
            :station_id=>@config["AGENT NAME"],
            :data=>data}).to_yaml)
            send_data ready_msg
            @connect=EventMachine::DefaultDeferrable.new
            @connect.timeout(@config["POLL INTERVAL"])
            @connect.errback do
                puts "Fuzzclient: Connection timed out. Retrying."
                send_client_ready
            end
    end

    def deliver(data,msg_id)
        status=false
        begin
            begin
                begin
                    @word=Connector.new(CONN_OFFICE, 'word', @config["WORK DIR"])
                    @word.connected?
                rescue
                    raise RuntimeError, "Couldn't establish connection to app. #{$!}"
                end
                @word.deliver data
                unless @word.connected?
                    print "!#{@word.pid}!";$stdout.flush
                    File.open("1crash"+self.object_id.to_s+'-'+msg_id.to_s+".doc", "wb+") {|io| io.write(data)}
                    status="CRASH"
                else
                    print(".");$stdout.flush
                    status="SUCCESS"
                end
                @word.close
            rescue 
                unless $!.message =~ /CONN_OFFICE/m # a process id that went away
                    print "<#{$!.message}>";$stdout.flush
                    #File.open("2crash"+self.object_id.to_s+'-'+sent.to_s+".doc", "wb+") {|io| io.write(Thread.current[:data])}
                    status="HANG"
                else
                    print "#";$stdout.flush
                    status="FAIL"
                end
                @word.close
            end
        rescue
            print "!#{@word.pid}!";$stdout.flush
            File.open("1crash"+self.object_id.to_s+'-'+msg_id.to_s+".doc", "wb+") {|io| io.write(data)}
            status="CRASH"
        end
        @word=nil
        status
    end

    def post_init
        @handler=NetStringTokenizer.new
        @sent=0
        puts "FuzzClient: Starting up..."
        send_client_ready ""
    end

    def receive_data(data)
        @handler.parse(data).each {|m| 
            @connect.succeed
            msg=FuzzMessage.new(m)
            case msg.verb
            when "DELIVER"
                begin
                    status=deliver(msg.data,msg.id)
                rescue
                    status="ERROR"
                    raise RuntimeError, "Something is fucked. Dying #{$!}"
                end
                send_client_ready "#{msg.id}:#{status}"
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
