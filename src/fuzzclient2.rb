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


default_config={"AGENT NAME"=>"CLIENT1",
    "SERVER IP"=>"127.0.0.1",
    "SERVER PORT"=>10001,
    "WORK DIR"=>'C:\fuzzclient',
    "CONFIG DIR"=>'C:\fuzzclient',
    "POLL INTERVAL"=>5
}


config_file=ARGV[0]
if config_file and not File.exists? config_file
    puts "FuzzClient: Bad config file #{config_file}, using default config."
    config=default_config
elsif not config_file
    if File.exists?(File.join(default_config["CONFIG DIR"],"fuzzclient_config.txt"))
        puts "FuzzClient: Loading from default config file."
        config_data=File.open(File.join(default_config["CONFIG DIR"],"fuzzclient_config.txt"), "r") {|io| io.read}
        config=YAML::load(config_data)
    else
        puts "FuzzClient: Using default config."
        config=default_config
    end
else
    begin
        config_data=File.open(config_file, "r") {|io| io.read}
        config=YAML::load(config_data)
    rescue
        puts "FuzzClient: Bad config file #{config_file}, using default config."
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
                        File.open(File.join(config["CONFIG DIR"],"fuzzclient_config.txt"),"w+") { |io|
                            io.write(YAML::dump(config))
                        }
                    rescue
                        puts "FuzzClient: Couldn't write out config."
                    end
                end
            rescue
                raise RuntimeError, "FuzzClient: Couldn't create directory: #{$!}"
            end
        else
            raise RuntimeError, "FuzzClient: #{dirname} unavailable. Exiting."
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
        puts "FuzzClient: Couldn't write out config."
    end
    print "Done. Exiting.\n"
}

begin
    Win32::Registry::HKEY_CURRENT_USER.open('SOFTWARE\Microsoft\Office\12.0\Word\Resiliency',Win32::Registry::KEY_WRITE) do |reg|
        reg.delete_key "StartupItems" rescue nil
        reg.delete_key "DisabledItems" rescue nil
    end
rescue
    nil
end


module FuzzClient

    def initialize(config)
        @config=config
    end

    def post_init
        @handler=NetStringTokenizer.new
        @sent=0
        @template=""
        puts "FuzzClient: Starting up..."
        send_client_startup
    end

    def prepare_test_file(data, msg_id)
        begin
            filename="test-"+msg_id.to_s+".doc"
            filename=File.join(@config["WORK DIR"],filename)
            fso=WIN32OLE.new("Scripting.FileSystemObject")
            path=fso.GetAbsolutePathName(filename) # Sometimes paths with backslashes break things, the FSO always does things right.
            fso.ole_free
            File.open(path, "wb+") {|io| io.write data}
            path
        rescue
            raise RuntimeError, "Fuzzclient: Couldn't create test file #{fn} : #{$!}"
        end
    end

    def clean_up( fn )
        10.times do
            begin
                FileUtils.rm_f(fn)
            rescue
                raise RuntimeError, "Fuzzclient: Failed to delete #{fn} : #{$!}"
            end
            return true unless File.exist? fn
            sleep(0.1)
        end
        return false
    end

    def deliver(data,msg_id)
        begin
            status=:error
            crash_details="" # will only be set to anything if there's a crash
            this_test_filename=prepare_test_file(data, msg_id)
            begin
                5.times do
                    begin
                        @word=Connector.new(CONN_OFFICE, 'word')
                        break
                    rescue
                        sleep(1)
                        next
                    end
                end
                current_pid=@word.pid
            rescue
                raise RuntimeError, "Couldn't establish connection to app. #{$!}"
            end
            # Attach debugger
            # -snul - don't load symbols
            # -hd don't use the debug heap
            # -pb don't request an initial break
            # -x ignore first chance exceptions
            # -xi ld ignore module loads
            debugger=Connector.new(CONN_CDB,"-snul -c \"sxe -c \\\"r;g\\\" av;g\" -hd -sflags 0x4000 -x -xi ld -p #{current_pid}")
            begin
                @word.deliver this_test_filename
                status=:success
                print '.';$stdout.flush
            rescue
                # check for crashes
                sleep(0.1) # This magically seems to fix a race condition.
                if debugger.crash?
                    status=:crash
                    sleep(0.1) while debugger.target_running?
                    crash_details=debugger.dq_all.join
                    File.open(File.join(@config["WORK DIR"],"crash-"+msg_id.to_s+".doc"), "wb+") {|io| io.write(data)}
                    print '!';$stdout.flush
                    # If the app has crashed we should kill the debugger, otherwise
                    # the app won't be killed without -9.
                    debugger.close
                else
                    status=:fail
                    print '#';$stdout.flush
                end
            end
            # close the debugger and kill the app
            # This should kill the winword process as well
            # Clean up the connection object
            @word.close rescue nil
            debugger.close 
            clean_up(this_test_filename) 
            [status,crash_details]
        rescue
            raise RuntimeError, "Delivery: fatal: #{$!}"
            # ask the server to revert me to my snapshot?
        end
    end

    # Protocol Send functions
    
    def send_client_bye
        self.reconnect(@config["SERVER IP"],@config["SERVER PORT"]) if self.error?
        msg=@handler.pack(FuzzMessage.new({
            :verb=>:client_bye,
            :station_id=>@config["AGENT NAME"],
            :data=>""}).to_yaml)
        send_data msg
    end

    def send_client_startup
        self.reconnect(@config["SERVER IP"],@config["SERVER PORT"]) if self.error?
        msg=@handler.pack(FuzzMessage.new({
            :verb=>:client_startup,
            :station_id=>@config["AGENT NAME"],
            :client_type=>:fuzz,
            :data=>""}).to_yaml)
        @initial_connect=EventMachine::DefaultDeferrable.new
        @initial_connect.timeout(@config["POLL INTERVAL"])
        @initial_connect.errback do
            puts "Fuzzclient: Connection timed out. Retrying."
            send_client_startup
        end
        send_data msg
    end

    def send_client_ready
        self.reconnect(@config["SERVER IP"],@config["SERVER PORT"]) if self.error?
        msg=@handler.pack(FuzzMessage.new({
            :verb=>:client_ready,
            :station_id=>@config["AGENT NAME"],
            :data=>""}).to_yaml)
        send_data msg
    end

    def send_result(id, status, crash_details)
        self.reconnect(@config["SERVER IP"],@config["SERVER PORT"]) if self.error?
        msg=@handler.pack(FuzzMessage.new({
            :verb=>:result,
            :station_id=>@config["AGENT NAME"],
            :id=>id,
            :status=>status,
            :data=>crash_details}).to_yaml)
        send_data msg
    end

    # Protocol Receive functions

    def handle_deliver( msg )
        if @template
            fuzzfile=Diff::LCS.patch(@template,msg.data)
        else
            fuzzfile=msg.data
        end
        begin
            status,crash_details=deliver(fuzzfile,msg.id)
        rescue
            status=:error
            puts $!
            EventMachine::stop_event_loop
            raise RuntimeError, "Fuzzclient: Fatal error. Dying #{$!}"
        end
        send_result msg.id, status, crash_details
        send_client_ready
    end

    def handle_server_ready( msg )
        if @initial_connect
            @initial_connect.succeed
            @initial_connect=false
        end
        @template=msg.template
        send_client_ready
    end
    
    def handle_server_bye( msg )
        puts "FuzzClient: Server is finished."
        send_client_bye
        EventMachine::stop_event_loop
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

EventMachine::run {
    EventMachine::connect(config["SERVER IP"],config["SERVER PORT"], FuzzClient, config)
}
puts "Event loop stopped. Shutting down."
