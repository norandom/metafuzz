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


    def send_client_shutdown
        self.reconnect(@config["SERVER IP"],@config["SERVER PORT"]) if self.error?
        ready_msg=@handler.pack(FuzzMessage.new({
            :verb=>"CLIENT SHUTDOWN",
            :station_id=>@config["AGENT NAME"],
            :data=>""}).to_yaml)
            send_data ready_msg
    end

    def send_client_startup
        self.reconnect(@config["SERVER IP"],@config["SERVER PORT"]) if self.error?
        ready_msg=@handler.pack(FuzzMessage.new({
            :verb=>"CLIENT STARTUP",
            :station_id=>@config["AGENT NAME"],
            :data=>""}).to_yaml)
            send_data ready_msg
            @initial_connect=EventMachine::DefaultDeferrable.new
            @initial_connect.timeout(@config["POLL INTERVAL"])
            @initial_connect.errback do
                puts "Fuzzclient: Connection timed out. Retrying."
                send_client_startup
            end
    end

    def send_client_ready
        self.reconnect(@config["SERVER IP"],@config["SERVER PORT"]) if self.error?
        ready_msg=@handler.pack(FuzzMessage.new({
            :verb=>"CLIENT READY",
            :station_id=>@config["AGENT NAME"],
            :data=>""}).to_yaml)
            send_data ready_msg
    end

    def send_result(data='')
        self.reconnect(@config["SERVER IP"],@config["SERVER PORT"]) if self.error?
        ready_msg=@handler.pack(FuzzMessage.new({
            :verb=>"CLIENT RESULT",
            :station_id=>@config["AGENT NAME"],
            :data=>data}).to_yaml)
            send_data ready_msg
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
                FileUtils.rm_f(fn.split('\\').map {|s| s=~/.*.doc/ ? '~$'+s.reverse[0..9].reverse : s}.join('\\'))
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
            status="ERROR"
            this_test_filename=prepare_test_file(data, msg_id)
            begin
                5.times do
                    begin
                        @word=Connector.new(CONN_OFFICE, 'word')
                        break
                    rescue
                        puts $!
                        sleep(1)
                        retry
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
            debugger=Connector.new(CONN_CDB,"-snul -hd -pb -x -xi ld -p #{current_pid}")
            begin
                @word.deliver this_test_filename
                status="SUCCESS"
                print '.';$stdout.flush
            rescue
                # check AV status
                sleep(0.1) # This magically seems to fix a race condition.
                if debugger.crash?
                    status="CRASH"
                    File.open(File.join(@config["WORK DIR"],"crash-"+msg_id.to_s+".doc"), "wb+") {|io| io.write(data)}
                    print '!';$stdout.flush
                    debugger.close
                else
                    status="FAIL"
                    print '#';$stdout.flush
                end
            end
            # close the debugger and kill the app
            # This should kill the winword process as well
            # Clean up the connection object
            @word.close rescue nil
            debugger.close 
            clean_up(this_test_filename) 
            status
        rescue
            raise RuntimeError, "Delivery: fatal: #{$!}"
            # ask the server to revert me to my snapshot
        end
    end

    def post_init
        @handler=NetStringTokenizer.new
        @sent=0
        @template=""
        puts "FuzzClient: Starting up..."
        send_client_startup
        at_exit {send_client_shutdown}
    end

    def receive_data(data)
        @handler.parse(data).each {|m| 
            msg=FuzzMessage.new(m)
            case msg.verb
            when "DELIVER"
                #fuzzfile=Diff::LCS.patch(@template,msg.data)
                fuzzfile=msg.data
                begin
                    status=deliver(fuzzfile,msg.id)
                rescue
                    status="ERROR"
                    puts $!
                    EventMachine::stop_event_loop
                    raise RuntimeError, "Something is fucked. Dying #{$!}"
                end
                send_result "#{msg.id}:#{status}"
                send_client_ready
            when "SERVER FINISHED"
                puts "FuzzClient: Server is finished."
                send_client_shutdown
                EventMachine::stop_event_loop
            when "TEMPLATE"
                @initial_connect.succeed
                @template=msg.data
                send_client_ready
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
