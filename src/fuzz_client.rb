require 'rubygems'
require 'eventmachine'
require File.dirname(__FILE__) + '/em_netstring'
require File.dirname(__FILE__) + '/fuzzprotocol'
require 'fileutils'
require 'objhax'
require 'base64'


class FuzzClient < EventMachine::Connection

    VERSION="1.0.7"
    def self.setup( config_hsh={})
        default_config={
            :agent_name=>"CLIENT1",
            :server_ip=>"127.0.0.1",
            :server_port=>10001,
            :work_dir=>File.expand_path('C:/fuzzclient'),
            :poll_interval=>60
        }
        @config=default_config.merge config_hsh
        @config.each {|k,v|
           meta_def k do v end
           meta_def k.to_s+'=' do |new| @config[k]=new end
        }
        unless File.directory? @config[:work_dir]
            print "Work directory #{@config[:work_dir]} doesn't exist. Create it? [y/n]: "
            answer=STDIN.gets.chomp
            if answer =~ /^[yY]/
                begin
                    Dir.mkdir(config[:work_dir])
                rescue
                    raise RuntimeError, "FuzzClient: Couldn't create directory: #{$!}"
                end
            else
                raise RuntimeError, "FuzzClient: Work directory unavailable. Exiting."
            end
          end
          @unanswered=[]
          class << self
            attr_reader :unanswered
          end
    end

    def post_init
        @handler=NetStringTokenizer.new
        puts "FuzzClient#{VERSION}: Starting up..."
        send_client_startup
    end

    def deliver(data,msg_id)
        # Deliver the test here, return the status and any extended
        # crash data (eg debugger output). Currently, the harness
        # uses :success, :fail, :crash and :error
        [:success, ""]
    end

    # Protocol Send functions

    def send_message( msg_hash )
        self.reconnect(self.class.server_ip,self.class.server_port) if self.error?
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_yaml)
    end

    def send_client_bye
        send_message(
            :verb=>:client_bye,
            :station_id=>self.class.agent_name,
            :data=>"")
    end

    def send_client_startup
        send_message(
            :verb=>:client_startup,
            :station_id=>self.class.agent_name,
            :client_type=>:fuzz,
            :data=>"")
        waiter=EventMachine::DefaultDeferrable.new
        waiter.timeout(self.class.poll_interval)
        waiter.errback do
            puts "Fuzzclient: Initial connection timed out. Retrying."
            send_client_startup
          end
        self.class.unanswered << waiter
    end

    def send_client_ready
        send_message(
            :verb=>:client_ready,
            :station_id=>self.class.agent_name,
            :data=>"")
        waiter=EventMachine::DefaultDeferrable.new
        waiter.timeout(self.class.poll_interval)
        waiter.errback do
            puts "Fuzzclient: Connection timed out. Retrying."
            send_client_ready
          end
        self.class.unanswered << waiter
    end

    def send_result(id, status, crash_details, fuzzfile)
        send_message(
            :verb=>:result,
            :station_id=>self.class.agent_name,
            :id=>id,
            :status=>status,
            :data=>crash_details,
            :crashfile=>(status==:crash ? fuzzfile : false))
    end

    # Protocol Receive functions

    def handle_deliver( msg )
        self.class.unanswered.shift.succeed until self.class.unanswered.empty?
        fuzzdata=Base64.decode64 msg.data
        begin
            status,crash_details=deliver(fuzzdata,msg.id)
        rescue
            status=:error
            EventMachine::stop_event_loop
            raise RuntimeError, "Fuzzclient: Fatal error. Dying #{$!}"
        end
        send_result msg.id, status, crash_details, fuzzdata
        send_client_ready
    end

    def handle_server_ready( msg )
        self.class.unanswered.shift.succeed until self.class.unanswered.empty?
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
