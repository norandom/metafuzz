require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'
require 'result_tracker'
require 'objhax'

class TestCase < EventMachine::DefaultDeferrable
    attr_reader :data
    def initialize( data )
        @data=data
        super()
    end
    alias :get_new_case :succeed
end

class FuzzServer < EventMachine::Connection

    WaitQueue=[]
    DeliveryQueue=[]
    def self.waiting_for_data
        WaitQueue
    end
    def self.delivery_queue
        DeliveryQueue
    end
    def self.setup( config_hsh={})
        default_config={
            :agent_name=>"SERVER",
            :server_ip=>"0.0.0.0",
            :server_port=>10001,
            :work_dir=>File.expand_path('~/fuzzserver'),
            :database_filename=>"/dev/shm/metafuzz.db"
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
                    Dir.mkdir(@config[:work_dir])
                rescue
                    raise RuntimeError, "ProdctionClient: Couldn't create directory: #{$!}"
                end
            else
                raise RuntimeError, "ProductionClient: Work directory unavailable. Exiting."
            end
        end
        # Class instance variables, shared across subclass instances
        # but not between different subclasses.
        @@result_tracker=ResultTracker.new(self.database_filename)
        def self.result_tracker
            @@result_tracker
        end
    end

    def post_init
        @handler=NetStringTokenizer.new
    end

    def send_msg( msg_hash )
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_yaml)
    end

    # Users might want to overload this function.
    def handle_result( msg )
        result_id,result_status,crashdata,crashfile=msg.id, msg.status, msg.data, msg.crashfile
        if result_status==:crash
            detail_path=File.join(self.class.work_dir,"detail-#{result_id}.txt")
            crashfile_path=File.join(self.class.work_dir,"crash-#{result_id}")
            File.open(detail_path, "wb+") {|io| io.write(crashdata)}
            File.open(crashfile_path, "wb+") {|io| io.write(crashfile)}
        end
        self.class.result_tracker.add_result(Integer(result_id),result_status,detail_path||=nil,crashfile_path||=nil)
    end

    # Only comes from fuzzclients.
    def handle_client_ready( msg )
        unless self.class.delivery_queue.empty?
            id,test_case=self.class.delivery_queue.shift
            send_msg(:verb=>:deliver,:data=>test_case.data,:id=>id)
            test_case.get_new_case
        else
            waiter=EventMachine::DefaultDeferrable.new
            waiter.callback do |id, test_case|
                send_msg(:verb=>:deliver,:data=>test_case.data,:id=>id)
                test_case.get_new_case
            end
            self.class.waiting_for_data << waiter
        end
    end

    def handle_client_startup( msg )
        send_msg(:verb=>:server_ready)
    end

    def handle_new_test_case( msg )
        server_id=self.class.result_tracker.check_out
        test_case=TestCase.new(msg.data)
        test_case.callback do
            send_msg(:verb=>:ack_case, :id=>msg.id)
            send_msg(:verb=>:server_ready,:server_id=>server_id)
        end
        if waiting=self.class.waiting_for_data.shift
            waiting.succeed(server_id,test_case)
        else
            self.class.delivery_queue << [server_id, test_case]
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
