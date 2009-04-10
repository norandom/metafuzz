require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'
require 'diff/lcs'
require 'ole/storage'
require 'rt2'
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

    QUEUE_SIZE_LIMIT=20

    def self.setup( config_hsh={})
        default_config={
            :agent_name=>"SERVER",
            :server_ip=>"0.0.0.0",
            :server_port=>10001,
            :work_dir=>File.expand_path('~/fuzzserver/data'),
            :poll_interval=>5,
            :database_filename=>"metafuzz.db"
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
                    raise RuntimeError, "ProdctionClient: Couldn't create directory: #{$!}"
                end
            else
                raise RuntimeError, "ProductionClient: Work directory unavailable. Exiting."
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

        @waiting_for_data=[]
        @delivery_queue=prod_queue
        @result_tracker=ResultTracker.new(File.join(self.work_dir,self.database_filename))
        class << self
            attr_reader :delivery_queue, :result_tracker, :waiting_for_data
        end
    end

    def initialize *args
        @handler=NetStringTokenizer.new
        puts "FuzzServer: Starting up..."
        super
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
        if self.class.delivery_queue.empty? and self.class.delivery_queue.finished?
            send_msg(:verb=>:server_bye)
        else
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
    end

    def handle_client_startup( msg )
        self.class.result_tracker.send("add_"+msg.client_type.to_s+"_client")
        send_msg(:verb=>:server_ready)
    end

    def handle_new_test_case( msg )
        server_id=self.class.result_tracker.check_out
        send_msg(:verb=>:ack_case, :id=>msg.id, :server_id=>server_id)
        test_case=TestCase.new(msg.data)
        test_case.callback do
            send_msg(:verb=>:server_ready)
        end
        if waiting=self.class.waiting_for_data.shift
            waiting.succeed(server_id,test_case)
            # We're not keeping up, get a spare.
            send_msg(:verb=>:server_ready) unless self.class.delivery_queue.size > QUEUE_SIZE_LIMIT
        else
            self.class.delivery_queue << [server_id, test_case]
        end
    end

    def handle_client_bye( msg )
        self.class.result_tracker.send("remove_"+msg.client_type.to_s+"_client")
        if self.class.result_tracker.production_clients==0
            self.class.delivery_queue.finish
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
