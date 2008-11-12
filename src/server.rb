require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'
require 'thread'
require 'fuzzer'

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
end

prod_thread=Thread.new do
    begin
        gen=Generators::RollingCorrupt.new("XXXX",8,8)
        while gen.next?
            # This << will block until the queue has < 20 items
            prod_queue << gen.next
        end
        puts "Production Thread Finished."
        prod_queue.finish
        Thread.stop
    rescue
        puts "Error: Production Thread Exiting: #{$!}"
        Thread.current.exit
    end
end

module FuzzServer

    def post_init
        @handler=NetStringTokenizer.new
    end

    def initialize(prod_queue)
        @production_queue=prod_queue
    end

    def receive_data(data)
        @handler.parse(data).each do |m| 
            msg=FuzzMessage.new(m)
            if msg.verb=="CLIENT READY"
                if @production_queue.empty? and @production_queue.finished?
                    send_data(@handler.pack(FuzzMessage.new({:verb=>"SERVER FINISHED"}).to_yaml))
                else
                    # define a block to prepare the response
                    get_data=proc do
                        # This pop will block until data is available
                        # but since we are using EM.defer that's OK
                        my_data=@production_queue.pop
                        # This is what will be passed to the callback
                        @handler.pack(FuzzMessage.new({:verb=>"DELIVER",:data=>my_data}).to_yaml)
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
    end

end

EventMachine::run {
    EventMachine::start_server("0.0.0.0", 10000, FuzzServer, prod_queue)
}
