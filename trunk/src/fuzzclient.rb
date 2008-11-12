require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'

module FuzzClient

    def post_init
        @handler=NetStringTokenizer.new
        puts "Sending ready.."
        @ready_msg=@handler.pack(FuzzMessage.new({:verb=>"CLIENT READY"}).to_yaml)
        send_data @ready_msg
    end

    def receive_data(data)
        @handler.parse(data).each {|m| 
            puts "Got Data. Loading..."
            msg=FuzzMessage.new(m)
            puts "Got #{msg.verb} -- #{msg.data.inspect}"
            case msg.verb
            when "DELIVER"
                puts msg.data
                send_data @ready_msg
            when "SERVER FINISHED"
                EventMachine::stop_event_loop
            else
                raise RuntimeError, "Unknown Command!"
            end
        }
    end
end

EventMachine::run {
    EventMachine::connect("127.0.0.1", 10000, FuzzClient)
}
puts "Client Exited."
