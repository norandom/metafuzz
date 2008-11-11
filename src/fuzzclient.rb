require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'yaml'

module FuzzClient

    def post_init
        @handler=NetStringTokenizer.new
        puts "Sending ready.."
        send_data(@handler.pack("CLIENT READY"))
    end

    def receive_data(data)
        @handler.parse(data).each {|m| 
            puts "Got YAML Data. Loading..."
            obj=YAML::load(m)
            puts "Got #{obj.class} - #{obj.inspect}"
        }
        EventMachine::stop_event_loop
    end
end

EventMachine::run {
    EventMachine::connect("127.0.0.1", 10000, FuzzClient)
}
puts "Client Exited."
