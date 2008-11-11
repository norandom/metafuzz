require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'yaml'

module FuzzServer

    def post_init
        @handler=NetStringTokenizer.new
    end

    def receive_data(data)
        puts "Got client connection..."
        @handler.parse(data).each {|m| 
            if m=="CLIENT READY"
                puts "Got a client ready message, sending stuff"
                hsh={:foo=>12,:bar=>"a string",:baz=>[1,23,4]}
                send_data(@handler.pack(YAML::dump(hsh)))
            end
        }
    end
end

EventMachine::run {
    EventMachine::start_server("0.0.0.0", 10000, FuzzServer)
}
