require 'production_client'
require 'word_dggfuzz2'

ProductionClient.setup

EM.epoll
EM.set_max_timers(5000)
EventMachine::run {
    EventMachine::connect(ProductionClient.server_ip,ProductionClient.server_port, ProductionClient)
}
puts "Event loop stopped. Shutting down."
