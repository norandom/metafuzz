require 'connector'
require 'conn_tcp'
require 'proto-pptp'

c=Connector.new(CONN_TCP, '172.16.61.129', 1723)
f=PPTP::PPTPFSA.new
loop do
    puts "At Node <#{f.current_node.name}>"
    if f.current_node.send_edges.empty?
      puts "Don't know how to move from this node, bailing."
      break
    end
    puts "Trying to move from <#{f.current_node.name}> to <#{f.current_node.send_edges.first.destination.name}>."
    pkt=f.navigate f.current_node, f.current_node.send_edges.first.destination
    puts "About to send a #{pkt.class.to_s}"
    puts "Sending..."
    begin
        c.sr pkt
    rescue
        c.reconnect
        c.sr pkt
    end
    resp=c.dq_first
    if resp
        puts "Got Resp #{PPTP::Parser.new(resp.clone).class.to_s rescue "invalid"}"
    else
        puts "No response from peer."
    end
    if f.current_node.can_process? resp
        puts "FSA can process!" 
        puts "Sending data to FSA."
        f.deliver resp 
        puts "Node now <#{f.current_node.name}>"
    else
        puts "FSA couldn't process. :("
    end
    if f.current_node.edges.empty?
        puts "Node <#{f.current_node.name}> is a dead end. Bailing."
        break
    end
end
