
require 'fsa'
class TestFSA < FSA
       node :init, root=true
       node :req_sent
       node :established
       node :closing

       edge :init, :req_sent, :send, proc {set_state(:cookie, "abcdef"); output_pkt="<<Imagine I am a packet...>>"}
       req_sent_match=proc {|data| data.slice(0,6)==get_state(:cookie)}
       req_sent_action=proc {|data| set_state(:trans_id, data.slice(6..-1))}
       edge :req_sent, :established, :recv,  req_sent_match, req_sent_action
       #more edges here...
 end

 t=TestFSA.new
 puts "Starting at Node #{t.current_node.name}"
 #output=t.current_node.invoke_send_edge(t.current_node.send_edges_to(t.req_sent).first)
 output=t.navigate(t.current_node, t.req_sent)
 puts "Need to send: #{output} to get to req_sent..."
 # would send output here.
 puts "sending..."
 puts "New Node: #{t.current_node.name}"
 puts "Current State: #{t.state.inspect}"
 # would read response here
 response="abcdef165"
 puts "Got response: #{response}"
 if t.current_node.can_process?(response)
       puts "Response Match - sending #{response.inspect} to FSA..."
       t.deliver(response)
 end
 puts "New Node: #{t.current_node.name}"
 puts "Current State: #{t.state.inspect}"
 puts "Resetting..."
 t.reset
 puts "New Node: #{t.current_node.name}"
 puts "Current State: #{t.state.inspect}"
