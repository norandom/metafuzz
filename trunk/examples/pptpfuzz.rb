require 'fuzzer'
require 'proto-pptp'
require 'connector'
require 'conn_tcp'

fixer=
proc {|hdr|
	begin
		hdr.len=hdr.length
	rescue ArgumentError
		hdr.len=65535
	end
	
	unless hdr.fields.index(hdr[:cookie])==2 # an overflow field got inserted
        magic=[0x1a, 0x2b, 0x3c, 0x4d].pack('cccc')
		return hdr.to_s[0..3]+magic+hdr.to_s[8..-1]
	end

	hdr.cookie="1a2b3c4d"
	hdr.to_s
}
fix_outgoing_call_req=
    proc {|hdr|	
    begin
		hdr.len=hdr.length
	rescue ArgumentError
		hdr.len=65535
	end
	
    hdr.call_id=rand(2**16)
    hdr.call_serial=rand(2**16)
    hdr.ph_len=hdr.ph_num.length
	unless hdr.fields.index(hdr[:cookie])==2 # an overflow field got inserted
        magic=[0x1a, 0x2b, 0x3c, 0x4d].pack('cccc')
		return hdr.to_s[0..3]+magic+hdr.to_s[8..-1]
	end

	hdr.cookie="1a2b3c4d"
	hdr
}
		
f1=Fuzzer.new(PPTP::StartControlConnReq.new, fixer)
f2=Fuzzer.new(PPTP::StopControlConnReq.new, fixer)
f3=Fuzzer.new(PPTP::OutgoingCallReq.new, fix_outgoing_call_req)

valid_start=PPTP::StartControlConnReq.new
valid_start.len=valid_start.length
valid_stop=PPTP::StopControlConnReq.new
valid_stop.len=valid_stop.length

send_queue=Queue.new

production=Thread.new do
    f3.basic_tests("corner", 1500, true) {|data| send_queue << data}
    print '*'
    Thread.current.exit
end

sent=0
start=Time.now

5.times do
    Thread.new do    
        Thread.current[:conn]=Connector.new(CONN_TCP, '172.16.61.129', 1723)
        begin
            loop do
                loop do
                    Thread.current[:conn].dq_all
                    Thread.current[:conn].sr valid_start
                    Thread.current[:conn].quicksend valid_stop if Thread.current[:conn].q_empty?
                    next unless Thread.current[:conn].dq_all.any? {|resp| PPTP::Parser.new(resp).control_type==2 rescue false}
                    break
                end
                begin
                    data=send_queue.pop
                    Thread.current[:conn].deliver data
                    print("."); $stdout.flush
                    sent+=1
                rescue
                    Thread.current[:conn].reconnect
                    Thread.current[:conn].deliver data
                    print("!"); $stdout.flush
                    sent+=1
                end
                Thread.current[:conn].quicksend valid_stop
            end
        rescue
            puts "#{Thread.current.inspect}: Ow, I died. :("
            Thread.current.exit
        end
    end
end
sleep(1) until production.stop? and send_queue.empty?
print "\n"
puts "Sent #{sent} tests in #{"%2.2f" % (Time.now - start)} seconds. Bye."
