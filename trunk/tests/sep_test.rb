require 'binstruct'
require 'fuzzer'

=begin
class HTTPGet < BinStruct
	string :op, 0, "Operation"
	string :dir, 0, "Directory"
	string :ver, 0, "Version"
	
	separator ' '
	default_value :op, "GET"
	default_value :dir, '/'
	default_value :ver, "HTTP/1.0"
end
=end

#f=Fuzzer.new(SepTest.new)
#f.basic_tests("corner", 10, false) {|pkt| p pkt.to_s}

#hreq=HTTPGet.new "GET /cgi-bin/thing.cgi HTTP/1.0"
#hreq.fields.each {|f| p f.to_s}

class BeerReq < BinStruct
	bitstring :flags, 8, "Beer Flags"
	signed :temp, 8, "Beer Temperature"
	unsigned :len, 8, "Name Length"
	string	:name, 'self.len * 8', "Beer Name"
	string :extra, 32*8, "Extra Beer Data", 
		'self.flags[0..0]=="1"'
		
	def drink
		puts "BEER MAKES ME HAPPY!!"
	end

end

require 'fuzzer'
f=Fuzzer.new(BeerReq.new)
f.basic_tests("corner",10,false) {|req| p req.pack}


