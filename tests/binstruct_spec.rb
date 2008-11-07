#Specification for the main functionality of the BinStruct library, built with the very cool Rspec ( http://rspec.rubyforge.org ).
#Doesn't have full code coverage yet, but does cover the main field assignment and value retrieval stuff.
require 'binstruct'
require 'spec'

class TestStruct < BinStruct #:nodoc:
	unsigned :flag, 1, "Attribute Format Flag"
	signed :type, 15, "Attribute Type"
	unsigned :length, 16, "Attribute Length", "self.flag==0"
	bitstring :flags, 13, "Some Flags"
	bitstring :pad, 3, "Random Padding"
	hexstring :testhex, 64, "Some hex data"
	string :teststr, 32, "Some string data"
	octetstring :ipaddr, 32, "IP Address"
	string :long_value, "self.length", "Attribute Value", "self.flag==0"
	unsigned :short_value, 8*2, "Attribute Value", "self.flag==1"
	default_value :type, -23
	default_value :long_value, "faff"
	default_value :flag, 1
	default_value :short_value, 13
	default_value :ipaddr, "192.168.13.12"
	separator ' '
end

context "A new BinStruct" do
	specify "should inherit from BinStruct" do
		lambda {Class.new(BinStruct)}.should_not_raise
	end
	specify "should allow definition of unsigned fields" do
		lambda{Class.new(BinStruct).send(:unsigned, :flag, 1, "Attribute Format Flag")}.should_not_raise
		da=TestStruct.new;da[:short_value].length_type.should_equal "fixed"
	end
	
	specify "should allow definition of signed fields" do
		lambda{Class.new(BinStruct).send(:signed, :flag, 1, "Attribute Format Flag")}.should_not_raise
		da=TestStruct.new;da[:type].length_type.should_equal "fixed"
	end
	
	specify "should allow definition of octetstring fields" do
		lambda{Class.new(BinStruct).send(:octetstring, :flag, 1, "Attribute Format Flag")}.should_not_raise
		da=TestStruct.new;da[:ipaddr].length_type.should_equal "fixed"
	end
	
	specify "should allow definition of bitstring fields" do
		lambda{Class.new(BinStruct).send(:bitstring, :flag, 1, "Attribute Format Flag")}.should_not_raise
		da=TestStruct.new;da[:flags].length_type.should_equal "fixed"
	end
	
	specify "should allow definition of string fields" do
		lambda{Class.new(BinStruct).send(:string, :flag, 1, "Attribute Format Flag")}.should_not_raise
		da=TestStruct.new;da[:teststr].length_type.should_equal "variable"
	end
	
	specify "should allow definition of hexstring fields" do
		lambda{Class.new(BinStruct).send(:hexstring, :flag, 1, "Attribute Format Flag")}.should_not_raise
		da=TestStruct.new;da[:testhex].length_type.should_equal "variable"
	end
	
	specify "should allow definition of a separator string" do
		lambda{Class.new(BinStruct).send(:separator, ' ')}.should_not_raise
		lambda{ da=TestStruct.new;da.separator=' ' }.should_not_raise
		lambda{ da=TestStruct.new;da.separator }.should_not_raise
	end
	
	specify "should warn about unknown commands" do
		lambda{Class.new(BinStruct).send(:elephant_warriors, :flag, 1, "Attribute Format Flag")}.should_raise SyntaxError
	end
	
end

context "The test BinStruct created without arguments" do
	specify "should get correct default value for signed" do
		TestStruct.new.type.should_equal -23
	end
	specify "should get correct default value for octet strings" do
		TestStruct.new.ipaddr.should_equal "192.168.13.12"
	end
	specify "should have correct default value for the flag" do
		TestStruct.new.flag.should_equal 1
	end
	specify "should create a short_value and not a long_value" do
		TestStruct.new.short_value.should_equal 13
		lambda {TestStruct.new.long_value}.should_raise NoMethodError
	end
	specify "should create empty strings for String fields" do
		TestStruct.new.teststr.should_equal ''
	end
	specify "should create empty strings for HexString fields" do
		TestStruct.new.teststr.should_equal ''
	end
	
	specify "should be cloneable" do
		da=TestStruct.new; da.clone.to_s.should_equal da.to_s
	end
	
	specify "should have the same results for pack as to_s" do
		TestStruct.new.pack.should_equal TestStruct.new.to_s
	end
	
	specify "should have ' ' as the separator string" do
		TestStruct.new.separator.should_equal ' '
	end		
	
end

context "When assigning values to the test BinStruct" do
	specify "signed fields should not allow values that would overflow the sign bit" do
		lambda {TestStruct.new.type=16384}.should_raise ArgumentError
		lambda {TestStruct.new.type=-16384}.should_raise ArgumentError
		lambda {TestStruct.new.type=16383}.should_not_raise
		lambda {TestStruct.new.type=-16383}.should_not_raise
		da=TestStruct.new; da.type=-1; da.type.should_equal -1
	end
	
	specify "unsigned fields should not allow values that would overflow" do
		lambda {TestStruct.new.short_value=65536}.should_raise ArgumentError
		lambda {TestStruct.new.short_value=-32768}.should_raise ArgumentError
		lambda {TestStruct.new.short_value=65535}.should_not_raise
		lambda {TestStruct.new.short_value=-32767}.should_not_raise
	end
	
	specify "unsigned fields should allow negative assignment, but read the values as unsigned" do
		da=TestStruct.new; da.short_value=-1; da.short_value.should_equal 65535
	end

	specify "octet string fields should correctly handle input" do
		lambda {TestStruct.new.ipaddr="192.168.256.4"}.should_raise ArgumentError # octet out of range
		lambda {TestStruct.new.ipaddr="192.168.13"}.should_raise ArgumentError # too few octets
		lambda {TestStruct.new.ipaddr="192.168.13.4.7"}.should_raise ArgumentError # too many octets
		lambda {TestStruct.new.ipaddr="0.0.0.0"}.should_not_raise
		lambda {TestStruct.new.ipaddr="255.255.255.255"}.should_not_raise
	end
	
	specify "hex string fields should correctly handle input" do
		lambda {TestStruct.new.testhex="1234567890abcdefg"}.should_raise ArgumentError # non-hex digit
		lambda {TestStruct.new.testhex="1234567890abcdef"}.should_not_raise
		lambda {TestStruct.new.testhex="fa ce f0 0d"}.should_not_raise
		lambda {TestStruct.new.testhex="fa ce f0 0d\nff ff ff ff"}.should_not_raise
		lambda {TestStruct.new.testhex=0xff}.should_not_raise
		lambda {TestStruct.new.testhex=255}.should_not_raise
		lambda {TestStruct.new.testhex=0377}.should_not_raise
		lambda {TestStruct.new.testhex=0b11111111}.should_not_raise
		lambda {TestStruct.new.testhex=""}.should_not_raise
		lambda {TestStruct.new.testhex="f"}.should_not_raise
	end	
	
	specify "hex string fields return hex bytes, by left padding with 0 when required" do
		da=TestStruct.new; da.testhex="f"; da.testhex.should_equal "0f"
		da=TestStruct.new; da.testhex="ff"; da.testhex.should_equal "ff"
		da=TestStruct.new; da.testhex=0xff; da.testhex.should_equal "ff"
		da=TestStruct.new; da.testhex=255; da.testhex.should_equal "ff"
		da=TestStruct.new; da.testhex=15; da.testhex.should_equal "0f"
		da=TestStruct.new; da.testhex=0377; da.testhex.should_equal "ff"
		da=TestStruct.new; da.testhex=0b111100000000111111111110; da.testhex.should_equal "f00ffe"
		da=TestStruct.new; da.testhex=15732734; da.testhex.should_equal "f00ffe"
	end
	
	specify "bitstring fields should allow only '1', '0' and whitespace" do
		lambda {TestStruct.new.flags="01010101010121"}.should_raise ArgumentError # non binary
		lambda {TestStruct.new.flags=0b010101010101}.should_raise ArgumentError # not a string
		lambda {TestStruct.new.testhex="1111 1111 0000 0000\n1111 0101"}.should_not_raise
	end
	
	specify "bitstring fields return $length bits, padding left or truncating right" do
		da=TestStruct.new; da.flags="1"; da.flags.should_equal "0000000000001" # pad
		da=TestStruct.new; da.flags=""; da.flags.should_equal "0000000000000" # pad
		da=TestStruct.new; da.flags="1111 1111\n 1111 0111"; da.flags.should_equal "1111111111110" # truncate
	end
end

context "The Binstruct instance methods" do
	specify "should allow the fields to be pulled as an array" do
		TestStruct.new.fields.class.should_equal Array
	end
end






	
