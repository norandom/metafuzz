require 'binstruct'

module WordStructures

	class StructuredStorageHeader	< BinStruct
		hexstring :sig, 8*8,	"Signature"
		hexstring :classid, 16*8, "CLSID"
		unsigned :minorver, 2*8, "Minor Version"
		unsigned :majorver, 2*8, "Major Version"
		hexstring :byteorder, 2*8, "Byte Order"
		unsigned :sectorshift, 2*8, "Sector Shift (size)"
		unsigned :minisectorshift, 2*8, "Mini Sector Shift (size)"
		unsigned :res, 2*8, "Reserved"
		unsigned :res1, 4*8, "Reserved1"
		unsigned :res2, 4*8, "Reserved2"
		unsigned :sectcount, 4*8, "Number of Sects"
		unsigned :firstsect, 4*8, "First Sect Offset"
		unsigned :transactionsig, 4*8, "Transaction Signature"
		unsigned :minisectcutoff, 4*8, "Mini Stream Max Size"
		unsigned :minifatstart, 4*8, "First Sect in Mini FAT chain"
		unsigned :minifatcount, 4*8, "Number of Mini FAT Sects"
		unsigned :difstart, 4*8, "First Sect in DIF chain"
		unsigned :difcount, 4*8, "Number of DIF Sects"
		hexstring :fat109, 436*8, "First 109 Sects"
		
		default_value :sig, "d0 cf 11 e0 a1 b1 1a e1"
		default_value :minorver, 33
		default_value :majorver, 3
		default_value :byteorder, "ff fe"
		default_value :sectorshift, 9
		default_value :minisectorshift, 6
		default_value :minisectcutoff, 4096
		endianness "intel"
	end
	
end


#data=File.open('c:\bunk\boof.doc',"rb") {|io| io.read(512)}
#a=WordStructures::StructuredStorageHeader.new(data)

raw=File.open('rawfib.txt',"r") {|io| io.readlines}
clumped=[[]]
raw.each {|line| 
	if line =~ /^Word \d+/ or line =~ /Introduced/
		clumped << []
	else
		clumped.last << line
	end
	clumped.pop if clumped.last[0] =~ /Microsoft Office/
}

final=[]	
clumped.each_index {|idx| 
	begin
	next if idx==0 or clumped[idx+1]==nil
	ary=clumped[idx]
	if ary[4] and ary[4] =~ /^:\d+$/
		type="bitfield_with_start"
	end
	if ary[0] =~ /^\d+$/  and not type
		type="bytes" 
	else
		type="bitfield" unless type
	end
	if type=="bitfield"
		#puts  "#{ary[0].chomp} : #{ary[2].chomp[1..-1]} : #{ary[4].chomp if ary[4]}"
		#final << [ary[0].chomp, ary[2].chomp[1..-1], ary[4].chomp if ary[4]]
		final << [ary[0].chomp, ary[2].chomp[1..-1],(ary[4].chomp rescue nil)]
	elsif type=="bitfield_with_start"
		#puts "#{ary[0].chomp} -- #{ary[2].chomp} : #{ary[4].chomp[1..-1]} : #{ary.last.chomp}"
		final << [ary[2].chomp,ary[4].chomp[1..-1],ary[0].chomp+' '+ary.last.chomp]
	else
		size=(clumped[idx+1][0].chomp.to_i - ary[0].chomp.to_i)*8
		p clumped[idx+1] if size<0
		#puts "#{ary[0].chomp} -- #{ary[2].chomp} : #{size} : #{ary[4].chomp if ary[4]}"
		final << [ary[2].chomp,size,(ary[0].chomp+' '+ary[4].chomp if ary[4])]
	end
	rescue 
		puts ary 
		puts type
		puts $!
		exit
	end
}

File.open("fib.txt","w+") {|io|
	io.puts "class WordFIB < Binstruct"
	io.puts
	final.each {|line| 
		next if line[1].to_i==0
		if line[2] && line[2].length > 64
			print "."
			line[2][63..-1]='[...]'
		end
		io.puts "\tunsigned :#{line[0]}, #{line[1]}, \"#{line[2]}\""
	}
	io.puts
	io.puts "\tendianness \"intel\""
	io.puts "end"
}

	
