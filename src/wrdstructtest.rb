require 'binstruct'
require 'wordstruct'
require 'rubygems'
require 'ole/storage'
require 'enumerator'

def hexdump(str)
  str.unpack('H*').first.scan(/.{2}/).each_slice(16) {|s| puts s.join(' ')}
end

raw=File.open('c:\bunk\foo.doc','rb') {|io| io.read}
rawfib=raw[512,1472]
fib=WordStructures::WordFIB.new(rawfib)
ole=Ole::Storage.open('c:\bunk\foo.doc','rb')
table_stream=ole.file.read("1Table")
ole.close
p table_stream.length
p fib.fcSttbfffn
p fib.lcbSttbfffn
hexdump table_stream[fib.fcSttbfffn,fib.lcbSttbfffn]
hexdump table_stream[fib.fcCmds,fib.lcbCmds]
hexdump table_stream


