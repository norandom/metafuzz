require 'binstruct'
require 'fib'

data=IO.read('c:\bunk\boof.doc',1472,512)
p data.length
a=WordFIB.new(data)
p a.fields.map {|f| f.length}.inject(0) {|s,n| s+=n}/8
p a.fields.last
p a.to_s.length
