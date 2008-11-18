require 'generator'
require 'objhax'

#Generators that can be used to create output for various purposes.
#The Fuzzer object already contains tweakable constants that will create simple generators for basic elements like
#signed and unsigned fields, strings and the like, but you can create new fields and define your own generators for
#more complex elements like ASN.1, URLs, email fields, HTML elements or whatever. The individual generators are
#documented under the class definitions. The generators inherit from the Generator class, so they support <tt>next?, next, 
#index, current</tt> etc.
#
# ---
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# Please read LICENSE.TXT for details. Or see RDoc for the file license.rb
module Generators

  #In: Series, Start, Step, Limit, [Transform1, [...] TransformN]
  # 
  #Series can be anything that can be coerced into 
  #an array including Array, String, Generator etc.
  #Start, Step and Limit are the initial value, stepsize
  #and maximum repeat count. 
  #If start=0
  #then the first step will be skipped, so start=0 step=50
  #will produce 50 whatevers as the first iteration.
  #If step=0 then an exponential step will be used, adding
  #3, 5, 9, 17, 33, 65, 129 [...] to the start value ( (2**stepnum) + 1 ),
  #with the final step being replaced by the limit variable.
  #Transform1..N are Proc objects that will
  #be run, in order, at each iteration to perform
  #output feedback mutation.
  #The first transform is run on the final array itself, so 
  #it needs to be able to cope with an array (eg Proc.new {|a| a.to_s})
  #A Repeater with start,step,limit=1,1,1 can be used as a Dictionary
  #by passing a list or an Incrementor by passing a range.
  #
  #Examples:
  # g=Generators::Repeater.new('A',0,2,10, proc {|a| a.to_s })
  # g.to_a
  # => ["AA", "AAAA", "AAAAAA", "AAAAAAAA", "AAAAAAAAAA"]
  #
  # g=Generators::Repeater.new( (1..6),1,1,1,proc {|a| a.first })
  # g.to_a
  # => [1, 2, 3, 4, 5, 6]
  #
  # g=Generators::Repeater.new( %w( dog cat monkey love ),1,1,1,proc {|a| a.to_s })	
  # g.to_a
  # => ["dog", "cat", "monkey", "love"]
  #
  # g=Generators::Repeater.new( %w( dog cat monkey love ),1,1,1,proc {|a| a.to_s}, proc {|s| Base64.encode64(s).chop })
  # g.to_a
  # => ["ZG9n", "Y2F0", "bW9ua2V5", "bG92ZQ=="]
  #
  # g=Generators::Repeater.new( "replace me!",1,1,10,proc {|a| a.map {|e| rand(256).chr }.join} )
  # g.to_a
  # => ["\252", "j\302", "\264\231C", "\245\303\334\314", "\351\230R\207K", 
  #      "\343;\356b\201\t", "\204\212sR\027$\344", "B\274~8\2128G\242", 
  #      "/9,<*\365}\023q", "u\212\3129\241X\267Ao\246"]
  class Repeater < Generator

    def initialize(series, start, step, limit, *transforms)

      @series=series
      @transforms=transforms
      @start,@step,@limit=start,step,limit

      unless @series.kind_of? Generator
        items=Array(@series)
      else
        items=@series
      end

      results=[]
      repeats=[@start]
      while repeats.last < @limit
        if @step==0
          repeats << repeats.first + 2**(repeats.length)+1
        else
          repeats << repeats.last + @step
        end
      end
      repeats.shift if repeats.first==0
      if repeats.last > @limit
        repeats.pop; repeats.push @limit
      end
      @block=proc {|g|
        items.each {|item|
          repeats.map {|e| Array.new(e, item)}.each {|r|
            # run procs on array to be yielded
            g.yield(transforms.inject(r) {|r, xform|
              xform.call(r)
            })
          }
        }
      }
      @index = 0 
      @queue = [] 
      @cont_next = @cont_yield = @cont_endp = nil 
      if @cont_next = callcc { |c| c } 
        @block.call(self) 
        @cont_endp.call(nil) if @cont_endp 
      end 
      self 
    end

    #Reset generator to original state.
    def rewind()
      initialize(@series, @start, @step, @limit, *@transforms) if @index.nonzero?
    end
  end


  #In: n Series where n>0.
  #Out: Arrays, each having n elements
  #	
  #The Cartesian generator will output each item in the cartesian
  #product of the series passed as arguments. Output
  #is in the form of an array. 
  #
  #Example: 
  # require 'generators'
  # g=Generators::Cartesian.new( ('a'..'c'), [1,2], %w( monkey hat ) )
  # while g.next?
  #	foo, bar, baz=g.next
  #	puts "#{foo} : #{bar} -- #{baz}"
  # end
  #Produces:
  # a : 1 -- monkey
  # a : 1 -- hat
  # a : 2 -- monkey
  # a : 2 -- hat
  # b : 1 -- monkey
  # b : 1 -- hat
  # b : 2 -- monkey
  # b : 2 -- hat
  # c : 1 -- monkey
  # [etc]
  #Note: The cartesian product function is quite forgiving
  #and will take Generators, Ranges and Arrays (at least)
  class Cartesian < Generator

    def cartprod(base, *others) #:nodoc:
      if block_given?
        if others.empty?
          base.each{|a| yield [a]}   
        else
          base.each do | a |
            cartprod(*others) do | b |
            yield [a, *b] 
            end
          end
        end
        nil
      else
        return base.map{|a|[a]} if others.empty?
        others = cartprod(*others)
        base.inject([]) { | r, a | others.inject(r) { | r, b | r << ([a, *b]) } }
      end
    end

    def initialize (*series)
      @series=series
      @block=proc {|g|
        cartprod(*series).each {|elem|
          g.yield elem
        }
      }
      @index = 0 
      @queue = [] 
      @cont_next = @cont_yield = @cont_endp = nil 
      if @cont_next = callcc { |c| c } 
        @block.call(self) 
        @cont_endp.call(nil) if @cont_endp 
      end 
    end

    def rewind()
      initialize(*@series) if @index.nonzero?
    end
  end

  #Outputs a stream of corner cases for the given bitlength as Integers
  #
  #Currently, this will output all 1's, all 0s,
  #plus a few corner cases like 1000, 0001, 1110, 0111
  #0101, 1010 etc
  #
  # require 'generators'
  # g=Generators::BinaryCornerCases.new(16)
  # g.to_a.map {|case| "%.16b" % case}
  #Produces:
  # ["1111111111111111", "0000000000000000", "1000000000000000", "0000000000000001", 
  #  "0111111111111111", "1111111111111110", "1100000000000000", "0000000000000011", 
  #  "0011111111111111", "1111111111111100", "1110000000000000", "0000000000000111", 
  #  "0001111111111111", "1111111111111000", "1010101010101010", "0101010101010101"]
  class BinaryCornerCases < Generator


    def initialize (bitlength)
      @bitlength=bitlength

      cases=[]
      # full and empty
      cases << ('1'*bitlength).to_i(2)
      cases << ('0'*bitlength).to_i(2)
      # flip up to 4 bits at each end
      # depending on bitlength
      case
      when @bitlength > 32
        lim=4
      when (16..32) === @bitlength
        lim=3
      when (8..15) === @bitlength
        lim=2
      else
        lim=1
      end
      for i in (1..lim) do
        cases << (('1'*i)+('0'*(bitlength-i))).to_i(2)
        cases << (('0'*(bitlength-i))+('1'*i)).to_i(2)
        cases << (('0'*i)+('1'*(bitlength-i))).to_i(2)
        cases << (('1'*(bitlength-i))+('0'*i)).to_i(2)
      end
      # alternating
      cases << ('1'*bitlength).gsub(/11/,"10").to_i(2)
      cases << ('0'*bitlength).gsub(/00/,"01").to_i(2)

      @block=proc {|g|
        # The call to uniq avoids repeated elements
        # when bitlength < 4
        cases.uniq.each {|c| g.yield c}
      }
      @index = 0 
      @queue = [] 
      @cont_next = @cont_yield = @cont_endp = nil 
      if @cont_next = callcc { |c| c } 
        @block.call(self) 
        @cont_endp.call(nil) if @cont_endp 
      end 
    end

    def rewind()
      initialize(@bitlength) if @index.nonzero?
    end

  end

  #In: Value, Limit, Transform1, ... TransformN
  #
  #Out: Value, passed through each Transform in order
  #	
  #Although named Static, this generator can be passed
  #Proc objects that refer to variables in the appropriate namespace, which
  #can allow the output to change. If you update a
  #variable that affects a Proc you will need to make
  #one call to <tt>next</tt> to clear the last queue entry
  #before the output stream changes. Proc objects that make internal calls to <tt>Kernel::rand</tt>
  #will also produce a variable output stream.
  #
  #The Generator will run out after Limit calls, or never
  #if Limit is specified as -1.
  #
  #WARNING: Don't pass one of these to the Cartesian
  #generator with a limit of -1 or you'll get an infinite loop.
  #
  #Example:
  # g=Generators::Static.new("angry gibbon", 5, proc {|s| OpenSSL::Digest::MD5.new( s + rand(256).chr ) } )
  # g.to_a
  # => [e2fc714c4727ee9395f324cd2e7f331f, 68774090e020b81d2bd584298a8cd612, 
  #     971f3cbaa55fa9f7290effc88b42b39b, dcc4a4d1992c0cd595454eb34b74e761, 
  #     a7aef58ed131b9ebf095d608d57529d9]
  class Static < Generator


    def initialize (val, limit, *transforms)
      @val=val
      @limit=limit
      @transforms=transforms
      @block=proc {|g|
        if limit==-1
          loop do
            g.yield(transforms.inject(Marshal.load(Marshal.dump(@val))) {|val, proc|
              val=proc.call(val)
            })
          end
        else
          for i in (1..limit)
            g.yield(transforms.inject(Marshal.load(Marshal.dump(@val))) {|val, proc|
              val=proc.call(val)
            })
          end
        end
      }
      @index = 0 
      @queue = [] 
      @cont_next = @cont_yield = @cont_endp = nil 
      if @cont_next = callcc { |c| c } 
        @block.call(self) 
        @cont_endp.call(nil) if @cont_endp 
      end 
    end

    def rewind()
      initialize(@val, @limit, *@transforms) if @index.nonzero?
    end
  end

  # Takes a series of kind_of? Generator objects and produces a generator which will produce the output of 
  # all the others by calling g.next over and over.
  # You could also do this by passing g1.to_a+g2.to_a
  # to the Repeater, but this is cleaner and uses lazier
  # evaluation.
  class Chain < Generator
    def initialize ( *generators )
      @generators=generators

      @block=proc {|g|
        generators.each {|gen|
          while gen.next?
            g.yield gen.next
          end
        }
      }
      @index = 0 
      @queue = [] 
      @cont_next = @cont_yield = @cont_endp = nil 
      if @cont_next = callcc { |c| c } 
        @block.call(self) 
        @cont_endp.call(nil) if @cont_endp 
      end 
    end

    def rewind()
      @generators.each {|g| g.rewind}
      initialize(*@generators) if @index.nonzero?
    end
  end

  # Parameters: String, Bitlength, Stepsize.
  # Will corrupt Bitlength bits of the provided string by substituting each of the binary outputs
  # of the BinaryCornerCases generator. At each step it will advance the 'rolling window' that is
  # being corrupted by Stepsize bits. So, with Bitlength 11 and Stepsize 3 it will first corrupt bits
  # [0..10] then bits [3..13] and so on. Note that it is assumed that the string is packed already, so it 
  # will be unpacked to binary, corrupted at the binary level and then repacked.
  class RollingCorrupt < Generator
    def initialize(str, bitlength, stepsize)
      @str,@bitlength,@stepsize=str,bitlength,stepsize
      @binstr=str.unpack('B*').first
      raise RuntimeError, "Generators::RollingCorrupt: internal bitstring conversion broken?" unless @binstr.length==(@str.length*8)
      @block=proc {|g|
        gBin=Generators::BinaryCornerCases.new(bitlength)
        rng=Range.new(0, @binstr.length-1)
        rng.step(stepsize) {|idx|
          gBin.rewind
          while gBin.next?
            out_str=@binstr.clone
            out_str[idx..idx+(bitlength-1)] = "%.#{bitlength}b" % gBin.next
            g.yield [out_str[0..@binstr.length-1]].pack('B*')
	  end
        }

      }
      @index = 0 
      @queue = [] 
      @cont_next = @cont_yield = @cont_endp = nil 
      if @cont_next = callcc { |c| c } 
        @block.call(self) 
        @cont_endp.call(nil) if @cont_endp 
      end 
    end

    def rewind()
      initialize(@str,@bitlength,@stepsize) if @index.nonzero?
    end
  end

  class Chop < Generator
    def remove_middle_third( instr )
      len=instr.length
      return instr if len < 3
      case (len % 3)
      when 0 # smallest case 3 => 1 (1) 1
        return instr[0..(len/3)-1] + instr[-(len/3)..-1]
      when 1 # smallest case 4 => 1 (2) 1
        return instr[0..((len-1)/3)-1] + instr[-((len-1)/3)..-1]
      when 2 # smallest case 5 => 2 (1) 2
        return instr[0..((len+1)/3)-1] + instr[-((len+1)/3)..-1]
      else
        raise RuntimeError, "Universe broken, modulus doesn't work."
      end
    end

    def initialize(str)
      @str=str
      @block=proc {|g|
        while str.length >= 3
          str=remove_middle_third(str)
          g.yield str
        end
      }
      @index = 0 
      @queue = [] 
      @cont_next = @cont_yield = @cont_endp = nil 
      if @cont_next = callcc { |c| c } 
        @block.call(self) 
        @cont_endp.call(nil) if @cont_endp 
      end 
    end

    def rewind()
      initialize(@str) if @index.nonzero?
    end
  end


end
