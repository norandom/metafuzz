#The main point of interest of this module are the two hashes Injection_Generators and Replacement_Generators which 
#allow users to create custom blocks of fuzzing code that will be run for fields of a certain type. Want to run the cool
#x509 fuzzing code you just wrote and define an x509 field for use within BinStruct? Just add the code as a proc to these hashes
#and add a new Fields::Field subclass to the Fields module.
#
#If your new field type is Fields::FooField you do it like this:
# module Mutations
# 	Injection_Generators["foo"]=Proc.new {|maxlen| # l33t code here} 
# 	Replacement_Generators["foo"]=Proc.new {|maxlen| # more l33t code}
# end
#
#Now your code gets run to generate the injection and replacement elements whenever the fuzzer gets to a FooField.
#
# ---
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# Please read LICENSE.TXT for details. Or see RDoc for the file license.rb
module Mutations
		
	# creates an incrementing generator from a set of tokens. Resulting strings will contain
    # an exponentially incrementing number of tokens chosen from the set, until the maximum 
    # length is reached (tokens can be more than one character).
	def create_string_generator(set, maxlen)
		Generators::Repeater.new("foo",0,0,maxlen,proc {|a| a.map {|e| set[rand(set.length)]}.to_s})
	end
	module_function :create_string_generator
	
	# Tweakable blocks that create the fuzz element generators, based on field type.
	# New field types might want to add their own fuzz element generators. The default
	# is to generate random 8-bit junk, but a special case is defined for string types.
	# The overflow elements for strings are four sets of strings of random selections from 
	# {/^*.[]$+@?1234()\'`} (regexp)  rand(256) (junk) and {%x%s%n} (format string) and {'p'} (ASCII).
	# This hash is for the injected elements, not the replacement elements.
	injection_default=Proc.new{|maxlen, sepstring| 
		gJunk=create_string_generator(Array((0..255)).map {|e| "" << e},maxlen)
		gSep=create_string_generator([sepstring],maxlen)
		gFinal=gJunk
		gFinal=Generators::Chain.new(gFinal,gSep) unless sepstring==""
		gFinal
	}
	Injection_Generators=Hash.new(injection_default) #:nodoc:
	Injection_Generators["string"]=Proc.new {|maxlen, sepstring|
		gJunk=create_string_generator(Array((0..255)).map {|e| "" << e},maxlen)
		gLetters=create_string_generator(['p'],maxlen)
		gRegexp=create_string_generator(%w(/ ^ * . [ ] $ + @ ? 1 2 3 4 ( ) \\ ` '),maxlen)
		gFormat=create_string_generator(%w(%s %n %x),maxlen)
		gTokens=create_string_generator([' ',"\t","\n",':',';',','],maxlen)
		gSep=create_string_generator([sepstring],maxlen)
		gFinal=Generators::Chain.new(gLetters,gFormat,gTokens,gRegexp,gJunk)
		gFinal=Generators::Chain.new(gFinal,gSep) unless sepstring==""
		gFinal
	}
	# This hash is for the blocks that will create generators for field replacement generators.
	# The default looks at the length type. For fixed length fields it will enumerate possible values
	# if the field is <= 8 bits in length. For longer fields it will yield a set of binary corner cases.
	# For variable length fields like strings, hexstrings and the like it expands them by repeating the field up to maxlen times. 
	# and then runs a rolling corruption pass over them at the binary level (see the RollingCorrupt Generator)
	# corrupting 13 bits with a stepsize of 3 then 17 bits with a stepsize of 17. Finally, it successively removes
	# the middle third of the string until it is length 2.
	# Users would want to add
	# new blocks to the hash when they have types that need complicated fuzzing, eg ASN.1,
	# compressed chunks and the like.
	Replacement_Generators={} #:nodoc:
	Replacement_Generators.default=Proc.new{|field, maxlen|
		@preserve_length=true
		if field.length_type=="fixed" or maxlen==0
			# for fields > 8 bits, just test the corner cases
			if field.length > 8
				g=Generators::BinaryCornerCases.new(field.length)
			else # enumerate fully
				g=Generators::Repeater.new((0..(2**field.length)-1),1,1,1,proc {|a| a.first})
			end
		elsif field.length_type=="variable"
			rep=Generators::Repeater.new(field.get_value,0,0,maxlen,proc {|a| a.to_s})
			rc1=Generators::RollingCorrupt.new(field.get_value,8,8)
			rc2=Generators::RollingCorrupt.new(field.get_value,16,16)
			chopper=Generators::Chop.new(field.get_value)
			g=Generators::Chain.new(rep,rc1,rc2, chopper)
		else
			raise RuntimeError, "Mutations::replace_field: Unknown length type #{field.length_type}"
		end
	}
	#Yields a series of data elements that can be used to replace the field which is passed as a parameter.
	#
	#Looks up the field.type as a string in a Replacement_Generators hash, so users can expand the repetoire of
	#generators by creating custom field types that require particular fuzzing approaches.
	def replace_field(field, coverage, maxlen) #:yields:replacement_data
		#grab a generator
		g=Replacement_Generators[field.type].call(field, maxlen)
		while g.next?
			yield g.next
		end 
	end #replace_field
	
	#Yields a series of data elements that can be injected immediately before the field which is passed as a parameter,
	#and once after the final field.
	#
	#Looks up the field.type as a string in an Injection_Generators hash, so users can expand the repetoire of
	#generators by creating custom field types that require particular fuzzing approaches. The separator string
	#for the structure (if any) is also passed as a parameter, and will be expanded during the fuzzing process.
	def inject_data(field, maxlen) #:yields:data_to_inject
		#grab a generator
		g=Injection_Generators[field.type].call(maxlen, @binstruct.separator)
		while g.next?
			yield g.next
		end
	end #inject_data
	
end
