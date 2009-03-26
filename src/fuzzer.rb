require 'binstruct'
require 'generators'
require 'mutations'

#The Fuzzer class is a simple metafuzzing example. It will attempt to send sensible fuzzing
#output based on the types of fields within the structure. Fuzzer allows the user to specify 'fixup'
#code blocks that will be run in order, using output chaining, on the fuzzed structure element. 
#Some examples might be blocks that encrypt or encode the data, correct length fields, calculate
#checksums or simply add to the confusion by randomly messing with the output.
class Fuzzer
    include Mutations
    self.extend Mutations
    # binstruct is a kind_of? BinStruct.
    # *fixups is an array of Proc objects or lambdas which can do things like correct
    # lengths within the structure, calculate checksums and so forth. The fixups will
    # be applied cumulatively in the order specified. REMEMBER that the fixups need
    # to be able to deal with the fact that the fields may not all be kind_of? Field::Field
    # if some extension code or a previous fixup has messed with the obj#fields Array directly.
    # Also, the fixups need to return the struct itself, usually this is as simple as
    # proc do {|bs| #code; bs}

    attr_reader :check
    attr_accessor :preserve_length, :verbose

    def self.string_to_binstruct( str, granularity=8, endian=:big )
        strclone=str.clone
        chunk_array=[]
        chunk_size=str.length/granularity > 0 ? str.length/granularity : 1
        while strclone.length > 0
            chunk_array << strclone.slice!(0,chunk_size)
        end
        raise RuntimeError, "Fuzzer: Data corruption while converting string to BinStruct" unless str==chunk_array.join
        bstruct=BinStruct.new
        bstruct.endian=endian
        chunk_array.each {|elem|
            #add elem to bstruct
            inject_field=Fields::StringField.new(elem.unpack('B*').join,'fromstr',elem.length*8,"String to BinStruct",nil,bstruct.endianness)
            bstruct.fields << inject_field
        }
        bstruct
    end

    def initialize(fuzztarget, *fixups)
        unless fuzztarget.kind_of? String or fuzztarget.kind_of? BinStruct
            raise ArgumentError, "Fuzzer: Don't know how to fuzz #{fuzztarget.class}, only String and Binstruct"
        end
        if fuzztarget.kind_of? String
            #do string thing
            @binstruct=Fuzzer.string_to_binstruct(fuzztarget)
        else
            #do binstruct thing
            @binstruct=fuzztarget
        end
        raise ArgumentError, "Fuzzer: Fixups must all be Proc objects." unless fixups.all? {|f| f.kind_of? Proc}
        @fixups=fixups
        @preserve_length=false
        @grouplink=true
        @verbose=true
        @check=@binstruct.to_s
    end

    def count_tests(overflow_maxlen=5000, send_unfixed=true, skip=0, fuzzlevel=1)
        num_tests=0
        was_true=@verbose
        @verbose=false
        begin
            self.basic_tests(overflow_maxlen, send_unfixed, skip, fuzzlevel) {|t| 
                num_tests+=1
            }
        rescue
            raise RuntimeError, "Fuzzer:count_tests: An error #{$!} at #{num_tests}"
            exit
        end
        @verbose=true if was_true
        raise RuntimeError, "Count: Oops, we screwed the struct" unless @binstruct.to_s==@check
        num_tests
    end

    #Run three basic sets of tests for each field.
    #1. Enumerate possible field values (replace)
    #The next two tests are only done if Fuzzer#preserve_length == false (default)
    #2. Delete the field from the structure (delete)
    #3. Insert overflow elements into the structure before each field (and at the end) (inject)
    #
    #Each fuzzed structure will be yielded with and without fixup procedures applied
    #if the send_unfixed paramter is true (which is the default).
    #
    #Example:
    # f=Fuzzer.new(ExampleStruct.new)
    # f.basic_tests("corner", 1500, false) {|pkt| some_socket.send(pkt,0)} 
    def basic_tests( overflow_maxlen=5000, send_unfixed=true, skip=0, fuzzlevel=1 ) #:yields:fuzzed_item

        count=0
        if skip > 0
            puts "Skipping #{skip} tests."
        end
        fuzzblock=proc do |current_field| # remember that it's possible for current_field to be not a Fields::Field

            puts "Starting new field" if @verbose
            puts @binstruct.inspect[@binstruct.flatten.index(current_field)] if @verbose
            # Test 1 - Enumerate possible values for this field. Uses the fuction replace_field in the Mutations module
            # to decide what to replace the field with - see that module for the defaults. It should be possible to add all
            # the custom fuzzing code to Mutations, not here.
            val=current_field.get_value
            replace_field(current_field, overflow_maxlen, fuzzlevel, @preserve_length) do |value| 
                begin
                    # best to set it using raw binary to avoid signedness issues etc
                    current_field.set_raw value.unpack('B*').join[-current_field.length..-1]
                    next if @binstruct.to_s==@check
                rescue ArgumentError, NoMethodError
                    puts "Skipping field: #{$!}" if @verbose
                    # most likely was not a Fields::Field
                    next
                end
                if @preserve_length
                    unless @binstruct.to_s.length == @check.to_s.length
                        puts "#{@binstruct.to_s.length} vs #{@check.to_s.length}"
                        puts current_field.inspect
                        puts current_field.bitstring.length
                        puts current_field.get_value.length
                        puts val.length
                        raise RuntimeError, "Fuzzer: Length Mismatch when @preserve_length set!" 
                    end
                end
                if send_unfixed || @fixups.empty?
                    if count >= skip
                        puts @binstruct.inspect[@binstruct.flatten.index(current_field)] if @verbose
                        yield @binstruct 
                    end
                    count+=1
                end
                unless @fixups.empty?
                    if count >= skip
                        fixed_bs=@fixups.inject(@binstruct) {|struct,fixup| fixup.call(struct)}
                        next if fixed_bs.to_s==@check
                        puts fixed_bs.inspect[fixed_bs.flatten.index(current_field)] if @verbose
                        yield fixed_bs
                    end
                    count+=1
                end
            end
            current_field.set_value(val)
            raise RuntimeError, "Fuzzer: Data Corruption" unless @binstruct.to_s==@check
            #puts "Check passed."

            puts "starting delete" if @verbose
            nulfield=BinStruct.new 
            unless @preserve_length
                @binstruct.replace(current_field, nulfield)
                unless @binstruct.to_s==@check
                    if send_unfixed || @fixups.empty?
                        if count >= skip
                            yield @binstruct 
                        end
                        count+=1
                    end
                    unless @fixups.empty?
                        if count >= skip
                            fixed_bs=@fixups.inject(@binstruct) {|struct,fixup| fixup.call(struct)}
                            next if fixed_bs.to_s==@check
                            yield fixed_bs
                        end
                        count+=1
                    end

                end
                @binstruct.replace(nulfield,current_field)
            else
                #puts "Skipping delete"
            end
            raise RuntimeError, "Fuzzer: Data Corruption" unless @binstruct.to_s==@check

            # Test 3 - Insert overflow chunks of varying lengths before the field
            # unless @preserve_length is set
            # Uses the inject_data function from the Mutations module to decide what to inject.
            # Creates a StringField to contain
            # the overflow chunk data so that things that iterate over the field array expecting
            # Fields::Field types will not break (even if things will be in the wrong order
            # sometimes)
            puts "starting inject" if @verbose
            unless @preserve_length
                # if this is the first field, dump the chunks before.
                if current_field==@binstruct.flatten.first
                    inject_data(current_field, overflow_maxlen, fuzzlevel) do |chunk|
                        chunk=(chunk+current_field.to_s).unpack('B*').join
                        inject_field=Fields::StringField.new(chunk,'injected',chunk.length*8,"injected by fuzzer",nil,@binstruct.endianness)
                        @binstruct.replace(current_field, inject_field)

                        if send_unfixed || @fixups.empty?
                            if count >= skip
                                puts @binstruct.inspect[@binstruct.flatten.index(inject_field)] if @verbose
                                yield @binstruct 
                            end
                            count+=1
                        end
                        unless @fixups.empty?
                            if count >= skip
                                fixed_bs=@fixups.inject(@binstruct) {|struct,fixup| fixup.call(struct)}
                                next if fixed_bs.to_s==@check
                                puts fixed_bs.inspect[fixed_bs.flatten.index(inject_field)] if @verbose
                                yield fixed_bs
                            end
                            count+=1
                        end

                        @binstruct.replace(inject_field, current_field)
                        raise RuntimeError, "Fuzzer: Data Corruption" unless @binstruct.to_s==@check
                    end
                end
                inject_data(current_field, overflow_maxlen, fuzzlevel) do |chunk|
                    chunk=(current_field.to_s+chunk).unpack('B*').join
                    inject_field=Fields::StringField.new(chunk,'injected',chunk.length,"injected by fuzzer",nil,@binstruct.endianness)
                    @binstruct.replace(current_field,inject_field)
                    if send_unfixed || @fixups.empty?
                        if count >= skip
                            puts @binstruct.inspect[@binstruct.flatten.index(inject_field)] if @verbose
                            yield @binstruct 
                        end
                        count+=1
                    end
                    unless @fixups.empty?
                        if count >= skip
                            fixed_bs=@fixups.inject(@binstruct) {|struct,fixup| fixup.call(struct)}
                            next if fixed_bs.to_s==@check
                            puts fixed_bs.inspect[fixed_bs.flatten.index(inject_field)] if @verbose
                            yield fixed_bs
                        end
                        count+=1
                    end

                    @binstruct.replace(inject_field, current_field)
                    raise RuntimeError, "Fuzzer: Data Corruption" unless @binstruct.to_s==@check
                end
            else
                #puts "Skipping Insert"
            end
            puts "inject done" if @verbose
        end # fuzzblock
        if @binstruct.respond_to? :deep_each
            @binstruct.flatten.reverse.each &fuzzblock
        else
            @binstruct.fields.each &fuzzblock
        end
        if @grouplink
            cartprod_block=proc do |bs|
                bs.groups.each {|group, contents|
                    fields=contents.flatten.map {|sym| bs[sym]}
                    saved_values=fields.map {|field| field.get_value}
                    gens=fields.map {|field| 
                        Mutations::Replacement_Generators[field.type].call(field, overflow_maxlen, @preserve_length, 8*fuzzlevel)
                    }
                    cartprod=Generators::Cartesian.new(*gens)
                    while cartprod.next?
                        new_values=cartprod.next
                        fields.zip(new_values) {|field,new_value| field.set_raw(new_value.unpack('B*').join[-field.length..-1])}
                        if send_unfixed || @fixups.empty?
                            if count >= skip
                                puts "---cartprod start---" if @verbose
                                fields.each {|f| puts @binstruct.inspect[@binstruct.flatten.index(f)]} if @verbose
                                puts "---cartprod finish---" if @verbose
                                next if @binstruct.to_s==@check
                                yield @binstruct 
                            end
                            count+=1
                        end
                        unless @fixups.empty?
                            if count >= skip
                                fixed_bs=@fixups.inject(@binstruct) {|struct,fixup| fixup.call(struct)} if @fixups
                                puts "---cartprod start---" if @verbose
                                fields.each {|f| puts fixed_bs.inspect[fixed_bs.flatten.index(f)]} if @verbose
                                puts "---cartprod finish---" if @verbose
                                next if fixed_bs.to_s==@check
                                yield fixed_bs
                            end
                            count+=1
                        end
                    end
                    fields.zip(saved_values) {|field,saved_value| field.set_value saved_value}
                    raise RuntimeError, "Fuzzer: Data Corruption in cartesian product" unless @binstruct.to_s==@check
                }
                bs.each {|atom|
                    cartprod_block.call(atom) if atom.respond_to? :groups
                }
            end
            cartprod_block.call(@binstruct)
        end
    end	# basic_tests
end

if __FILE__==$0
    puts "Starting tests..."
    require 'fuzzer'
    require 'wordstruct'
    b=WordStructures::WordSPRM.new("\x01\x08\x01")
    bs=BinStruct.new("\x02\x01") {|buf| endian :little;string buf, :foo, 16, "thing"}
    f=Fuzzer.new(bs)
    b.deep_each {|f| p f.name}
    #f.preserve_length=true
    f.basic_tests(10,false) {|t| p t}
end
