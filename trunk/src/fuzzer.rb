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

    attr_accessor :preserve_length

    def self.string_to_binstruct( str, granularity=8 )
        strclone=str.clone
        chunk_array=[]
        chunk_size=str.length/granularity > 0 ? str.length/granularity : 1
        while strclone.length > 0
            chunk_array << strclone.slice!(0,chunk_size)
        end
        raise RuntimeError, "Fuzzer: Data corruption while converting string to BinStruct" unless str==chunk_array.join
        bstruct=BinStruct.new
        chunk_array.each {|elem|
            #add elem to bstruct
            inject_field=Fields::StringField.new(elem.unpack('B*').join,'injected',elem.length*8,"This field was injected",nil,bstruct.endianness)
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
        @check=@binstruct.to_s
    end

    def count_tests(overflow_maxlen=5000, send_unfixed=true, fuzzlevel=1)
        num_tests=0
        self.basic_tests(overflow_maxlen, send_unfixed, fuzzlevel) {|t| num_tests+=1}
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
    def basic_tests( overflow_maxlen=5000, send_unfixed=true, fuzzlevel=1 ) #:yields:fuzzed_item

        @binstruct.fields.each do |current_field| # remember that it's possible for current_field to be not a Fields::Field

            # Test 1 - Enumerate possible values for this field. Uses the fuction replace_field in the Mutations module
            # to decide what to replace the field with - see that module for the defaults. It should be possible to add all
            # the custom fuzzing code to Mutations, not here.
            val=current_field.get_value
            replace_field(current_field, overflow_maxlen, fuzzlevel) do |value| 
                begin
                    if current_field.length_type=="fixed" 
                        # best to set it using raw binary to avoid signedness issues etc
                        current_field.set_raw value.to_s(2)
                    else
                        current_field.set_value value
                    end
                rescue ArgumentError, NoMethodError
                    # most likely was not a Fields::Field
                    next
                end
                if @preserve_length
                    raise RuntimeError, "Fuzzer: Length Mismatch when @preserve_length set!" unless tempstruct.to_s.length == @binstruct.to_s.length
                end
                yield @binstruct if send_unfixed || @fixups==nil
                yield @fixups.inject(@binstruct) {|struct,fixup| fixup.call(struct)} if @fixups
            end
            current_field.set_value(val)
            raise RuntimeError, "Fuzzer: Data Corruption" unless @binstruct.to_s==@check

            # Test 2 - Delete the field and send the packet unless @preserve_length is set
            idx=@binstruct.fields.index(current_field)
            unless @preserve_length
                @binstruct.fields.delete current_field
                yield @binstruct if send_unfixed || @fixups==nil
                yield @fixups.inject(@binstruct) {|struct,fixup| fixup.call(struct)} if @fixups
            end
            @binstruct.fields.insert(idx, current_field)
            raise RuntimeError, "Fuzzer: Data Corruption" unless @binstruct.to_s==@check


            # Test 3 - Insert overflow chunks of varying lengths before the field
            # unless @preserve_length is set
            # Uses the inject_data function from the Mutations module to decide what to inject.
            # Creates a BitstringField to contain
            # the overflow chunk data so that things that iterate over the field array expecting
            # Fields::Field types will not break (even if things will be in the wrong order
            # sometimes)
            unless @preserve_length
                inject_data(current_field, overflow_maxlen, fuzzlevel) do |chunk|
                    inject_field=Fields::BitstringField.new(chunk.unpack('B*').join,'injected',chunk.length*8,"This field was injected",nil,@binstruct.endianness)
                    @binstruct.fields.insert(@binstruct.fields.index(current_field),inject_field)
                    yield @binstruct if send_unfixed || @fixups==nil
                    yield @fixups.inject(@binstruct) {|struct,fixup| fixup.call(struct)} if @fixups
                    @binstruct.fields.delete(inject_field)
                    raise RuntimeError, "Fuzzer: Data Corruption" unless @binstruct.to_s==@check
                end
                # if this is the last field, dump the chunks afterwards as well.
                if current_field==@binstruct.fields.last
                    inject_data(current_field, overflow_maxlen, fuzzlevel) do |chunk|
                        inject_field=Fields::BitstringField.new(chunk.unpack('B*').join,'injected',chunk.length*8,"This field was injected",nil,@binstruct.endianness)
                        @binstruct.fields << inject_field 
                        yield @binstruct if send_unfixed || @fixups==nil
                        yield @fixups.inject(@binstruct) {|struct,fixup| fixup.call(struct)} if @fixups
                        @binstruct.fields.delete(inject_field)
                        raise RuntimeError, "Fuzzer: Data Corruption" unless @binstruct.to_s==@check
                    end
                end
            end
        end
    end	# basic_tests
end
