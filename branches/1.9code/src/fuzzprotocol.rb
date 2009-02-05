require 'objhax'
require 'yaml'

class FuzzMessage

    # .new can take a Hash or YAML-dumped Hash, and any symbols not defined 
    # below will also be added as getters and setters, making the protocol
    # self extending if both parties agree.
    def initialize(data)
        @msghash={:verb=>'',:station_id=>'',:data=>'',:checksum=>''}
        if data.class==String
            load_yaml(data)
        else
            unless data.class==Hash
                raise ArgumentError, "FuzzMessage: .new takes a Hash or a YAML-dumped Hash."
            end
            @msghash={:verb=>'',:station_id=>'',:data=>'',:checksum=>''}.merge! data
        end
        # Set up instance getters and setters for the hash symbols
        @msghash.each {|k,v|
            meta_def k do
                @msghash[k]
            end

            meta_def (k.to_s+'=').to_sym do |new_val|
                @msghash[k]=new_val
            end
        }
            
    end

    def to_hash
        @msghash
    end

    # Users should probably just instantiate a new object with YAML data
    def load_yaml(yaml_data)
        begin
            decoded=YAML::load(yaml_data)
            unless decoded.class==Hash
                raise ArgumentError, "FuzzMessage (load_yaml): YAML data not a Hash!"
            end
            @msghash.merge!(decoded)
        rescue
            raise ArgumentError, "FuzzMessage (load_yaml): Bad YAML data."
        end
    end

    def to_yaml
        YAML::dump(@msghash)
    end
end

=begin
f=FuzzMessage.new({:verb=>"NEWDATA",:message=>"ELEPHANTS RULE"})
dumped=f.to_yaml
p dumped.class
tst=YAML::load(dumped)
p tst
g=FuzzMessage.new(dumped)
p g
p g.message
=end
