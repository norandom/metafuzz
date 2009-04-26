require 'objhax'
require 'json'
require 'digest/md5'

class FuzzMessage

    # .new can take a Hash or YAML-dumped Hash, and any symbols not defined 
    # below will also be added as getters and setters, making the protocol
    # self extending if both parties agree.
    def initialize(data)
        if data.class==String
            load_json(data)
        else
            unless data.class==Hash
                raise ArgumentError, "FuzzMessage: .new takes a Hash or a JSON-dumped Hash."
             end
            @msghash=data
        end
        # Set up instance getters and setters for the hash symbols
        @msghash.each {|k,v|
            meta_def String(k) do
                @msghash[k]
            end

            meta_def (String(k)+'=') do |new_val|
                @msghash[k]=new_val
            end
        }
            
    end

    def to_hash
        @msghash
    end

    # Users should probably just instantiate a new object with YAML data
    def load_json(json_data)
        begin
            decoded=JSON::load(json_data)
            unless decoded.class==Hash
                raise ArgumentError, "FuzzMessage (load_json): JSON data not a Hash!"
            end
            @msghash=decoded
        rescue
            raise ArgumentError, "FuzzMessage (load_json): Bad JSON data."
        end
    end

    def to_s
        JSON::dump(@msghash)
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
