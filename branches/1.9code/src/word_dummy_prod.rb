require 'rubygems'
require 'fuzzer'

class Producer < Generators::NewGen

    Template=File.open( File.expand_path("~/wordcrashes/boof.doc"),"rb") {|io| io.read}

    def initialize
        @duplicate_check=Hash.new(false)
        @block=Fiber.new do
            loop do
            Fiber.yield Template
            print '.';$stdout.flush
            end
            false
        end
        super
    end
end
