require 'rubygems'
require 'fuzzer'

class Producer < Generators::NewGen

    Template=File.open( File.expand_path("~/fuzzserver/rtf.doc"),"rb") {|io| io.read}

    def initialize
        @duplicate_check=Hash.new(false)
        @block=Fiber.new do
            loop do
		p Template[336..346]
            Fiber.yield Template
            print '.';$stdout.flush
            end
            false
        end
        super
    end
end
