require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'
require 'thread'
require 'fuzzer'
require 'fib'
require 'diff/lcs'
require 'wordstruct'
require 'ole/storage'
require 'mutations'

default_config={"AGENT NAME"=>"PRODSERVER",
    "SERVER IP"=>"0.0.0.0",
    "SERVER PORT"=>11000,
    "WORK DIR"=>'C:\prodserver',
    "CONFIG DIR"=>'C:\prodserver',
    "COMPRESSION"=>false,
    "SEND DIFFS ONLY"=>false,
    "USE THREADPOOL"=>true,
    "POLL INTERVAL"=>5
}

config_file=ARGV[0]
if config_file and not File.exists? config_file
    puts "ProdServer: Bad config file #{config_file}, using default config."
    config=default_config
elsif not config_file
    if File.exists?(File.join(default_config["CONFIG DIR"],"prodserver_config.txt"))
        puts "ProdServer: Loading from default config file."
        config_data=File.open(File.join(default_config["CONFIG DIR"],"prodserver_config.txt"), "r") {|io| io.read}
        config=YAML::load(config_data)
    else
        puts "ProdServer: Using default config."
        config=default_config
    end
else
    begin
        config_data=File.open(config_file, "r") {|io| io.read}
        config=YAML::load(config_data)
    rescue
        puts "ProdServer: Bad config file #{config_file}, using default config."
        config=default_config
    end
end

["CONFIG DIR","WORK DIR"].each { |dirname|
    unless File.directory? config[dirname]
        print "Directory #{dirname} doesn't exist. Create it? [y/n]: "
        answer=STDIN.gets.chomp
        if answer =~ /^[yY]/
            begin
                Dir.mkdir(config[dirname])
                if dirname=="CONFIG DIR"
                    print "Saving config to #{config["CONFIG DIR"]}..."
                    begin
                        File.open(File.join(config["CONFIG DIR"],"prodserver_config.txt"),"w+") { |io|
                            io.write(YAML::dump(config))
                        }
                    rescue
                        puts "ProdServer: Couldn't write out config."
                    end
                end
            rescue
                raise RuntimeError, "ProdServer: Couldn't create directory: #{$!}"
            end
        else
            raise RuntimeError, "ProdServer: #{dirname} unavailable. Exiting."
        end
    end
}

at_exit {
    print "Saving config to #{config["CONFIG DIR"]}..."
    begin
        File.open(File.join(config["CONFIG DIR"],"prodserver_config.txt"),"w+") { |io|
            io.write(YAML::dump(config))
        }
    rescue
        puts "ProdServer: Couldn't write out config."
    end
    print "Done. Exiting.\n"
}

module ProdServer
    def initialize(data)
        @data=data
    end

    def post_init
        send_data @data
    end
end

Producer.each_item {|item|
    EventMachine::connect(config["SERVER IP"],config["SERVER PORT"],ProdServer,item)
}
