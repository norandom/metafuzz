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
require 'result_tracker'

default_config={"AGENT NAME"=>"SERVER",
    "SERVER IP"=>"0.0.0.0",
    "SERVER PORT"=>10000,
    "WORK DIR"=>'C:\fuzzserver',
    "CONFIG DIR"=>'C:\fuzzserver',
    "COMPRESSION"=>false,
    "SEND DIFFS ONLY"=>false,
    "USE THREADPOOL"=>true,
    "POLL INTERVAL"=>5
}

config_file=ARGV[0]
if config_file and not File.exists? config_file
    puts "FuzzServer: Bad config file #{config_file}, using default config."
    config=default_config
elsif not config_file
    if File.exists?(File.join(default_config["CONFIG DIR"],"fuzzserver_config.txt"))
        puts "FuzzServer: Loading from default config file."
        config_data=File.open(File.join(default_config["CONFIG DIR"],"fuzzserver_config.txt"), "r") {|io| io.read}
        config=YAML::load(config_data)
    else
        puts "Fuzzserver: Using default config."
        config=default_config
    end
else
    begin
        config_data=File.open(config_file, "r") {|io| io.read}
        config=YAML::load(config_data)
    rescue
        puts "FuzzServer: Bad config file #{config_file}, using default config."
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
                        File.open(File.join(config["CONFIG DIR"],"fuzzserver_config.txt"),"w+") { |io|
                            io.write(YAML::dump(config))
                        }
                    rescue
                        puts "FuzzServer: Couldn't write out config."
                    end
                end
            rescue
                raise RuntimeError, "FuzzServer: Couldn't create directory: #{$!}"
            end
        else
            raise RuntimeError, "FuzzServer: #{dirname} unavailable. Exiting."
        end
    end
}

at_exit {
    print "Saving config to #{config["CONFIG DIR"]}..."
    begin
        File.open(File.join(config["CONFIG DIR"],"fuzzserver_config.txt"),"w+") { |io|
            io.write(YAML::dump(config))
        }
    rescue
        puts "FuzzServer: Couldn't write out config."
    end
    print "Done. Exiting.\n"
}

prod_queue=SizedQueue.new(20)
# Quickly patch the queue object to add a finished? method
# Couldn't think of anything more elegant.
class << prod_queue
    def finish 
        Thread.critical=true
        @finished=true
    ensure
        Thread.critical=false
    end
    def finished?
        Thread.critical=true
        @finished||=false
    ensure
        Thread.critical=false
    end
    def template=(data)
        Thread.critical=true
        @template=data
    ensure
        Thread.critical=false
    end
    def template
        Thread.critical=true
        @template||=""
    ensure
        Thread.critical=false
    end
end

production=Thread.new do
    begin
        unmodified_file=File.open( 'c:\bunk\foo.doc',"rb") {|io| io.read}
        header,raw_fib,rest=""
        prod_queue.template=unmodified_file
        FileUtils.copy('c:\bunk\foo.doc','c:\bunk\tmp.doc')
        File.open( 'c:\bunk\tmp.doc',"rb") {|io| 
            header=io.read(512)
            raw_fib=io.read(1472)
            rest=io.read
        }
        raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == unmodified_file
        fib=WordStructures::WordFIB.new(raw_fib)
        # Open the file, get a copy of the table stream
        ole=Ole::Storage.open('c:\bunk\foo.doc','rb')
        table_stream=ole.file.read("1Table")
        ole.close
        fib.groups[:ol].each {|fc,lcb|
            100.times do
                gJunk=Mutations.create_string_generator(Array((0..255)).map {|e| "" << e},50000)
                while gJunk.next?
                    # Append random junk to the end of the stream
                    fuzzed_table=table_stream + gJunk.next
                    # open the new file and insert the modified table stream
                    Ole::Storage.open('c:\bunk\tmp.doc','rb+') {|ole|
                        ole.file.open("1Table","wb+") {|f| f.write( fuzzed_table )}
                    }
                    # Read in the new file contents
                    File.open( 'c:\bunk\tmp.doc',"rb") {|io| 
                        header=io.read(512)
                        raw_fib=io.read(1472)
                        rest=io.read
                    }
                    newfib=WordStructures::WordFIB.new(raw_fib)
                    # point the fc to the start of the junk
                    newfib.send((fc.to_s+'=').to_sym, table_stream.length)
                    # set the lcb to the size of the junk
                    newfib.send((lcb.to_s+'=').to_sym, fuzzed_table.length-table_stream.length)
                    # and add it to the queue.
                    prod_queue << (header+newfib.to_s+rest)
                end
            end
        }
        prod_queue.finish
        Thread.current.exit	
    rescue
        puts "Production failed: #{$!}";$stdout.flush
        exit
    end
end

module FuzzServer

    def initialize(prod_queue, rt, config)
        @config=config
        @production_queue=prod_queue
        @template=@production_queue.template
        @result_tracker=rt
        @handler=NetStringTokenizer.new
        EM.add_periodic_timer(30) {@result_tracker.spit_results}
        at_exit {@result_tracker.spit_results}
    end


    def handle_client_result(msg)
        result_id,result_status=msg.data.split(':')
        begin
            @result_tracker.add_result(Integer(result_id),result_status)
        rescue
            sleep 1
            @result_tracker.add_result(Integer(result_id),result_status)
        end
    end

    def handle_client_ready
        if @production_queue.empty? and @production_queue.finished?
            send_data(@handler.pack(FuzzMessage.new({:verb=>"SERVER FINISHED"}).to_yaml))
        else
            unless @config["USE THREADPOOL"]
                my_data=@production_queue.pop
                id=@result_tracker.check_out
                if @config["SEND DIFFS"]
                    diffs=Diff::LCS.diff(@template,my_data)
                    send_data @handler.pack(FuzzMessage.new({:verb=>"DELIVER",:data=>diffs,:id=>id}).to_yaml)
                else
                    send_data @handler.pack(FuzzMessage.new({:verb=>"DELIVER",:data=>my_data,:id=>id}).to_yaml)
                end
            else
                # define a block to prepare the response
                get_data=proc do
                    # This pop will block until data is available
                    # but since we are using EM.defer that's OK
                    my_data=@production_queue.pop
                    id=@result_tracker.check_out
                    # This is what will be passed to the callback
                    if @config["SEND DIFFS"]
                        diffs=Diff::LCS.diff(@template,my_data)
                        @handler.pack(FuzzMessage.new({:verb=>"DELIVER",:data=>diffs,:id=>id}).to_yaml)
                    else
                        @handler.pack(FuzzMessage.new({:verb=>"DELIVER",:data=>my_data,:id=>id}).to_yaml)
                    end
                end
                # This callback will be invoked once the response is ready.
                callback=proc do |data|
                    send_data data
                end
                # Send the work to the thread queue, so we are ready for more connections.
                EM.defer(get_data, callback)
            end
        end
    end

    def handle_client_startup
        send_data @handler.pack(FuzzMessage.new({:verb=>"TEMPLATE",:data=>@template}).to_yaml)
        @result_tracker.add_client
    end

    def handle_client_shutdown
        @result_tracker.remove_client
        if @production_queue.empty? and @production_queue.finished? and @result_tracker.clients <=0
            puts "All done, shutting down."
            EventMachine::stop_event_loop
        end
    end

    def receive_data(data)
        @handler.parse(data).each do |m| 
            msg=FuzzMessage.new(m)
            case msg.verb
            when "CLIENT RESULT"
                handle_client_result(msg)
            when "CLIENT READY"
                handle_client_ready
            when "CLIENT STARTUP"
                handle_client_startup
            when "CLIENT SHUTDOWN"
                handle_client_shutdown
            else
                #unknown command, real programmer would error handle.
                nil
            end
        end
    end

end

rt=ResultTracker.new

EventMachine::run {
    EventMachine::start_server(config["SERVER IP"], config["SERVER PORT"], FuzzServer, prod_queue, rt, config)
}
