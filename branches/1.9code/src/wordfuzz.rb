require 'fuzzer'
require 'connector'
require 'conn_office'
require 'fib'
require 'win32/process'
require 'thread'

send_queue=Queue.new
queue_mutex=Mutex.new
production_finished=false
sent=0
start=Time.now
unmodified_file=File.open( 'c:\share\boof.doc',"rb") {|io| io.read}
work_dir='c:/fuzzclient'
=begin
production=Thread.new do
    begin
        header,raw_fib,rest=""
        File.open( 'c:\share\boof.doc',"rb") {|io| 
            header=io.read(512)
            raw_fib=io.read(1472)
            rest=io.read
        }
        raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == unmodified_file
        fib=WordFIB.new(raw_fib)
        fib.fcSttbfffn=0
        1024.times do
            fib.fcSttbfffn+=2048
            fuzzed=fib.to_s
            queue_mutex.synchronize{
                send_queue << (header+fuzzed.to_s+rest)
            }
            fuzzed=nil
        end
        production_finished=true
        Thread.current.exit
    rescue
        puts "Production failed: #{$!}";$stdout.flush
        exit
    end
end
=end
=begin
production=Thread.new do
    begin
        header,raw_fib,rest=""
        File.open( 'c:\share\boof.doc',"rb") {|io| 
            header=io.read(512)
            raw_fib=io.read(1472)
            rest=io.read
        }
        raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == unmodified_file
        g=Generators::RollingCorrupt.new(raw_fib,16,8)
        2200.times do
            g.next
        end
        while g.next?
            toobig=false
            fuzzed=g.next
            raise RuntimeError, "Data Corruption" unless fuzzed.length==raw_fib.length
            queue_mutex.synchronize{
                send_queue << (header+fuzzed+rest)
                toobig=true if send_queue.length > 50
            }
            sleep(5) if toobig
        end
        production_finished=true
        Thread.current.exit	
    rescue
        puts "Production failed: #{$!}";$stdout.flush
        exit
    end
end
=end

production=Thread.new do
    begin
        header,target,rest=""
        File.open( 'c:\share\boof.doc',"rb") {|io| 
            header=io.read(40224)
            target=io.read(160)
            rest=io.read
        }
        raise RuntimeError, "Data Corruption" unless header+target+rest == unmodified_file
        g=Generators::RollingCorrupt.new(target,32,8)
        while g.next?
            toobig=false
            fuzzed=g.next
            raise RuntimeError, "Data Corruption" unless fuzzed.length==target.length
            queue_mutex.synchronize{
                send_queue << (header+fuzzed+rest)
                toobig=true if send_queue.length > 50
            }
            sleep(5) if toobig
        end
        production_finished=true
        Thread.current.exit	
    rescue
        puts "Production failed: #{$!}";$stdout.flush
        exit
    end
end

begin
    loop do
        begin
            data=nil
            loop do
                queue_mutex.synchronize {
                    data=send_queue.pop unless send_queue.empty?
                }
                break if data
                sleep(rand(5))
            end
            @data=data
            loop do
                @conn=Connector.new(CONN_OFFICE, 'word', work_dir)
                break if @conn.connected?
                @conn=nil
                sleep(rand(5))
            end
            sent+=1
            @conn.deliver data
            unless @conn.connected?
                print "[1-#{sent}-1]";$stdout.flush
                File.open("1crash"+self.object_id.to_s+'-'+sent.to_s+".doc", "wb+") {|io| io.write(@data)}
                @conn=nil
            end
            print(".");$stdout.flush
            if sent%100==0
                GC.start
                print "<#{sent}>";$stdout.flush
            end
            @conn.close if @conn
            @conn=nil
        rescue 
            if $!.message =~ /CRASH/m # a process id that went away
                print "<#{$!.message}>";$stdout.flush
                File.open(File.join(work_dir,"2crash"+self.object_id.to_s+'-'+sent.to_s+".doc"), "wb+") {|io| io.write(@data)}
            else
                print "#";$stdout.flush
            end
            if sent%100==0
                GC.start
                print "<#{sent}>";$stdout.flush
            end
            @conn.close if @conn
            @conn=nil
            retry
        end
    end
rescue
    print "[3-#{sent}-3]";$stdout.flush
    File.open("1crash"+self.object_id.to_s+'-'+sent.to_s+".doc", "wb+") {|io| io.write(@data)}
    @conn.close if @conn
    @conn=nil
    retry
end
at_exit {puts "Exiting... #{sent}";puts $!}
sleep(1) until production_finished and send_queue.empty?

print "\n"
puts "Sent #{sent} tests in #{"%2.2f" % (Time.now - start)} seconds. Bye."
