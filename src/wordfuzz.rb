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

=begin
production=Thread.new do
  begin
	header,raw_fib,rest=""
	File.open( 'c:\bunk\boof.doc',"rb") {|io| 
	  header=io.read(512)
	  raw_fib=io.read(1472)
	  rest=io.read
	}
	raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == unmodified_file
	fib=WordFIB.new(raw_fib)
	fuzzer=Fuzzer.new(fib)
	fuzzer.preserve_length=true
	fuzzer.basic_tests("corner",0,false) {|fuzzed|
	  queue_mutex.synchronize{
		send_queue << (header+fuzzed.to_s+rest)
	  }
	}
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
		header,raw_fib,rest=""
		File.open( 'c:\share\boof.doc',"rb") {|io| 
			header=io.read(512)
			raw_fib=io.read(1472)
			rest=io.read
		}
		raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == unmodified_file
		g=Generators::RollingCorrupt.new(raw_fib,16,8)
		500.times do
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
=begin
idle_word_pruner=Thread.new do
  word_instances=Hash.new(0)
  begin
	wmi = WIN32OLE.connect("winmgmts://")
	loop do
	  processes = wmi.ExecQuery("select * from win32_process")
	  processes.each {|p|
		if p.Name=="WINWORD.EXE"
		  if word_instances[p.ProcessId] > 1
			print "[!#{p.ProcessId}!]";$stdout.flush
			Process.kill(1, p.ProcessId)
			word_instances.delete(p.ProcessId)
		  else
			word_instances[p.ProcessId]+=1
		  end
		end
	  }
	  print '*';$stdout.flush
	  sleep(30)
	end
  rescue
	raise RuntimeError, "Monitor Thread died: #{$!}"
  end
end
=end
1.times do
	Thread.new do
		begin
			loop do
				begin
					data=nil
					loop do
						queue_mutex.synchronize {
							data=send_queue.pop unless send_queue.empty?
						}
						if data
							break
						else
							sleep(rand(5))
						end
					end
					Thread.current[:conn]=Connector.new(CONN_OFFICE, 'word')
					Thread.current[:data]=data
					sent+=1
					Thread.current[:conn].deliver data
					unless Thread.current[:conn].connected?
						print "[1-#{sent}-1]";$stdout.flush
						File.open("1crash"+self.object_id.to_s+'-'+sent.to_s+".doc", "wb+") {|io| io.write(Thread.current[:data])}
						Thread.current[:conn]=nil
					end
					print(".");$stdout.flush
					if sent%100==0
						GC.start
						print "<#{sent}>";$stdout.flush
					end
				rescue 
					if $!.message =~ /Crash!!/m
						print "[2-#{sent}-2]";$stdout.flush
						File.open("2crash"+self.object_id.to_s+'-'+sent.to_s+".doc", "wb+") {|io| io.write(Thread.current[:data])}
					else
						print "#";$stdout.flush
					end
					if sent%100==0
						GC.start
						print "<#{sent}>";$stdout.flush
					end
					Thread.current[:conn].close if Thread.current[:conn]
					Thread.current[:conn]=nil
					retry
				ensure
					Thread.current[:conn].close if Thread.current[:conn]
					Thread.current[:conn]=nil
				end
			end
		rescue
			print "[3-#{sent}-3]";$stdout.flush
			#File.open("3crash"+self.object_id.to_s+'-'+sent.to_s+".doc", "wb+") {|io| io.write(Thread.current[:data])}
			Thread.current[:conn].close if Thread.current[:conn]
			Thread.current[:conn]=nil
			retry
		end
	end
end
at_exit {puts "Exiting... #{sent}"}
sleep(1) until production_finished and send_queue.empty?

print "\n"
puts "Sent #{sent} tests in #{"%2.2f" % (Time.now - start)} seconds. Bye."
