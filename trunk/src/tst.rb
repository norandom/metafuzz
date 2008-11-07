require 'win32ole'
require 'win32/process'


Thread.new do
	word_instances=Hash.new(0)
	begin
		wmi = WIN32OLE.connect("winmgmts://")
		loop do
			processes = wmi.ExecQuery("select * from win32_process")
			processes.each {|p|
				if p.Name=="WINWORD.EXE"
					if word_instances[p.ProcessId] > 60
						puts "Killing Word: #{p.ProcessId}";$stdout.flush
						Process.kill(1, p.ProcessId)
						word_instances.delete(p.ProcessId)
					else
						word_instances[p.ProcessId]+=1
					end
				end
			}
			sleep(1)
		end
	rescue
		raise RuntimeError, "Monitor Thread died: #{$!}"
	end
end



