	require 'win32/process'
	require 'win32ole'
	require 'fileutils'
	
	word_instances=Hash.new(0)
	begin
		wmi = WIN32OLE.connect("winmgmts://")
		loop do
			processes = wmi.ExecQuery("select * from win32_process")
			processes.each {|p|
				if p.Name=="WINWORD.EXE" or p.Name=="DW20.EXE" #or p.Name=="WerFault.exe"
					if word_instances[p.ProcessId] > 1
						print "[!#{p.ProcessId}!]";$stdout.flush
						begin
							Process.kill(1, p.ProcessId)
						rescue
							puts $!
							puts p.Name
							exit
						end
						word_instances.delete(p.ProcessId)
					else
						word_instances[p.ProcessId]+=1
					end
				end
			}
			Dir.glob("*mp*.doc", File::FNM_DOTMATCH).each {|fn| 
				begin
					FileUtils.rm_f(fn)
				rescue
					next # probably still open
				end
				print "@";$stdout.flush
			}
			print '*';$stdout.flush
			sleep(5)
		end
	rescue
		retry
	end
