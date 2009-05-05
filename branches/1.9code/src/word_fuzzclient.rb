require 'fuzz_client'
require 'connector'
require 'conn_office'
require 'conn_cdb'
require 'win32/registry'

begin
    Win32::Registry::HKEY_CURRENT_USER.open('SOFTWARE\Microsoft\Office\12.0\Word\Resiliency',Win32::Registry::KEY_WRITE) do |reg|
        reg.delete_key "StartupItems" rescue nil
        reg.delete_key "DisabledItems" rescue nil
    end
rescue
    nil
end

# Temporary sets of commands and stuff go here. Lame, but working.
Win32::Registry::HKEY_CURRENT_USER.open('Control Panel\Desktop',Win32::Registry::KEY_WRITE)["Wallpaper"]=""
Win32::Registry::HKEY_CURRENT_USER.open('Control Panel\Desktop',Win32::Registry::KEY_WRITE)["SCRNSAVE.EXE"]=""
Win32::Registry::HKEY_CURRENT_USER.open('Environment',Win32::Registry::KEY_WRITE)["TEMP"]="R:\\Temp"
Win32::Registry::HKEY_CURRENT_USER.open('Environment',Win32::Registry::KEY_WRITE)["TMP"]="R:\\Temp"
Win32::Registry::HKEY_LOCAL_MACHINE.open('SYSTEM\CurrentControlSet\Control\Session Manager\Environment',Win32::Registry::KEY_WRITE)["TEMP"]="R:\\Temp"
Win32::Registry::HKEY_LOCAL_MACHINE.open('SYSTEM\CurrentControlSet\Control\Session Manager\Environment',Win32::Registry::KEY_WRITE)["TMP"]="R:\\Temp"

class WordFuzzClient < FuzzClient

    def prepare_test_file(data, msg_id)
        begin
            filename="test-"+msg_id.to_s+".doc"
            path=File.join(self.class.work_dir,filename)
            File.open(path, "wb+") {|io| io.write data}
            path
        rescue
            raise RuntimeError, "Fuzzclient: Couldn't create test file #{filename} : #{$!}"
        end
    end

    def clean_up( fn )
        10.times do
            begin
                FileUtils.rm_f(fn)
            rescue
                raise RuntimeError, "Fuzzclient: Failed to delete #{fn} : #{$!}"
            end
            return true unless File.exist? fn
            sleep(0.1)
        end
        return false
    end

    def deliver(data,msg_id)
        begin
            status=:error
            crash_details="" # will only be set to anything if there's a crash
            this_test_filename=prepare_test_file(data, msg_id)
            begin
                5.times do
                    begin
                        @word=Connector.new(CONN_OFFICE, 'word')
                        break
                    rescue
                        sleep(1)
                        next
                    end
                end
                current_pid=@word.pid
            rescue
                raise RuntimeError, "Couldn't establish connection to app. #{$!}"
            end
            # Attach debugger
            # -snul - don't load symbols
            # -c  - initial command
            # sxe -c "!exploitable -m;g" av - run the MS !exploitable windbg extension
            # -hd don't use the debug heap
            # -pb don't request an initial break (not used now, cause we need the break so we can read the initial command)
            # -x ignore first chance av exceptions
            # -xi ld ignore module loads
            debugger=Connector.new(CONN_CDB,"-snul -xi ld -p #{current_pid}")
			debugger.puts "!load winext\\msec.dll"
			debugger.puts "sxe -c \"!exploitable -m;g\" av"
			debugger.puts "g"
            begin
                @word.deliver this_test_filename
                status=:success
                print '.';$stdout.flush
            rescue
                # check for crashes
                sleep(0.1) # This magically seems to fix a race condition.
                if debugger.crash?
                    status=:crash
                    sleep(0.1) while debugger.target_running?
                    crash_details=debugger.dq_all.join
                    print '!';$stdout.flush
                    # If the app has crashed we should kill the debugger, otherwise
                    # the app won't be killed without -9.
                    debugger.close
                else
                    status=:fail
                    print '#';$stdout.flush
                end
            end
            # close the debugger and kill the app
            # This should kill the winword process as well
            # Clean up the connection object
            @word.close rescue nil
            debugger.close 
            clean_up(this_test_filename) 
            [status,crash_details]
        rescue
            raise RuntimeError, "Delivery: fatal: #{$!}"
            # ask the server to revert me to my snapshot?
        end
    end
end

server="192.168.242." << (101+rand(2)).to_s
if File.directory? 'R:/'
	workdir='R:/fuzzclient'
elsif File.directory? "E:/"
	workdir="E:/fuzzclient"
else
	raise RuntimeError, "WordFuzzClient: Couldn't find the ramdisk."
end
WordFuzzClient.setup('server_ip'=>server, 'work_dir'=>workdir)
puts "Modified CDB command line"

EventMachine::run {
    system("start ruby wordslayer.rb")
    system("start ruby dk.rb")
    EventMachine::connect(WordFuzzClient.server_ip,WordFuzzClient.server_port, WordFuzzClient)
}
puts "Event loop stopped. Shutting down."
