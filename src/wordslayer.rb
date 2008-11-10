require 'win32/process'
require 'win32ole'
require 'fileutils'


def get_process_array(wmi)
    processes=wmi.ExecQuery("select * from win32_process where name='WINWORD.EXE' or name='DW20.EXE'")
    ary=[]
    processes.each {|p|
        ary << p.ProcessId
    }
    ary
end

def delete_temp_files
    Dir.glob("*mp*.doc", File::FNM_DOTMATCH).each {|fn| 
        begin
            FileUtils.rm_f(fn)
        rescue
            next # probably still open
        end
        print "@";$stdout.flush
    }
end

word_instances=Hash.new(0)
begin
    wmi = WIN32OLE.connect("winmgmts://")
    loop do
        procs=get_process_array(wmi)
        word_instances.delete_if {|pid,kill_level| not procs.include?(pid)}
        procs.each {|p| word_instances[p]+=1}
        word_instances.each {|pid,kill_level|
            if kill_level > 8
                Process.kill(9,pid)
                print "<!#{pid}!>";$stdout.flush
            elsif kill_level > 1 # seen before, try and kill
                Process.kill(1,pid)
                print "<#{pid}>";$stdout.flush
                word_instances[pid]=9
            end
        }
        delete_temp_files
        print '*';$stdout.flush
        sleep(5)
    end
rescue
    puts $!
    sleep(5)
    retry
end
