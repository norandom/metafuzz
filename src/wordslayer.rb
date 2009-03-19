require 'rubygems'
require 'win32/process'
require 'win32ole'
require 'fileutils'


def get_process_array(wmi)
    processes=wmi.ExecQuery("select * from win32_process where name='WINWORD.EXE' or name='DW20.EXE'")
    ary=[]
    processes.each {|p|
        ary << p.ProcessId
    }
    processes=nil
    ary
end

def delete_temp_files
        patterns=['B:/Temp/**/*.*', 'B:/Temporary Internet Files/**/*.*', 'B:/fuzzclient/~$*.doc']
        patterns.each {|pattern|
        Dir.glob(pattern, File::FNM_DOTMATCH).each {|fn|
            next if File.directory?(fn)
            begin
                FileUtils.rm_f(fn)
            rescue
                next # probably still open
            end
            print "@";$stdout.flush
        }
        }
end

word_instances=Hash.new(0)
wmi = WIN32OLE.connect("winmgmts://")
FileUtils.mkdir_p 'B:/Temp'
begin
    loop do
        procs=get_process_array(wmi)
        word_instances.delete_if {|pid,kill_level| not procs.include?(pid)}
        procs.each {|p| word_instances[p]+=1}
        word_instances.each {|pid,kill_level|
            if kill_level > 1 # seen before, try and kill
                Process.kill(9,pid)
                print "<#{pid}>";$stdout.flush
                word_instances[pid]=9
            end
        }
        print '*';$stdout.flush
        sleep(10)
        delete_temp_files
    end
rescue
    puts "Wordslayer: PK: #{$!}"
    sleep(5)
    retry
end
