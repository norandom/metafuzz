require 'win32/process'
require 'win32ole'
require 'fileutils'
require 'windows_manipulation'
require 'pp'

def get_process_array(wmi)
    processes=wmi.ExecQuery("select * from win32_process where name='WINWORD.EXE' or name='DW20.EXE'")
    ary=[]
    processes.each {|p|
        ary << p.ProcessId
    }
    ary
end

def delete_temp_files
    tempfiles='C:/Documents and Settings/Administrator/Local Settings/Temporary Internet Files/Content.Word/*WR*.tmp'
    fuzzfiles='C:/fuzzclient/*mp*.doc'

    [tempfiles,fuzzfiles].each {|pattern|
        Dir.glob(pattern, File::FNM_DOTMATCH).each {|fn| 
            begin
                FileUtils.rm_f(fn)
            rescue
                next # probably still open
            end
            print "@";$stdout.flush
        }
    }
end

def kill_dialog_boxes
    my_result=WindowOperations::do_enum_windows('classname=~/OpusApp/')
    my_result.each {|k,v|
        children=WindowOperations::do_enum_windows("parentwindow==#{k}")
        v << children
    }

    my_result.each {|k,v|
        v[3].each {|k,v|
            if v[1]=~/bosa_sdm/ # dialog box, like Show Repairs or password prompt for encrypted file
                # These guys don't expose their buttons as children, you just have to tell them to die.
                WindowOperations::send_window_message(k,WM_DESTROY)
            end
            if v[1]=~/32770/ # alert, like 'too big to save' or 'do you want to download a converter'
                alert_stuff=do_child_windows(k)
                switch_to_window = User32['SwitchToThisWindow' , 'pLI'  ]
                switch_to_window.call(k,1)
                alert_stuff.each {|k,v|
                    if v[0]=="Button" and (v[1]=="OK" or v[1]=="&No")
                        WindowOperations::send_window_message(k,BMCLICK)
                    end
                }
            end
        }
    }
end

dialog_killer=Thread.new do
    loop do 
        begin
            kill_dialog_boxes 
        rescue 
            puts $!
        end
        sleep(0.5)
    end
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
        puts word_instances.length
        sleep(5)
    end
rescue
    puts $!
    sleep(5)
    retry
end
