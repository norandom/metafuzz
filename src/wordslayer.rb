require 'win32/process'
require 'win32ole'
require 'fileutils'
require 'windows_manipulation'
require 'pp'

BMCLICK=0x00F5
WM_DESTROY=0x0010

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

    [tempfiles].each {|pattern|
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

def kill_dialog_boxes(wm)

    my_result=wm.do_enum_windows {|k,v| v[:classname] =~ /OpusApp/}
    my_result.each {|word_hwnd,child|
        children=wm.do_enum_windows {|k,v| v[:parent_window]==word_hwnd}
        child[:children]=children
    }
    # my_result is now Word windows with their toplevel children
    my_result.each {|k,v|
        if v[:children]
            v[:children].each {|k,v|
                if v[:classname]=~/bosa_sdm/
                    wm.send_window_message(k, WM_DESTROY)
                end
                if v[:classname]=~/32770/
                    wm.switch_to_window(k)
                    wm.do_child_windows(k) {|k,v| v[:classname]=="Button" and (v[:caption]=="OK" or v[:caption]=="&No")}.each {|k,v|
                        wm.send_window_message(k, BMCLICK)
                    }
                end
            }
        end
    }
end

dialog_killer=Thread.new do
    wm=WindowOperations.new
    loop do 
        begin
            kill_dialog_boxes(wm)
        rescue 
            puts "Wordslayer: DK: #{$!}"
        end
        sleep(0.5)
    end
end


word_instances=Hash.new(0)
begin
    wmi = WIN32OLE.connect("winmgmts://")
    loop do
        procs=wmi.ExecQuery("select * from win32_process where name='WINWORD.EXE'")
        procs.each {|p|
            if p.WorkingSetSize.to_i > 100*1024*1024 # 100MB
                Process.kill(9, p.ProcessId)
            end
        }
        print '*';$stdout.flush
        sleep(5)
        delete_temp_files
    end
rescue
    puts "Wordslayer: PK: #{$!}"
    sleep(5)
    retry
end
