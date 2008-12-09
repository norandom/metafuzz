require 'windows_manipulation'
require 'Win32API'

BMCLICK=0x00F5
WM_DESTROY=0x0010

def kill_dialog_boxes
    closeHandle = Win32API.new("kernel32", "CloseHandle", ['L'],'I')
    wm=WindowOperations.new
    my_result=wm.do_enum_windows {|k,v| v[:classname] =~ /OpusApp/}
    my_result.each {|word_hwnd,child|
        children=wm.do_enum_windows {|k,v| v[:parent_window]==word_hwnd}
        child[:children]=children
        close_handle.call word_hwnd
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
                close_handle.call k
            }
        end
    }
    my_result=nil
    wm=nil
end


loop do 
    begin
        kill_dialog_boxes
    rescue 
        puts "Wordslayer: DK: #{$!}"
    end
    sleep(0.5)
end
