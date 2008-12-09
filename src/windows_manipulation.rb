require 'pp'
# I AM NOT THREAD SAFE!
class WindowOperations

    require 'dl'
    require 'Win32API'

    BMCLICK=0x00F5
    WM_DESTROY=0x0010
    User32=DL.dlopen("user32")

    def initialize
        @enum_windows = User32['EnumWindows', 'IPL']
        @get_class_name = User32['GetClassName', 'ILpI']
        @get_caption_length = User32['GetWindowTextLengthA' ,'LI' ]
        @get_caption = User32['GetWindowTextA', 'iLsL' ]
        @get_parent_window=User32['GetParent','II']
        @enum_child_windows = User32['EnumChildWindows' , 'IIPL' ]
        @switch_to_window = User32['SwitchToThisWindow' , 'pLI'  ]
        @closeHandle = Win32API.new("kernel32", "CloseHandle", ['L'],'I')
    end

    def switch_to_window(hwnd)
        @switch_to_window.call(hwnd,1)
    end

    def do_child_windows(hwnd, &blk)
        #This doesn't do what I expect, in that if you call enum_windows and look for windows that
        # have parent x, the results are different to calling enum_child_windows(hwnd(x))
    
        blk||=proc do true end
        results={}
        enum_child_windows_proc = DL.callback('ILL') {|hwnd,lparam|
            classname_buffer=' '*32 # limit the classname to 32 bytes
            r,rs = @get_class_name.call(hwnd, classname_buffer, classname_buffer.size)
            classname=rs[1].to_s
            textLength, a = @get_caption_length.call(hwnd)
            captionBuffer = " " * (textLength+1)
            t , textCaption  = @get_caption.call(hwnd, captionBuffer  , textLength+1)    
            caption=String(textCaption[1].to_s)
            results[hwnd]={:classname=>classname,:caption=>caption}
            r,rs,a,t,textCaption=nil
            @closeHandle.call hwnd
            -1
        }
        r=@enum_child_windows.call(hwnd, enum_child_windows_proc,0)
        DL.remove_callback(enum_child_windows_proc)
        results.each {|k,v|
            children=do_child_windows(k, &blk)
            v[:children]=children unless children.empty?
        }
        results.each {|handle,val|
          unless blk.call(handle,val)
            @closeHandle.call handle
          end
          }
        results.select &blk
    end

    def do_enum_windows(&blk)
        blk||=proc do true end
        results={}
        enum_windows_proc = DL.callback('ILL') {|hwnd,lparam|
            classname_buffer=' '*32 # limit the classname to 32 bytes
            r,rs = @get_class_name.call(hwnd, classname_buffer, classname_buffer.size)
            classname=rs[1].to_s
            textLength, a = @get_caption_length.call(hwnd)
            captionBuffer = " " * (textLength+1) # allow for null termination
            t , textCaption  = @get_caption.call(hwnd, captionBuffer, captionBuffer.length)    
            caption=textCaption[1].to_s
            parentwindow,unknown_var=@get_parent_window.call(hwnd)
            results[hwnd]={:parent_window=>parentwindow,:classname=>classname,:caption=>caption}
            r,rs,a,t,textCaption,parentwindow,unknown_var=nil
            @closeHandle.call hwnd
            -1 # -1 says keep going. Forget which constant it is.
        }
        r,rs=@enum_windows.call(enum_windows_proc,0)
        DL.remove_callback(enum_windows_proc)
        results.each {|handle,val|
          unless blk.call(handle,val)
            @closeHandle.call handle
          end
          }
        results.select &blk
    end

    def send_window_message(hwnd, message)
        post_message = User32['PostMessage', 'ILILL']
        r,rs=post_message.call(hwnd,message,0,0)
    end

end #module WindowOperations
=begin
wm=WindowOperations.new
my_result=wm.do_enum_windows {|k,v| v[:classname] =~ /OpusApp/}
my_result.each {|word_hwnd,child|
    children=wm.do_enum_windows {|k,v| v[:parent_window]==word_hwnd}
    child[:children]=children
}
pp my_result
<<<<<<< .mine
    my_result.each {|k,v|
        if v[:children]
            v[:children].each {|k,v|
                if v[:classname]=~/bosa_sdm/
                    wm.send_window_message(k, 0x0010)
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
=begin
=======
    my_result.each {|k,v|
        if v[:children]
            v[:children].each {|k,v|
                if v[:classname]=~/bosa_sdm/
                    puts "Sending kill to #{k}"
                    wm.send_window_message(k, 0x0010)
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
>>>>>>> .r66
my_result.each {|k,v|
    children=wm.do_child_windows(k)
    pp children
}
=end


