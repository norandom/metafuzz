require 'dl'

BMCLICK=0x00F5
User32 = DL.dlopen("user32")
enum_windows = User32['EnumWindows', 'IPL']
post_message = User32['PostMessage', 'ILILL']
get_class_name = User32['GetClassName', 'ILpI']
get_caption_length = User32['GetWindowTextLengthA' ,'LI' ]
get_caption = User32['GetWindowTextA', 'iLsL' ]
get_parent_window=User32['GetParent','II']
enum_child_windows = User32['EnumChildWindows' , 'IIPL' ]
post_message = User32['PostMessage', 'ILILL']
switch_to_window = User32['SwitchToThisWindow' , 'pLI'  ]

buf=' '*32
alert={}
enum_child_windows_proc = DL.callback('ILL') {|hwnd,lparam|
    r,rs = get_class_name.call(hwnd, buf, buf.size)
    classname=rs[1].to_s
    textLength, a = get_caption_length.call(hwnd)
    captionBuffer = " " * (textLength+1)
    t , textCaption  = get_caption.call(hwnd, captionBuffer  , textLength+1)    
    caption=String(textCaption[1].to_s)
    puts "\t#{hwnd} : #{classname} --> #{caption.inspect}"
    alert[hwnd]=[classname,caption]
    -1
}

enum_windows_proc = DL.callback('ILL') {|hwnd,lparam|
    r,rs = get_class_name.call(hwnd, buf, buf.size)
    classname=rs[1].to_s
    textLength, a = get_caption_length.call(hwnd)
    captionBuffer = " " * (textLength+1)
    t , textCaption  = get_caption.call(hwnd, captionBuffer  , textLength+1)    
    caption=textCaption[1].to_s
    parent_hwnd,b=get_parent_window.call(hwnd)       
    r,rs = get_class_name.call(parent_hwnd, buf, buf.size)
    parent_classname=rs[1].to_s
    if classname=~/32770/ and parent_classname=~/OpusApp/
        puts "Alert: #{hwnd} : #{classname} --> #{caption}" 
        r=enum_child_windows.call(hwnd, enum_child_windows_proc,0)
        p alert
        alert.each {|k,v|
            puts "#{k} : #{v[0]}"
            if v[0]=="Button" and v[1]=="OK"
                puts "Got button #{k}, trying to click..."
                switch_to_window.call(k,1)
                r,rs = post_message.call(k, BMCLICK, 0, 0)
                puts "#{r.inspect}, #{rs.inspect}"
            end
        }
        alert={}
    end
    -1
}
r,rs = enum_windows.call(enum_windows_proc, 0)
#r,rs = enum_child_windows.call(2492548, enum_child_windows_proc,0)
DL.remove_callback(enum_windows_proc)
DL.remove_callback(enum_child_windows_proc)

