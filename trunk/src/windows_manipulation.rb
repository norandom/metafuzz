require 'pp'
module WindowOperations

require 'dl'

BMCLICK=0x00F5
WM_DESTROY=0x0010
User32=DL.dlopen("user32")

def do_child_windows(hwnd)
  #This doesn't do what I expect, in that if you call enum_windows and look for windows that
  # have parent x, the results are different to calling enum_child_windows(hwnd(x))
  
buf=' '*32 # class names are limited to 32 characters, for some reason.
enum_windows = User32['EnumWindows', 'IPL']
get_class_name = User32['GetClassName', 'ILpI']
get_caption_length = User32['GetWindowTextLengthA' ,'LI' ]
get_caption = User32['GetWindowTextA', 'iLsL' ]
get_parent_window=User32['GetParent','II']
enum_child_windows = User32['EnumChildWindows' , 'IIPL' ]
post_message = User32['PostMessage', 'ILILL']
switch_to_window = User32['SwitchToThisWindow' , 'pLI'  ]
  results={}
  enum_child_windows_proc = DL.callback('ILL') {|hwnd,lparam|
      r,rs = get_class_name.call(hwnd, buf, buf.size)
      classname=rs[1].to_s
      textLength, a = get_caption_length.call(hwnd)
      captionBuffer = " " * (textLength+1)
      t , textCaption  = get_caption.call(hwnd, captionBuffer  , textLength+1)    
      caption=String(textCaption[1].to_s)
      results[hwnd]=[classname,caption]
      -1
  }
  r=enum_child_windows.call(hwnd, enum_child_windows_proc,0)
  DL.remove_callback(enum_child_windows_proc)
  results.each {|k,v|
    v << do_child_windows(k)
    }
  results
end

def do_enum_windows(condition)
  # this is hackish, but I'm in a hurry. Expects some ruby code as a string which
  # will be eval'ed in local context below. :(
results={}
buf=' '*32 # class names are limited to 32 bytes
enum_windows = User32['EnumWindows', 'IPL']
get_class_name = User32['GetClassName', 'ILpI']
get_caption_length = User32['GetWindowTextLengthA' ,'LI' ]
get_caption = User32['GetWindowTextA', 'iLsL' ]
get_parent_window=User32['GetParent','II']
enum_child_windows = User32['EnumChildWindows' , 'IIPL' ]
switch_to_window = User32['SwitchToThisWindow' , 'pLI'  ]
  enum_windows_proc = DL.callback('ILL') {|hwnd,lparam|
      r,rs = get_class_name.call(hwnd, buf, buf.size)
      classname=rs[1].to_s
      textLength, a = get_caption_length.call(hwnd)
      captionBuffer = " " * (textLength+1) # allow for null termination
      t , textCaption  = get_caption.call(hwnd, captionBuffer  , captionBuffer.length)    
      caption=textCaption[1].to_s
      parentwindow,unknown_var=get_parent_window.call(hwnd)
      results[hwnd]=[parentwindow,classname,caption] if eval(condition)
      -1 # -1 says keep going. Forget which constant it is.
  }
  r,rs=enum_windows.call(enum_windows_proc,0)
  DL.remove_callback(enum_windows_proc)
  results
end

def send_window_message(hwnd, message)
  post_message = User32['PostMessage', 'ILILL']
  r,rs=post_message.call(hwnd,message,0,0)
end

end #module WindowOperations

include WindowOperations

my_result=WindowOperations::do_enum_windows('classname=~/OpusApp/')
my_result.each {|k,v|
  children=WindowOperations::do_enum_windows("parentwindow==#{k}")
  v << children
  }
  pp my_result

my_result.each {|k,v|
    v[3].each {|k,v|
      if v[1]=~/32770/
        children=WindowOperations::do_child_windows(k)
        p children
      end
      }
  }




