require 'Win32API'

BMCLICK=0x00F5
WM_DESTROY=0x0010
WM_COMMAND=0x111
IDOK=1
IDCANCEL=2
IDNO=7
IDCLOSE=8
GW_ENABLEDPOPUP=0x0006

FindWindow=Win32API.new("user32.dll", "FindWindow", 'PP','N')
GetWindow=Win32API.new("user32.dll", "GetWindow", 'LI','I')
PostMessage=Win32API.new("user32.dll", "PostMessage", 'LILL','I')

def kill_dialog_boxes
    word_hwnd=FindWindow.call("OpusApp",0)
    child_hwnd=GetWindow.call(word_hwnd, GW_ENABLEDPOPUP)
    unless child_hwnd==0
        PostMessage.call(child_hwnd,WM_COMMAND,IDCANCEL,0)
        PostMessage.call(child_hwnd,WM_COMMAND,IDNO,0)
        PostMessage.call(child_hwnd,WM_COMMAND,IDOK,0)
        PostMessage.call(child_hwnd,WM_COMMAND,IDCLOSE,0)
    end
end

loop do
    begin
        kill_dialog_boxes
    rescue 
        puts "Wordslayer: DK: #{$!}"
    end
    sleep(0.1)
end
