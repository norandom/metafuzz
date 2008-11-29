require 'rubygems'
require 'win32/registry'
require 'win32/process'
require 'systemu'
require 'digest/md5'
require 'windows_popen'
require 'win32ole'

WORD_PATH="c:\\program files\\microsoft office\\office12"
CDB_PATH="C:\\Program Files\\Debugging Tools for Windows (x86)"
CRASHFILE_PATH='C:/fuzzclient'

gce = Win32API.new("kernel32", "GenerateConsoleCtrlEvent", ['I','I'], 'I')

def get_process_array
    wmi= WIN32OLE.connect("winmgmts://")
    processes=wmi.ExecQuery("select * from win32_process where name='notepad.exe'")
    ary=[]
    processes.each {|p|
        ary << p.ProcessId
    }
    ary
end
# Connect to cdb with systemu
commandline="\"#{CDB_PATH}\\cdb -xi ld -snul \"#{WORD_PATH}\\WINWORD.EXE\""
io = WindowsPipe.popen("\"#{CDB_PATH}\\cdb.exe\" -xi ld -snul NOTEPAD.EXE")
p io
Thread.new do
    while !(buffer = io.read).empty? 
        print buffer.gsub("\r", '') 
    end 
end
io.write("r\n")
sleep(5)
io.write("g\n")
p io.pid
io.write("r\n")
sleep 2
begin
    get_process_array.each {|cdbpid|
    puts "trying to send -3 to #{cdbpid}"
        Process.kill(2,cdbpid)
    }
rescue
    puts $!
end
gce.call(1,io.pid)
io.write(".echo W0000000000000000000t\n")
sleep(5)
