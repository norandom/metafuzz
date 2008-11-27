require 'rubygems'
require 'win32/registry'
require 'systemu'
require 'digest/md5'
require 'windows_popen'

WORD_PATH="c:\\program files\\microsoft office\\office12"
CDB_PATH="C:\\Program Files\\Debugging Tools for Windows (x86)"
CRASHFILE_PATH='C:/fuzzclient'

    # Connect to cdb with systemu
    commandline="\"#{CDB_PATH}\\cdb -xi ld -snul \"#{WORD_PATH}\\WINWORD.EXE\""
    io = WindowsPipe.popen("\"#{CDB_PATH}\\cdb.exe\" -xi ld -snul -p ")
    p io
    Thread.new do
    while !(buffer = io.read).empty? 
        print buffer.gsub("\r", '') 
    end 
    end
    io.write("r\n")
    sleep(5)
    io.write("q\n")
    sleep 10
