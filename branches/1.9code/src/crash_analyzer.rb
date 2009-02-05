require 'rubygems'
require 'win32/registry'
require 'systemu'
require 'digest/md5'

WORD_PATH='c:/program files/microsoft office/office12'
CDB_PATH='C:/Program Files/Debugging Tools for Windows (x86)'
CRASHFILE_PATH='C:/fuzzclient'

#TODO: This method doesn't work if the file doesn't actually cause a crash.
# each file to analyze
Dir.glob("#{CRASHFILE_PATH}/crash*.doc").each {|currentfile|
    # Remove the word registry values that enable safe mode and disabled items
    Win32::Registry::HKEY_CURRENT_USER.open('SOFTWARE\Microsoft\Office\12.0\Word\Resiliency',Win32::Registry::KEY_WRITE) do |reg|
        reg.delete_key "StartupItems" rescue nil
        reg.delete_key "DisabledItems" rescue nil
    end

    # Connect to cdb with systemu
    commandline="#{CDB_PATH}/cdb -c \"q\" -G -g -xi ld -snul \"#{WORD_PATH}/WINWORD.EXE\" /q #{currentfile}"
    status,out,err=systemu commandline

    res=[]
    out.each_line {|l| res << l.chomp if l=~/^eax/ or l=~/^eip/ or l=~/^cs/}
    register_string=res.join(' ').squeeze(' ')
    hsh=Digest::MD5.hexdigest(register_string)
    begin
        unless File.directory? CRASHFILE_PATH+"/#{hsh}"
            Dir.mkdir(CRASHFILE_PATH+"/#{hsh}")
            File.open(File.join(CRASHFILE_PATH+"/#{hsh}","crashdetail.txt"), "wb+") {|io| io.write(out)}
        end
        FileUtils.mv(currentfile,CRASHFILE_PATH+"/#{hsh}")
    rescue
        sleep(5)
        retry
    end
}

