require 'windows_popen'
require 'win32ole'
CDB_PATH="\"C:\\Program Files\\Debugging Tools for Windows (x86)\\cdb.exe\" "
require 'objhax'

#Establish a connection to the Windows CDB debugger. CDB has all the features of WinDbg, but it uses
#a simple command line interface.
#
#Parameters: For now, the full command line EXCLUDING the path to cdb itself as a string. 
#Sugar may follow later. Remember that program names that include spaces need to be 
#enclosed in quotes \"c:\\Program Files [...] \" etc.
module CONN_CDB

    #These methods will override the stubs present in the Connector
    #class, and implement the protocol specific functionality for 
    #these generic functions.
    #
    #Arguments required to set up the connection are stored in the
    #Connector instance variable @module_args.
    #
    #Errors should be handled at the Module level (ie here), since Connector
    #just assumes everything is going to plan.

    def get_process_array
        wmi= WIN32OLE.connect("winmgmts://")
        processes=wmi.ExecQuery("select * from win32_process")
        ary=[]
        processes.each {|p|
            ary << p.ProcessId
        }
        ary
    end


    #Set up a new socket.
    def establish_connection
        @command_line=@module_args[0]
        @generate_ctrl_event = Win32API.new("kernel32", "GenerateConsoleCtrlEvent", ['I','I'], 'I')
        begin
            @debugger=WindowsPipe.popen(CDB_PATH+@command_line)
            @child_pid=@debugger.pid
        rescue
            #do something
        end

    end

    #Blocking read from the socket.
    def blocking_read
        @debugger.read
    end

    #Blocking write to the socket.
    def blocking_write( data )
        @debugger.write data
    end

    #Return a boolen.
    def is_connected?
        # The process is alive - is that the same as connected?
        get_process_array.include? @child_pid
    end

    #Cleanly destroy the socket. 
    def destroy_connection
        if is_connected?
            @generate_ctrl_event.call(1,@child_pid) # send a ctrl-break, in case the debugee is running          
            @debugger.write("q\n") 
        end
    end
    
    # Sugar from here on.

    #Our popen object isn't actually an IO obj, so it only has read and write.
    def puts( str )
        @debugger.write str+"\n"
    end

    def send_break
        @generate_ctrl_event.call(1,@child_pid)
    end

    def registers
        sr "r\n"
        regstring=''
        # Potential infinite loop here :(
        sleep 0.1 until (regstring<<dq_all.join).index('eax=')
        #regstring=dq_all.join
        regstring=regstring[regstring.index('eax=')..-1].gsub!("\n",' ') 
        reghash={}
        regstring.split(' ').each {|tok|
            if tok.split('=').length==2
                reghash[tok.split('=')[0].to_sym]=tok.split('=')[1]
            end
        }
        # This is a bit glitzy, but it's fun. Add a singleton method to the return
        # hash for each register, so the caller can treat the registers as a hash
        # or do debugger.registers.eax etc.
        reghash.each {|k,v|
            reghash.meta_def k do v end
        }
        reghash
    end

end # module CONN_CDB

