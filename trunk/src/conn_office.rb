require 'win32ole'
require 'fileutils'
require 'Win32API'
require 'win32/process'
#Send data to an Office application via file, used for file fuzzing.
#
#Parameters: Application Name (string) [word,excel,powerpoint etc], Temp File Directory (String).
#The general process should be for the connector to store any string it is passed for the write in a
#file of the correct type, and then open the file in the application.
module CONN_OFFICE

    #These methods will override the stubs present in the Connector
    #class, and implement the protocol specific functionality for 
    #these generic functions.
    #
    #Arguments required to set up the connection are stored in the
    #Connector instance variable @module_args.
    #
    #Errors should be handled at the Module level (ie here), since Connector
    #just assumes everything is going to plan.

    #Open the application via OLE
    def pid_from_app(win32ole_app)
        # This approach is straight from MS docs, but it's a horrible hack. Set the window title
        # so we can tell it apart from any other Word instances, find the hWND, then use that
        # to find the PID. Will collide if another window has the same random number.
        window_caption=rand(2**32).to_s
        win32ole_app.caption=window_caption
        fw=Win32API.new("user32.dll", "FindWindow", 'PP','N')
        gwtpid=Win32API.new("user32.dll", "GetWindowThreadProcessId",'LP','L')
        pid=[0].pack('L') #will be filled in, because it's passed as a pointer
        wid=fw.call(0,window_caption)
        gwtpid.call(wid,pid)
        pid=pid.unpack('L')[0]
        [pid,wid]
    end
    private :pid_from_app
    attr_reader :pid,:wid

    #Open the application via OLE	
    def establish_connection
        @appname = @module_args[0]
        begin
            @app=WIN32OLE.new(@appname+'.Application')
            #@app.visible=true
            @pid,@wid=pid_from_app(@app)
            @app.DisplayAlerts=0
            @get_window=Win32API.new("user32.dll","GetWindow",'LI','I')
        rescue
            close
            raise RuntimeError, "CONN_OFFICE: establish: couldn't open application. (#{$!})"
        end
    end

    # It would be lovely if this could check for dialogs or subwindows
    # that need acknowledgement...
    def blocking_read
        ''
    end

    #Write a string to a file and open it in the application
    def blocking_write( filename )
        raise RuntimeError, "CONN_OFFICE: blocking_write: Not connected!" unless is_connected?
        begin
            # this call blocks, so if it opens a dialog box immediately we lose control of the app. 
            # This is the biggest issue, and so far can only be solved with a separate monitor app
            # that kills word processes that are hanging here.
            @app.Documents.Open({"FileName"=>filename,"AddToRecentFiles"=>false,"OpenAndRepair"=>false})
        rescue
            raise RuntimeError, "CONN_OFFICE: blocking_write: Couldn't write to application! (#{$!})"
        end
    end

    #Return a boolen.
    def is_connected?
        begin
            @app.visible # any OLE call will fail if the app has died
            return true  
        rescue
            return false
        end		
    end

    def dialog_boxes
      begin
        result=@get_window.call(@wid,6)!=0
        rescue
        raise
        end
    end

    def destroy_connection
        begin
            sleep(0.1) while dialog_boxes
            begin
                @app.Quit if @app
            rescue
                unless Process.kill(1,@pid).include?(@pid)
                    loop until Process.kill(9,@pid).include(@pid)
                end
            end
            @app.ole_free rescue nil
        ensure
            @app=nil
        end
    end

end
