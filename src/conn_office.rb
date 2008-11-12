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
    end
    private :pid_from_app
    attr_reader :pid
    #Open the application via OLE	
    def establish_connection
        @appname, @path = @module_args
        @path||=File.dirname(File.expand_path(__FILE__)) # same directory as the script is running from
        @files=[]
        begin
            @app=WIN32OLE.new(@appname+'.Application')
            #@app.visible=true # for now.
            @pid=pid_from_app(@app)
            @app.DisplayAlerts=0
        rescue
            destroy_connection
            raise RuntimeError, "CONN_OFFICE: establish: couldn't open application. (#{$!})"
        end
    end

    # It would be lovely if this could check for dialogs or subwindows
    # that need acknowledgement...
    def blocking_read
        ''
    end

    #Write a string to a file and open it in the application
    def blocking_write( data )
        raise RuntimeError, "CONN_OFFICE: blocking_write: Not connected!" unless is_connected?
        begin
            filename="temp" + Time.now.hash.to_s + self.object_id.to_s + ".doc"
            @files << filename
            fso=WIN32OLE.new("Scripting.FileSystemObject")
            path=fso.GetAbsolutePathName(filename) # Sometimes paths with backslashes break things, the FSO always does things right.
            File.open(path, "wb+") {|io| io.write(data)}
            # this call blocks, so if it opens a dialog box immediately we lose control of the app. 
            # This is the biggest issue, and so far can only be solved with a separate monitor app
            # that kills word processes that are hanging here.
            @app.Documents.Open({"FileName"=>path,"AddToRecentFiles"=>false,"OpenAndRepair"=>false})
            @app.visible
        rescue
            if $!.message =~ /OLE error code:0 .*Exception/m # the OLE server threw an exception, might be a genuine crash.
                raise RuntimeError, "CONN_OFFICE: Crash!! #{$!}"
            else # Either it's an OLE "the doc was corrupt" error, or the app hung, we killed it with -1 and got RPC server unavailable.
                destroy_connection
                raise RuntimeError, "CONN_OFFICE: blocking_write: Couldn't write to application! (#{$!})"
            end
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

    #Cleanly destroy the app. 
    def destroy_connection
        begin
            @app.Documents.each {|doc| doc.close(0) rescue nil} if is_connected? # otherwise there seems to be a file close race, and the files aren't deleted.
            begin
                if is_connected?
                    @app.Quit #Sometimes this opens an alert box "You can't close because a dialog box is open..."
                end
                if is_connected? # Still connected! Lay the smack down.
                    begin
                        Process.kill(9,@pid) # kill -1 doesn't always work, dunno why.
                    rescue
                        # This could be a little neater
                        puts "CONN_OFFICE: destroy_connection failed to kill: #{$!}"
                        nil# maybe it died in the meantime?
                    end
                end
            rescue
                puts "CONN_OFFICE: destroy_connection app.Quit failed: #{$!}"
            end
        ensure
            @app=nil #doc says ole_free gets called during garbage collection, so this should be enough
            @files.each {|fn| FileUtils.rm_f(fn)}
        end
    end

end
