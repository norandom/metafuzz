require 'win32ole'
require 'fileutils'

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
    def establish_connection
        @appname, @path = @module_args
    @path||=File.dirname(File.expand_path(__FILE__)) # same directory as the script is running from
    @files=[]
        begin
        @app=WIN32OLE.new(@appname+'.Application')
        #@app.visible=true # for now.
        @app.DisplayAlerts=0
        rescue
            destroy_connection
            raise RuntimeError, "CONN_OFFICE: establish: couldn't open application. (#{$!})"
        end
    end

    #Can't think of a good use for this.
    def blocking_read
        ''
    end

    #Write a string to a file and open it in the application
    def blocking_write( data )
        raise RuntimeError, "CONN_OFFICE: blocking_write: Not connected!" unless is_connected?
        begin
            filename=@path + "\/temp" + Time.now.hash.to_s + self.object_id.to_s + ".doc"
            @files << filename
            File.open(filename, "wb+") {|io| io.write(data)}
            @app.Documents.Open(filename) # this call blocks...
        rescue
            if $!.message =~ /OLE error code:0 /m and not $!.message =~ /OLE error code:0 .*unavailable/m# the OLE server threw an exception, should be a genuine crash.
              puts $!;$stdout.flush
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
        @app.Documents.each {|doc| doc.close rescue nil} if is_connected? # otherwise there seems to be a file close race, and the files aren't deleted.
        @app.Quit if is_connected?
    ensure
        @app=nil #doc says ole_free gets called during garbage collection, so this should be enough
        @files.each {|fn| FileUtils.rm_f(fn)}
    end
    end

end
