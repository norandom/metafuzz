
class ResultTracker

    def initialize
        @sent=0
        @prod_clients=0
        @fuzz_clients=0
        @mutex=Mutex.new
        @results={}
        @time_mark=Time.now
        @sent_mark=0
    end

    def production_clients
        Thread.critical=true
        @prod_clients
    ensure
        Thread.critical=false
    end

    def add_fuzz_client
        Thread.critical=true
        @fuzz_clients+=1
    ensure
        Thread.critical=false
    end

    def remove_fuzz_client
        Thread.critical=true
        @fuzz_clients-=1
    ensure
        Thread.critical=false
    end

    def add_production_client
        Thread.critical=true
        @prod_clients+=1
    ensure
        Thread.critical=false
    end

    def remove_production_client
        Thread.critical=true
        @prod_clients-=1
    ensure
        Thread.critical=false
    end

    def add_result(id, status)
        Thread.critical=true
        unless @results[id]==:checked_out
            raise RuntimeError, "RT: The id not checked out yet?"
        end
        @results[id]=status
    ensure
        Thread.critical=false
    end

    def check_out
        Thread.critical=true
        @sent+=1
        @results[@sent]=:checked_out
        @sent
    ensure
        Thread.critical=false
    end
    
    def results_outstanding
        Thread.critical=true
        @results.select {|k,v| v==:checked_out}.length
    ensure
        Thread.critical=false
    end

    def spit_results
        Thread.critical=true
        succeeded=@results.select {|k,v| v==:success}.length
        hangs=@results.select {|k,v| v==:hang}.length
        fails=@results.select {|k,v| v==:fail}.length
        crashes=@results.select {|k,v| v==:crash}.length
        unknown=@results.select {|k,v| v==:checked_out}.length
        if @sent%100==0
            @sent_mark=@sent
            @time_mark=Time.now
        end
        print "\r"
        print "Crash: #{crashes}, Fail: #{fails}, Success: #{succeeded}, #{@sent} currently @ #{"%.2f"%((@sent-@sent_mark)/(Time.now-@time_mark).to_f)}/s"
    ensure
        Thread.critical=false
    end
end
