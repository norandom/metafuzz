require 'fuzz_server'

class WordFuzzServer < FuzzServer
    # handle the result, write out the doc file and the .txt details.
    def handle_result( msg )
        result_id,result_status,crashdata,crashfile=msg.id, msg.status, msg.data, msg.crashfile
        if result_status==:crash
            detail_path=File.join(self.class.work_dir,"detail-#{result_id}.txt")
            crashfile_path=File.join(self.class.work_dir,"crash-#{result_id}.doc")
            File.open(detail_path, "wb+") {|io| io.write(crashdata)}
            File.open(crashfile_path, "wb+") {|io| io.write(crashfile)}
        end
        self.class.result_tracker.add_result(Integer(result_id),result_status,detail_path||=nil,crashfile_path||=nil)
    end
end

WordFuzzServer.setup

EM.epoll
EventMachine::run {
    EM.add_periodic_timer(20) do 
        @old_time||=Time.now
        @old_total||=Integer(WordFuzzServer.result_tracker.summary[:current_count])
        @total=Integer(WordFuzzServer.result_tracker.summary[:current_count])
        print "\rconns: #{EventMachine.connection_count}, "
        print "Q: #{WordFuzzServer.waiting_for_data.size}, "
        print "Done: #{@total} ("
	print "S/F/C: #{WordFuzzServer.result_tracker.summary[:success]} / "
	print "#{WordFuzzServer.result_tracker.summary[:fail]} / "
	print "#{WordFuzzServer.result_tracker.summary[:crash]}), "
        print "Speed: #{"%.2f" % ((@total-@old_total)/(Time.now-@old_time).to_f)}           "
        @old_total=Integer(WordFuzzServer.result_tracker.summary[:current_count])
        @old_time=Time.now
    end
EventMachine::start_server(WordFuzzServer.server_ip, WordFuzzServer.server_port, WordFuzzServer)
}
