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
    EM.add_periodic_timer(5) do 
        print "\rClients: #{EventMachine.connection_count}, Queue: #{WordFuzzServer.delivery_queue.size}"
        print ", Waiting: #{WordFuzzServer.waiting_for_data.size}"
    end
EventMachine::start_server(WordFuzzServer.server_ip, WordFuzzServer.server_port, WordFuzzServer)
}