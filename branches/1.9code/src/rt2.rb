require 'rtdbwrapper'

class ResultTracker2

    attr_reader :production_clients, :fuzz_clients

    def initialize(dbfile)
        @production_clients=0
        @fuzz_clients=0
        @db=RTDB.new(dbfile)
    end

    def add_fuzz_client
        @fuzz_clients+=1
    end

    def remove_fuzz_client
        @fuzz_clients-=1
    end

    def add_production_client
        @production_clients+=1
    end

    def remove_production_client
        @production_clients-=1
    end

    def add_result(id, status, crashdetail_path=nil,crashfile_path=nil)
        @db.insert_result(id,status,crashdetail_path,crashfile_path)
    end

    def results_outstanding
        @db.results_outstanding
    end

    def check_out
        @db.check_out
    end
end
