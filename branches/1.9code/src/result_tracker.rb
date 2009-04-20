require 'rtdbwrapper'

class ResultTracker

    def initialize(dbfile)
        @production_clients=0
        @fuzz_clients=0
        @db=RTDB.new(dbfile)
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

    def summary
        @db.summary
    end
end
