#require File.dirname(__FILE__) + '/rtdbwrapper'

# Just a quick wrapper, so I can change the underlying DB.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
module MetafuzzDB

    class ResultDB
        def initialize(params)
        end

        def add_result(id, status, crashdetail=nil, crashfile=nil, template=nil, encoding='base64')
        end

        def check_out
        end

        def result( id )
        end

        def crashfile( id )
        end

        def crashdetail( id )
        end

        def registers( id )
        end

        def stack_trace( id )
        end

        def exception_subtype( id )
        end

        def exception_short_desc( id )
        end

        def exception_long_desc( id )
        end
        
        def crashes_by_major_hash( hash_string )
        end

        def crashes_by_hash( hash_string )
        end
        
        def execute_raw_sql( sql_string )
        end

        def method_missing( meth, *args )
            @db.send meth, *args
        end
    end

    class TraceDB
    end

end
