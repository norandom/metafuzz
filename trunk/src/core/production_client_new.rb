require 'rubygems'
require 'eventmachine'
require 'fileutils'
require File.dirname(__FILE__) + '/objhax'
require 'base64'
require 'zlib'
require 'digest/md5'
require 'socket'
require File.dirname(__FILE__) + '/em_netstring'
require File.dirname(__FILE__) + '/fuzzprotocol'
require File.dirname(__FILE__) + '/detail_parser'

# This class is a generic class that can be inherited by task specific production clients, to 
# do most of the work. It speaks my own Metafuzz protocol which is pretty much
# serialized hashes, containing a verb and other parameters.
#
# In the overall structure, one or more of these will feed test cases to one or more fuzz servers.
# In a more complicated implementation it would also be able to adapt, based on the results.
#
# To be honest, if you don't understand this part, (which is completely fair) 
# you're better off reading the EventMachine documentation, not mine.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt

class ProductionClient < HarnessComponent

    COMPONENT="ProdClient"
    VERSION="3.0.0"
    DEFAULT_CONFIG={
        'server_ip'=>"127.0.0.1",
        'server_port'=>10001,
        'work_dir'=>File.expand_path('~/prodclient'),
        'poll_interval'=>10,
        'production_generator'=>nil,
        'queue_name'=>'bulk',
        'debug'=>false,
        'template'=>'',
        'template_hash'=>''
    }

    def self.next_case_id
        @case_id||=0
        @case_id+=1
    end

    def self.case_id
        @case_id||=0
    end

    # --- Send methods

    def send_test_case( tc, case_id, crc )
        send_message(
            'verb'=>'new_test_case',
            'id'=>case_id,
            'crc32'=>crc,
            'data'=>tc,
            'queue'=>self.class.queue_name,
            'template_hash'=>self.class.template_hash
        )
    end

    def send_client_startup
        send_message(
            'verb'=>'client_startup',
            'client_type'=>'production',
            'template'=>self.class.template,
            'crc32'=>Zlib.crc32( self.class.template ),
        )
    rescue
        puts $!
    end

    def send_next_case
        if self.class.production_generator.next?
            test=self.class.production_generator.next
            crc=Zlib.crc32(test)
            send_test_case test, self.class.next_case_id, crc
        else
            puts "All done, exiting."
            EventMachine::stop_event_loop
        end
    end

    # Receive methods...

    # By default, we just use the second ack which contains the result
    # to keep stats. If you need to have a sequential producer, overload 
    # this function to ignore the first ack which just signifies receipt.
    def handle_ack_msg( their_msg )
        our_stored_msg=super
        if their_msg.result
            self.class.lookup[:results][their_msg.result]||=0
            self.class.lookup[:results][their_msg.result]+=1
            if their_msg.result=='crash' and their_msg.detail
                unless our_stored_msg['crc32']==their_msg.crc32
                    raise RuntimeError, "#{COMPONENT}: BARF! CRC32 failure, file corruption."
                end
                crashdetail=Detail.new( their_msg.detail )
                self.class.lookup[:buckets][crashdetail.hash]=true
                # You might want to clear this when outputting status info.
                self.class.queue[:bugs] << crashdetail.long_desc
                # Just initials - NOT EXPLOITABLE -> NE etc
                classification=crashdetail.classification.split.map {|e| e[0]}.join
                self.class.lookup[:classifications][classification]||=0
                self.class.lookup[:classifications][classification]+=1
            end
        else
            send_next_case
        end
    end

    def handle_reset( msg )
        # Note that we don't cancel unacked test cases or
        # restart the production generator, we just send
        # the startup so the server will get our template
        send_client_startup
    end

    def post_init
        send_client_startup
    end
end
