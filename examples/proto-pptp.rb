require 'binstruct'
require 'fsa'

module PPTP #:nodoc: all

  class StartControlConnReq < BinStruct
    unsigned    :len,       16,     "Message Length"
    unsigned    :pptp_type,     16,     "PPTP Message Type"
    hexstring   :cookie,    32,     "Magic Cookie"
    unsigned    :control_type,  16,     "Control Message Type"
    unsigned    :res0,      16,     "Reserved0"
    unsigned    :prot_ver,      16,     "Protocol Version"
    unsigned    :res1,      16,     "Reserved1"
    unsigned    :framing,       32,     "Framing Capabilities"
    unsigned    :bearer,    32,     "Bearer Capabilities"
    unsigned    :max_chans,     16,     "Maximum Channels"
    unsigned    :firmware,      16,     "Firmware Revision"
    string  :hostname,  64*8,   "Host Name"
    string  :vendor_string,     64*8,   "Vendor String"

    default_value :pptp_type,   1
    default_value :cookie,      "1a2b3c4d"
    default_value :control_type,    1
    default_value :res0,    0
    default_value :res1,    0
    default_value :framing,     1
    default_value :prot_ver,    0x0100
    default_value :firmware,    2195
    default_value :bearer,      1
    default_value :hostname,    "assmonkey.ass.com".instance_eval(%(self + "\000"*(64-self.length)))
    default_value :vendor_string,   "ASS MONKEYS INCORPORATED".instance_eval(%(self + "\000"*(64-self.length)))
    default_value :len,  156
  end # StartControlConnReq

  class StartControlConnResp < BinStruct
    unsigned    :len,           16,     "Message Length"
    unsigned    :pptp_type,     16,     "PPTP Message Type"
    hexstring   :cookie,        32,     "Magic Cookie"
    unsigned    :control_type,  16,     "Control Message Type"
    unsigned    :res0,          16,     "Reserved0"
    unsigned    :prot_ver,      16,     "Protocol Version"
    unsigned    :result,        8,  "Result Code"
    unsigned    :error,         8,  "Error Code"
    unsigned    :framing,       32,     "Framing Capabilities"
    unsigned    :bearer,        32,     "Bearer Capabilities"
    unsigned    :max_chans,     16,     "Maximum Channels"
    unsigned    :firmware,      16,     "Firmware Revision"
    string  :hostname,          64*8,   "Host Name"
    string  :vendor_string,     64*8,   "Vendor String"
  end # StartControlConnResp

  class StopControlConnReq < BinStruct
    unsigned    :len,       16,     "Message Length"
    unsigned    :pptp_type,     16,     "PPTP Message Type"
    hexstring    :cookie,    32,     "Magic Cookie"
    unsigned    :control_type,  16,     "Control Message Type"
    unsigned    :res0,      16,     "Reserved0"
    unsigned    :reason,    8,      "Reason"
    unsigned    :res1,      8,      "Reserved1"
    unsigned    :res2,      16,     "Reserved2"

    default_value :pptp_type,   1
    default_value :cookie,      "1a2b3c4d"
    default_value :control_type,    3
    default_value :reason,      1
    default_value :len,         16
  end # StopControlConnReq

  class StopControlConnResp < BinStruct
    unsigned    :len,       16,     "Message Length"
    unsigned    :pptp_type,     16,     "PPTP Message Type"
    hexstring    :cookie,    32,     "Magic Cookie"
    unsigned    :control_type,  16,     "Control Message Type"
    unsigned    :res0,      16,     "Reserved0"
    unsigned    :result,    8,      "Result Code"
    unsigned    :error,     8,      "Error Code"
    unsigned    :res1,      16,     "Reserved1"
  end # StopControlConnResp

  class EchoReq < BinStruct
    unsigned    :len,       16,     "Message Length"
    unsigned    :pptp_type,     16,     "PPTP Message Type"
    hexstring    :cookie,    32,     "Magic Cookie"
    unsigned    :control_type,  16,     "Control Message Type"
    unsigned    :res0,      16,     "Reserved0"
    unsigned    :id,        32,     "Identifier"

    default_value :pptp_type,   1
    default_value :cookie,      '1a2b3c4d'
    default_value :control_type,    5
    default_value :id,      0xdeadbeef
  end # Echo Req

  class EchoResp < BinStruct
    unsigned    :len,       16,     "Message Length"
    unsigned    :pptp_type,     16,     "PPTP Message Type"
    hexstring    :cookie,    32,     "Magic Cookie"
    unsigned    :control_type,  16,     "Control Message Type"
    unsigned    :res0,      16,     "Reserved0"
    unsigned    :id,        32,     "Identifier"
    unsigned    :result,    8,      "Result Code"
    unsigned    :error,     8,      "Error Code"
    unsigned    :res1,      16,     "Reserved1"
  end # EchoResp

  class OutgoingCallReq < BinStruct
    unsigned    :len,       16,     "Message Length"
    unsigned    :pptp_type,     16,     "PPTP Message Type"
    hexstring    :cookie,    32,     "Magic Cookie"
    unsigned    :control_type,  16,     "Control Message Type"
    unsigned    :res0,      16,     "Reserved0"
    unsigned    :call_id,       16,     "Call ID"
    unsigned    :call_serial,   16,     "Call Serial Number"
    unsigned    :min_bps,       32,     "Minimum BPS"
    unsigned    :max_bps,       32,     "Maximum BPS"
    unsigned    :bearer,    32,     "Bearer Type"
    unsigned    :framing,       32,     "Framing Type"
    unsigned    :recv_window,   16,     "Packet Recv. Window Size"
    unsigned    :proc_delay,    16,     "Packet Processing Delay"
    unsigned    :ph_len,    16,     "Phone Number Length"
    unsigned    :res1,      16,     "Reserved1"
    string  :ph_num,    64*8,   "Phone Number"
    string  :subaddr,       64*8,   "Subaddress"

    default_value :pptp_type,   1
    default_value :cookie,      "1a2b3c4d"
    default_value :control_type,    7
    default_value :bearer,      3
    default_value :framing,     3
    default_value :min_bps,     300
    default_value :max_bps,     100000000
    default_value :recv_window, 64
    default_value :len,         168
    default_value :ph_num,      "\000"*64
    default_value :subaddr,     "\000"*64
    randomize :call_id
    randomize :call_serial
  end # OutgoingCallReq

  class OutgoingCallResp < BinStruct
    unsigned    :len,       16,     "Message Length"
    unsigned    :pptp_type,     16,     "PPTP Message Type"
    hexstring    :cookie,    32,     "Magic Cookie"
    unsigned    :control_type,  16,     "Control Message Type"
    unsigned    :res0,      16,     "Reserved0"
    unsigned    :call_id,       16,     "Call ID"
    unsigned    :peer_call_id,  16,     "Call Serial Number"
    unsigned    :result,    8,      "Result Code"
    unsigned    :error,     8,      "Error Code"
    unsigned    :cause,     16,     "Cause Code"
    unsigned    :speed,     32,     "Connect Speed"
    unsigned    :recv_window,   16,     "Packet Recv. Window Size"
    unsigned    :proc_delay,    16,     "Packet Processing Delay"
    unsigned    :chann_id,      32,     "Phyical Channel ID"
  end # OutgoingCallResp

  class CallClearReq < BinStruct
    unsigned    :len,       16,     "Message Length"
    unsigned    :pptp_type,     16,     "PPTP Message Type"
    hexstring    :cookie,    32,     "Magic Cookie"
    unsigned    :control_type,  16,     "Control Message Type"
    unsigned    :res0,      16,     "Reserved0"
    unsigned    :call_id,       16,     "Call ID"
    unsigned    :res1,          16,     "Reserved1"

    default_value :pptp_type,   1
    default_value :cookie,      "1a2b3c4d"
    default_value :control_type,    12
    default_value :len,             16
  end #CallClearReq

  class CallDiscNotify < BinStruct
    unsigned    :len,           16,     "Message Length"
    unsigned    :pptp_type,     16,     "PPTP Message Type"
    hexstring    :cookie,        32,     "Magic Cookie"
    unsigned    :control_type,  16,     "Control Message Type"
    unsigned    :res0,          16,     "Reserved0"
    unsigned    :call_id,       16,     "Call ID"
    unsigned    :result,        8,      "Result Code"
    unsigned    :error,         8,      "Error Code"
    unsigned    :cause,         16,     "Cause Code"
    unsigned    :res1,          16,     "Reserved1"
    string      :stats,         128*8,  "Call Statistics"
  end #CallDiscNotify

  class SetLinkInfo < BinStruct
    unsigned    :len,       16,     "Message Length"
    unsigned    :pptp_type,     16,     "PPTP Message Type"
    hexstring    :cookie,    32,     "Magic Cookie"
    unsigned    :control_type,  16,     "Control Message Type"
    unsigned    :res0,      16,     "Reserved0"
    unsigned    :peer_call_id,  16,     "Peer Call ID"
    unsigned    :res1,      16,     "Reserved1"
    hexstring    :send_accm, 32,     "Send ACCM"
    hexstring    :recv_accm, 32,     "Receive ACCM"

    default_value :pptp_type,   1
    default_value :cookie,      "1a2b3c4d"
    default_value :control_type,    15
    default_value :send_accm,   "ffffffff"
    default_value :recv_accm,   "ffffffff"
    default_value :len,         24
  end #SetLinkInfo

  class ControlMsgHdr < BinStruct #partial header, used for parsing
    unsigned    :len,       16,     "Message Length"
    unsigned    :pptp_type,     16,     "PPTP Message Type"
    unsigned    :cookie,    32,     "Magic Cookie"
    unsigned    :control_type,  16,     "Control Message Type"
    unsigned    :res0,      16,     "Reserved0"
  end

  class Parser
    def self.new( buffer )
      pptp_classes={  
        1=>"StartControlConnReq",
        2=>"StartControlConnResp",
        3=>"StopControlConnReq",
        4=>"StopControlConnResp",
        5=>"EchoReq",
        6=>"EchoResp",
        7=>"OutgoingCallReq",
        8=>"OutgoingCallResp",
        12=>"CallClearReq",
        13=>"CallDiscNotify",
        15=>"SetLinkInfo"   
      }
      leadin=ControlMsgHdr.new(buffer.dup)
      PPTP.const_get(pptp_classes[leadin.control_type]).new(buffer)
    end
  end #Parser

  class PPTPFSA < FSA
    node    :idle, root=true
    node    :sent_conn_req
    node    :conn_established
    node    :sent_call_req
    node    :call_established
    node    :sent_link_info
    node    :clearing
    node    :clear
    node    :sent_conn_terminate
    node    :terminated

    conn_establish_match=proc {|resp| 
      begin
        pkt=Parser.new(resp) 
      rescue 
        break(false)
      end
      pkt.control_type==2 && pkt.result==1
    }
    conn_establish_action=proc {|resp| nil}
    create_start_call=proc {
      pkt=OutgoingCallReq.new
      set_state :our_id, pkt.call_id
      pkt
    }
    call_established_match=proc {|resp|
      begin
        pkt=Parser.new(resp) 
      rescue 
        break false
      end
      pkt.control_type==8 && pkt.result==1 && pkt.peer_call_id==get_state(:our_id)
    }
    call_established_action=proc {|resp|
      set_state :their_id, Parser.new(resp).call_id
    }
    create_link_info=proc {
      li=SetLinkInfo.new
      li.peer_call_id=get_state :their_id
      li
    }
    create_call_clear=proc {
      ccr=CallClearReq.new
      ccr.call_id=get_state :our_id
      ccr
    }
    conn_term_match=proc {|resp|
      begin
        pkt=Parser.new(resp) 
      rescue 
        break(false)
      end
      pkt.class==StopControlConnResp
    }
    call_clear_match=proc {|resp|
      begin
        pkt=Parser.new(resp) 
      rescue 
        break(false)
      end
      pkt.class==CallDiscNotify && pkt.call_id==get_state( :their_id )
    }

    edge :idle, :sent_conn_req, :send, proc {StartControlConnReq.new}
    edge :sent_conn_req, :conn_established, :recv, conn_establish_match, conn_establish_action
    edge :conn_established, :sent_call_req, :send, create_start_call
    edge :sent_call_req, :call_established, :recv, call_established_match, call_established_action
    edge :call_established, :sent_link_info, :send, create_link_info
    edge :sent_link_info, :clearing, :send, create_call_clear
    edge :clearing, :clear, :recv, call_clear_match, proc {|resp| nil}
    edge :clear, :sent_conn_terminate, :send, proc {StopControlConnReq.new}
    edge :sent_conn_terminate, :terminated, :recv, conn_term_match, proc {|resp| nil}
  end #PPTPFSA

end #Module PPTP
