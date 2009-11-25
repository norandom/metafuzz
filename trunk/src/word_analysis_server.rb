require File.dirname(__FILE__) + '/analysis_server'
require File.dirname(__FILE__) + '/analysis_fsconn'
require 'base64'

# Fairly basic adaptation of the AnalysisServer class to handle Word fuzzing. 
# All I'm doing is overloading the handle_result method to write stuff
# out with a .doc extension.
#
# Revised version, using v2 of the fuzzprotocol.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt



EM.epoll
EventMachine::run {
	# Anything not set up here gets the default value.
    AnalysisServer.setup(
	'debug'=>false, 
	'server_ip'=>'192.168.242.101',
	'poll_interval'=>50
	)
   EventMachine::start_server(AnalysisServer.listen_ip, AnalysisServer.listen_port, AnalysisServer)
}