require 'connector'
require 'conn_cdb'

debugger=Connector.new(CONN_CDB,"notepad.exe")
p debugger.target_running?
debugger.send_break
p debugger.target_running?
p debugger.registers
p debugger.registers.eax
p debugger.crash?
debugger.close
