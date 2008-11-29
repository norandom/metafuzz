require 'connector'
require 'conn_cdb'

debugger=Connector.new(CONN_CDB,"notepad.exe")
p debugger.registers
p debugger.registers.eax
debugger.close
