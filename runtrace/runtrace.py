#!c:\python25\python.exe
#
# this is licensed as "fuck windows" seriously. fuck windows.
#
# (c) 2009, the grugq <the.grugq@gmail.com>

from __future__ import with_statement

import pydbg
import bisect

def load_addresses(path):
    addresses = {}

    with open(path) as fp:
        for line in (l.strip() for l in fp):
            address, name = line.split('|', 1)
            addresses[int(address)] = name
    return addresses

class Library(object):
    def __init__(self, name, functions):
        self.name = name
        self.functions = functions
        self.addrs = sorted(functions.keys())
        self.base = 0
        self.size = 0

    def rebase(self, base, size):
        self.base = base
        self.size = size
        #self.addrs = [base+addr for addr in self.addrs]

    def get_function(self, address):
        if address not in self:
            raise KeyError("address is not in range: %x, %x-%x" % (address, self.base,
                                                                    self.base+self.size))
        if address not in self.addrs:
            index = bisect.bisect_right(self.addrs, address)
            address = self.addrs[index]

        return self.functions[address]

    def __contains__(self, address):
        return self.base < address < (self.base + self.size)

class RunTracer(object):
    def __init__(self, addresses):
        self.dbg = pydbg.pydbg()
        self.addresses = addresses
        self.libraries = {}

        self.dbg.set_callback(pydbg.LOAD_DLL_DEBUG_EVENT, self.library_loaded)
        self.dbg.set_callback(pydbg.EXCEPTION_BREAKPOINT, self.bp_handler)

    def set_breakpoints(self):
        self.dbg.bp_set(self.addresses.keys(), handler=self.bp_handler)

    def load(self, path):
        self.dbg.load(path)

    def run(self):
        self.dbg.debug_event_loop()

    def add_library(self, lib):
        self.libraries[lib.name] = lib

    def library_loaded(self, dbg):
        lib = dbg.get_system_dll(-1)

        if lib.name in self.libraries:
            print "BP", lib.name, "%x" % lib.base
            library = self.libraries[lib.name]
            library.rebase(lib.base, lib.size)

            dbg.bp_set(library.addrs, handler=self.bp_handler)

        return pydbg.DBG_CONTINUE

    def add_frame(self, eip, name):
        pass

    def bp_handler(self, dbg):
        if dbg.first_breakpoint:
            self.set_breakpoints()
            return pydbg.DBG_CONTINUE

        eip = dbg.context.Eip
        if eip in self.addresses:
            name = self.addresses.get(eip)
        else:
            for lib in self.libraries.values():
                if eip in lib:
                    name = lib.get_function(eip)
                    break
            else:
                name = "UNKNOWN(%x)" % eip

        print "%x -> %s" % (eip, name)

        self.add_frame(eip, name)

        return pydbg.DBG_CONTINUE

def main(args):
    path = "dbgtarget.exe"

    addresses = load_addresses(args[1])
    ntdlladdrs = load_addresses("ntdll_address.txt")

    tracer = RunTracer(addresses)

    ntdll = Library("ntdll.dll", ntdlladdrs)

    tracer.add_library(ntdll)
    
    tracer.load(path)
    tracer.run()

if __name__ == "__main__":
    import sys
    main(sys.argv)
