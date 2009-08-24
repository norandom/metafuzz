#
#

from __future__ import with_statement

import idautils
import idc
import os

def get_filename():
    path, filename = os.path.split(idc.GetIdbPath())
    #filename, ext = os.path.splitext(filename)
    return filename

def get_segments():
    return [(ea, idc.SegEnd(ea)) for ea in idautils.Segments()]

def get_functions_in_range(start_ea, end_ea):
    return list(idautils.Functions(start_ea, end_ea))

def get_function_name(ea):
    return idc.GetFunctionName(ea)

def get_functions():
    segments = get_segments()

    for seg_num, seg in enumerate(segments):
        print 'Segment[%d/%d]' % (seg_num+1, len(segments))

        for address in get_functions_in_range(seg[0], seg[1]):
            name = get_function_name(address)

            yield (address, name)

def export_functions(path):
    with open(path, 'wb') as fp:
        for address,name in get_functions():
            fp.write("%s|%s\n" % (address,name))

def main():
    cwd = os.getcwd()
    path = os.path.join(cwd, "func_address.txt")

    print "DUMPING TO:", path

    export_functions(path)

if __name__ == "__main__":
    main()
