"""
bridgit.py
mr_me 2018

Usage:
======

Install this file into C:\Program Files\Windows Kits\10\Debuggers\x86 and make sure you load pykd

!load pykd.pyd
!py bridgit

Objective:
==========

Dump all allocations that occur from arbitrary JavaScript inside of FoxitReader using a "bridge". The bridge starts with a begin statement like so:

start("enabling heap hook");

Then ends with the end statement like so:

end("disabling heap hook");

Between these to, the goal is to attempt to find allocations of a size that we maybe looking for, to exploit various bugs.

Notes:
======

- The code could be cleaned up a little, but it works well.
- My motivation for this was to develop a working exploit for Foxit Reader

Usage:
======

You will need to create your js.pdf like so:

%PDF 
1 0 obj
<</Pages 1 0 R /OpenAction 2 0 R>> 
2 0 obj
<</S /JavaScript /JS (

function start(msg) {
    Math.atan(msg);
}

function end(msg) {
    Math.asin(msg);
}

console.show();

)>> trailer <</Root 1 0 R>>

Then, you will need to call the code like this in the console:

start("enabling heap hook");
this.addAnnot({type:"Text", page: 0, name:"test"});
end("disabling heap hook");

Example:
========

0:022> !py bridgit

    Bridgit - JavaScript Bridge for Foxit Reader
    mr_me 2018

Usage: !py bridgit.py -o <option> -s <size>
Example: !py bridgit.py -l
Example: !py bridgit.py -o find_ub
Example: !py bridgit.py -o find_ub -s 0x6c

Options:
  -h, --help  show this help message and exit
  -o OPTION   The option to specify
  -s SIZE     The size of the object to look for
  -l          List the options available
0:022> !py bridgit -l

    Bridgit - JavaScript Bridge for Foxit Reader
    mr_me 2018

(+) options available:

(1) 'find_ub' - find uninitialized buffers
(2) 'find_ob' - find objects via vtables

1. This example finds an uninitialized buffer. Note, you will need page heap enabled.

0:035> !py bridgit -o find_ub -s 0x6c

    Bridgit - JavaScript Bridge for Foxit Reader
    mr_me 2018

(+) setting up __CIatan_pentium4 bp
(+) setting up __CIasin_pentium4 bp
Breakpoint 0 hit
(+) DEBUG ATAN: (+) enabling heap hook
Breakpoint 2 hit
(+) enabling heap alloc bp
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 1 hit
(+) DEBUG ASIN: (+) disabling heap hook
Breakpoint 4 hit
(+) disabling heap alloc bp
(6b4.c80): Break instruction exception - code 80000003 (first chance)
(+) found uninitialized chunk: 0x0f77af90
    address 0f77af90 found in
    _DPH_HEAP_ROOT @ 6aa1000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                                10a1364c:          f77af90               6c -          f77a000             2000
    718e8e89 verifier!AVrfDebugPageHeapAllocate+0x00000229
    772461fe ntdll!RtlDebugAllocateHeap+0x00000030
    7720a0d3 ntdll!RtlpAllocateHeap+0x000000c4
    771d58e0 ntdll!RtlAllocateHeap+0x0000023a
    028cee12 FoxitReader!CertFreeCertificateChain+0x013a2a32
    0117810c FoxitReader+0x0034810c
    024d122a FoxitReader!CertFreeCertificateChain+0x00fa4e4a
    024d146e FoxitReader!CertFreeCertificateChain+0x00fa508e
    024e7943 FoxitReader!CertFreeCertificateChain+0x00fbb563

 

0f77af90  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0
0f77afa0  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0
0f77afb0  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0
0f77afc0  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0
0f77afd0  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0
0f77afe0  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0
0f77aff0  c0c0c0c0 c0c0c0c0 c0c0c0c0 d0d0d0d0
0f77b000  ???????? ???????? ???????? ????????

(+) done!

2. This example finds the annotation object of 0x5c

0:022> !py foxit -o find_ob

    Bridgit - JavaScript Bridge for Foxit Reader
    mr_me 2018

(+) setting up __CIatan_pentium4 bp
(+) setting up __CIasin_pentium4 bp
Breakpoint 0 hit
(+) DEBUG ATAN: (+) enabling heap hook
Breakpoint 2 hit
(+) enabling heap alloc bp
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 3 hit
...
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 3 hit
Breakpoint 1 hit
(+) DEBUG ASIN: (+) disabling heap hook
Breakpoint 3 hit
Breakpoint 1 hit
(+) DEBUG ASIN: (+) disabling heap hook
Breakpoint 4 hit
(+) disabling heap alloc bp
(6b4.f98): Break instruction exception - code 80000003 (first chance)
(+) found uninitialized chunk: 0x11b52fa0
    address 11b52fa0 found in
    _DPH_HEAP_ROOT @ 6aa1000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                                11b11888:         11b52fa0               5c -         11b52000             2000
          ? FoxitReader!CertFreeCertificateChain+18c16dc
    718e8e89 verifier!AVrfDebugPageHeapAllocate+0x00000229
    772461fe ntdll!RtlDebugAllocateHeap+0x00000030
    7720a0d3 ntdll!RtlpAllocateHeap+0x000000c4
    771d58e0 ntdll!RtlAllocateHeap+0x0000023a
    028cee12 FoxitReader!CertFreeCertificateChain+0x013a2a32
    027196ea FoxitReader!CertFreeCertificateChain+0x011ed30a
    01a9488a FoxitReader!CertFreeCertificateChain+0x005684aa
    013e7cb9 FoxitReader+0x005b7cb9
    00f9e72c FoxitReader+0x0016e72c
    00f9ec71 FoxitReader+0x0016ec71
    00f9e6b5 FoxitReader+0x0016e6b5
    0169695a FoxitReader!CertFreeCertificateChain+0x0016a57a
    01696ff8 FoxitReader!CertFreeCertificateChain+0x0016ac18
    015aa65d FoxitReader!CertFreeCertificateChain+0x0007e27d
    015b3f99 FoxitReader!CertFreeCertificateChain+0x00087bb9
    011791c8 FoxitReader+0x003491c8
    02576e8e FoxitReader!CertFreeCertificateChain+0x0104aaae
    0256ec76 FoxitReader!CertFreeCertificateChain+0x01042896
    02571023 FoxitReader!CertFreeCertificateChain+0x01044c43

 

11b52fa0  02dedabc 1002cfc0 100a5f50 00000000
11b52fb0  ffffffff 096e3fd0 00000001 00000001
11b52fc0  00000001 00000001 00000004 00000000
11b52fd0  00000000 00000000 00000000 00000000
11b52fe0  00000000 00000000 070607e2 f82d370d
11b52ff0  c0c0c000 00000000 1002cfc0 d0d0d0d0
11b53000  ???????? ???????? ???????? ????????
11b53010  ???????? ???????? ???????? ????????

(+) done!
"""

import pykd
import sys
from optparse import OptionParser

def banner():
    return """\n    Bridgit - JavaScript Bridge for Foxit Reader\n    mr_me 2018\n"""

class foxit_js_bridge(pykd.eventHandler):
    def __init__(self):

        # store the allocations we find
        self.allocs = []

        self.bp_heap_alloc = None

        # offsets to these symbols via reversing
        # tested on FoxitReader.exe v9.0.1.1049 (sha1: a01a5bde0699abda8294d73544a1ec6b4115fa68)
        # you will need to update this on different versions
        self.__CIatan_pentium4 = 0x13dc840
        self.__CIasin_pentium4 = 0x13dcb30

        addr = self.get_address("FoxitReader!CertFreeCertificateChain")

        if addr == None:
            return
        
        # address offsets for later use
        self.asan_addr = (int(addr, 16) + self.__CIatan_pentium4)
        self.asin_addr = (int(addr, 16) + self.__CIasin_pentium4)
        
        print "(+) setting up __CIatan_pentium4 bp"
        self.bp_asan = pykd.setBp((int(addr, 16) + self.__CIatan_pentium4), self.__CIatan_pentium4_callback)

        print "(+) setting up __CIasin_pentium4 bp"
        self.bp_asin = pykd.setBp((int(addr, 16) + self.__CIasin_pentium4), self.__CIasin_pentium4_callback)
        self.bp_end_atan = None
        self.bp_end_asin = None
        pykd.go()

    def get_address(self, localAddr):
        res = pykd.dbgCommand("x " + localAddr)
        result_count = res.count("\n")
        if result_count == 0:
            print localAddr + " not found."
            return None
        if result_count > 1:
            print "(-) warning, more than one result for", localAddr
        return res.split()[0]

    def get_pykd_version(self):
        version = pykd.version
        version_number = int(version.replace(',', '.').replace(' ', '').split('.')[1])
        return version_number
    
    def __CIatan_pentium4_callback(self, bp):
        sp = pykd.reg("esp")

        # reversed this a while a go now
        bridge = pykd.loadCStr((pykd.ptrPtr(sp + 0x78) + 0xb))
        print "(+) DEBUG ATAN: %s" % bridge

        if self.bp_end_atan == None:
            disas = pykd.dbgCommand("uf %x" % self.asan_addr).split('\n')
            for i in disas:
                if 'ret' in i:
                    self.ret_addr = i.split()[0]
                    break
            self.bp_end_atan = pykd.setBp(int(self.ret_addr, 16), self.return_call_back)
        return False
    
    def __CIasin_pentium4_callback(self, bp):
        sp = pykd.reg("esp")

        # reversed this a while a go now
        bridge = pykd.loadCStr((pykd.ptrPtr(sp + 0x78) + 0xb))
        print "(+) DEBUG ASIN: %s" % bridge

        if self.bp_end_asin == None:
            disas = pykd.dbgCommand("uf %x" % self.asin_addr).split('\n')
            for i in disas:
                if 'ret' in i:
                    self.ret_addr = i.split()[0]
                    break
            self.bp_end_asin = pykd.setBp(int(self.ret_addr, 16), self.return_call_back)
        return False
    
    def return_call_back(self, bp):
        if self.bp_end_atan == bp and self.bp_heap_alloc == None:
            # this is where we enable our heap alloc bp
            print "(+) enabling heap alloc bp"
            addr = self.get_address("ntdll!RtlAllocateHeap")
            disas = pykd.dbgCommand("uf %x" % int(addr, 16)).split('\n')
            for i in disas:
                if 'ret' in i:
                    self.ret_addr = i.split()[0]
                    break
            self.bp_heap_alloc = pykd.setBp(int(self.ret_addr, 16), self.return_call_back_with_eax)
        elif self.bp_end_asin == bp and self.bp_heap_alloc != None:
            # this is where we disable our heap alloc bp
            print "(+) disabling heap alloc bp"
            if self.get_pykd_version() == 3:
                self.bp_asan.remove()
                self.bp_asin.remove()
                self.bp_end_asin.remove()
                self.bp_end_atan.remove()
                self.bp_heap_alloc.remove()
            else:
                pykd.removeBp(self.bp_asan)
                pykd.removeBp(self.bp_asin)
                pykd.removeBp(self.bp_end_asin)
                pykd.removeBp(self.bp_end_atan)
                pykd.removeBp(self.bp_heap_alloc)
        return False

    def return_call_back_with_eax(self, bp):
        if int(pykd.reg("eax")) not in self.allocs:
            self.allocs.append(int(pykd.reg("eax")))
        return False

def main(): 
    usage = "!py %prog -o <option> -s <size>"
    usage += "\nExample: !py %prog -l"
    usage += "\nExample: !py %prog -o find_ub"
    usage += "\nExample: !py %prog -o find_ub -s 0x6c"

    parser = OptionParser(usage=usage)
    parser.add_option("-o", type="string",action="store", dest="option",
                      help="The option to specify")
    parser.add_option("-s", type="int", action="store", dest="size",
                      help="The size of the object to look for")
    parser.add_option("-l", action="store_true", dest="list",
                      help="List the options available")
    (options, args) = parser.parse_args()

    print banner()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    if options.list:
        print "(+) options available:\r\n"
        print "(1) 'find_ub' - find uninitialized buffers"
        print "(2) 'find_ob' - find objects via vtables"
        sys.exit(1)

    available_options = ["find_ub", "find_ob"]
    opt = options.option.lower()
    if opt in available_options:
        f = foxit_js_bridge()
        if "find_ub" == opt:
            for a in f.allocs:
                try:
                    # TODO: add a check here for page heap and alert user if not enabled
                    if (pykd.ptrDWord(a) == 0xc0c0c0c0):
                        heap_check = pykd.dbgCommand("!heap -p -a 0x%08x" % a)
                        if "busy" in heap_check:
                            print "(+) found uninitialized chunk: 0x%08x" % a
                            if options.size:
                                size = "%x -" % options.size
                                if size in heap_check:
                                    print heap_check
                                    print pykd.dbgCommand("dd 0x%08x" % a)
                            else:
                                print heap_check
                                print pykd.dbgCommand("dd 0x%08x" % a)
                except:
                    pass
        elif "find_ob" in opt:
            for a in f.allocs:
                try:
                    # Turns out that most foxit objects have offset +0x10 set to -1
                    # TODO: patch this to check for vftables
                    if (pykd.ptrDWord(a + 0x10) == 0xffffffff):
                        heap_check = pykd.dbgCommand("!heap -p -a 0x%08x" % a)
                        if "busy" in heap_check:
                            print "(+) found uninitialized chunk: 0x%08x" % a
                            if options.size:
                                size = "%x -" % options.size
                                if size in heap_check:
                                    print heap_check
                                    print pykd.dbgCommand("dd 0x%08x" % a)
                            else:
                                print heap_check
                                print pykd.dbgCommand("dd 0x%08x" % a)
                except:
                    pass
        print "(+) done!"

if __name__ == "__main__":
    main()
