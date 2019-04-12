"""bridgit.py
mr_me 2018
https://srcincite.io/blog/2018/06/22/foxes-among-us-foxit-reader-vulnerability-discovery-and-exploitation.html
"""
from __future__ import absolute_import

import pykd
import sys
import optparse


def banner():
    return """\n\tBridgit - JavaScript Bridge for Foxit Reader\n\tmr_me 2018\n"""


class foxit_js_bridge(pykd.eventHandler):
    def __init__(self):

        # store the allocations we find
        self.allocs = []
        self.ret_addr = None
        self.bp_heap_alloc = None

        # offsets to these symbols via reversing
        # tested on FoxitReader.exe v9.0.1.1049 (sha1: a01a5bde0699abda8294d73544a1ec6b4115fa68)
        # you will need to update this on different versions
        self.__CIatan_pentium4 = 0x13dc840
        self.__CIasin_pentium4 = 0x13dcb30

        addr = self.get_address("FoxitReader!CertFreeCertificateChain")

        if addr is None:
            return

        # address offsets for later use
        self.asan_addr = (int(addr, 16) + self.__CIatan_pentium4)
        self.asin_addr = (int(addr, 16) + self.__CIasin_pentium4)

        print("(+) setting up __CIatan_pentium4 bp")
        self.bp_asan = pykd.setBp((int(addr, 16) + self.__CIatan_pentium4), self._cb_CIatan_pentium4)

        print("(+) setting up __CIasin_pentium4 bp")
        self.bp_asin = pykd.setBp((int(addr, 16) + self.__CIasin_pentium4), self._cb_CIasin_pentium4)
        self.bp_end_atan = None
        self.bp_end_asin = None
        pykd.go()

    def get_address(self, local_addr):
        res = pykd.dbgCommand("x " + local_addr)
        result_count = res.count("\n")
        if result_count == 0:
            print(local_addr + " not found.")
            return None
        if result_count > 1:
            print("(-) warning, more than one result for", local_addr)
        return res.split()[0]

    def get_pykd_version(self):
        version = pykd.version
        version_number = int(version.replace(',', '.').replace(' ', '').split('.')[1])
        return version_number

    def _cb_CIatan_pentium4(self, bp):
        sp = pykd.reg("esp")

        # reversed this a while a go now
        bridge = pykd.loadCStr((pykd.ptrPtr(sp + 0x78) + 0xb))
        print("(+) DEBUG ATAN: %s" % bridge)

        if self.bp_end_atan is None:
            disas = pykd.dbgCommand("uf %x" % self.asan_addr).split('\n')
            for i in disas:
                if 'ret' in i:
                    self.ret_addr = i.split()[0]
                    break
            self.bp_end_atan = pykd.setBp(int(self.ret_addr, 16), self.return_call_back)
        return False

    def _cb_CIasin_pentium4(self, bp):
        sp = pykd.reg("esp")

        # reversed this a while a go now
        bridge = pykd.loadCStr((pykd.ptrPtr(sp + 0x78) + 0xb))
        print("(+) DEBUG ASIN: %s" % bridge)

        if self.bp_end_asin is None:
            disas = pykd.dbgCommand("uf %x" % self.asin_addr).split('\n')
            for i in disas:
                if 'ret' in i:
                    self.ret_addr = i.split()[0]
                    break
            self.bp_end_asin = pykd.setBp(int(self.ret_addr, 16), self.return_call_back)
        return False

    def return_call_back(self, bp):
        if self.bp_end_atan == bp and self.bp_heap_alloc is None:
            # this is where we enable our heap alloc bp
            print("(+) enabling heap alloc bp.")
            addr = self.get_address("ntdll!RtlAllocateHeap")
            disas = pykd.dbgCommand("uf %x" % int(addr, 16)).split('\n')
            for i in disas:
                if 'ret' in i:
                    self.ret_addr = i.split()[0]
                    break
            self.bp_heap_alloc = pykd.setBp(int(self.ret_addr, 16), self.return_call_back_with_eax)
        elif self.bp_end_asin == bp and self.bp_heap_alloc is not None:
            # this is where we disable our heap alloc bp
            print("(+) disabling heap alloc bp.")
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

    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-o", type="string", action="store", dest="option",
                      help="The option to specify")
    parser.add_option("-s", type="int", action="store", dest="size",
                      help="The size of the object to look for")
    parser.add_option("-l", action="store_true", dest="list",
                      help="List the options available")
    (options, args) = parser.parse_args()

    print(banner())

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    if options.list:
        print("(+) options available:\r\n")
        print("(1) 'find_ub' - find uninitialized buffers")
        print("(2) 'find_ob' - find objects via vtables")
        sys.exit(1)

    available_options = ["find_ub", "find_ob"]
    opt = options.option.lower()
    if opt in available_options:
        f = foxit_js_bridge()
        if "find_ub" == opt:
            for a in f.allocs:
                try:
                    # TODO: add a check here for page heap and alert user if not enabled
                    if pykd.ptrDWord(a) == 0xc0c0c0c0:
                        heap_check = pykd.dbgCommand("!heap -p -a 0x%08x" % a)
                        if "busy" in heap_check:
                            print("(+) found uninitialized chunk: 0x%08x" % a)
                            if options.size:
                                size = "%x -" % options.size
                                if size in heap_check:
                                    print(heap_check)
                                    print(pykd.dbgCommand("dd 0x%08x" % a))
                            else:
                                print(heap_check)
                                print(pykd.dbgCommand("dd 0x%08x" % a))
                finally:
                    pass
        elif "find_ob" in opt:
            for a in f.allocs:
                try:
                    # Turns out that most foxit objects have offset +0x10 set to -1
                    # TODO: patch this to check for vftables
                    if pykd.ptrDWord(a + 0x10) == 0xffffffff:
                        heap_check = pykd.dbgCommand("!heap -p -a 0x%08x" % a)
                        if "busy" in heap_check:
                            print("(+) found uninitialized chunk: 0x%08x" % a)
                            if options.size:
                                size = "%x -" % options.size
                                if size in heap_check:
                                    print(heap_check)
                                    print(pykd.dbgCommand("dd 0x%08x" % a))
                            else:
                                print(heap_check)
                                print(pykd.dbgCommand("dd 0x%08x" % a))
                finally:
                    pass
        print("(+) done!")


if __name__ == "__main__":
    main()
