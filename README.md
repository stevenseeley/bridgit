# bridgit

## Usage:

Install this file into C:\Program Files\Windows Kits\10\Debuggers\x86 and make sure you load pykd

```
!load pykd.pyd
!py bridgit
```

Also, you will need to enable page heap (and possible usermode stack traces) on FoxitReader.exe

```
C:\> gflags -i foxitreader.exe +hpa +ust
```

## Objective:

Dump all allocations that occur from arbitrary JavaScript inside of FoxitReader using a "bridge". The bridge starts with a begin statement like so:

```JavaScript
start("enabling heap hook");
// do some allocation here
end("disabling heap hook");
```
Between these to, the goal is to attempt to find allocations of a size that we maybe looking for, to discover and/or exploit various bugs.

## Notes:

- The code could be cleaned up a little, but it works well.
- I used this was to develop a working exploit for Foxit Reader targeting [ZDI-18-332](https://www.zerodayinitiative.com/advisories/ZDI-18-332/) but I also used it to discover [SRC-2018-0027](https://srcincite.io/advisories/src-2018-0027/)

## Usage:

You will need to create your `js.pdf` like so:

```
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
```

Then, you will need to call the code like this in the console:

```JavaScript
start("enabling heap hook");
this.addAnnot({type:"Text", page: 0, name:"test"});
end("disabling heap hook");
```

## Example:

```
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
```
