# Driver Buddy Revolutions for Ghidra
By Juan Sacco <support@exploitpack.com> Website: https://exploitpack.com

ghidra_vuln_finder.py is a Ghidra analysis script (based on DriverBuddy) that performs automated static reconnaissance on Windows kernel drivers. It scans the driver for common build patterns and interesting functions, decodes IOCTL values from the .sys file and triage potential attack surfaces (dispatch handlers and userland calls).

### IOCTL discovery & decoding
Detects IOCTLs both from dispatch-style code (looking for IoControlCode, Parameters.DeviceIoControl, etc. in decompiled functions) and from caller-side uses of IoBuildDeviceIoControlRequest.
Decodes CTL_CODE fields into their components:
- Device type (e.g. FILE_DEVICE_NETWORK)
- Function code
- Access (FILE_READ/WRITE/ANY)
- Method (METHOD_BUFFERED/IN_DIRECT/OUT_DIRECT/NEITHER)

### Device names and symbols
Extracts literal device and symbolic link names present in decompiled strings (e.g. \Device\Foo, \DosDevices\Bar) to help identify device interfaces and user-visible handles.

### Interesting opcode and API detection
Reports occurrences of interesting opcodes (e.g. rdmsr, wrmsr, rdpmc) that are suspicious/high-privileged.
Detects common C functions (e.g. sprintf, memcpy) and many WinAPI kernel functions (I/O, memory, object, and filter APIs) and prints the locations where they appear.

### Vulnerability heuristics added
The script contains several heuristics intended to highlight potentially dangerous code patterns (useful for triage — not proof of exploitability):

### Physical memory & low-level IO
Spots references like \Device\PhysicalMemory, calls to MmMapIoSpace / MmMapLockedPagesSpecifyCache, MmGetPhysicalAddress, and similar routines that indicate direct physical memory or MMIO access.

### Unsafe user-copy patterns
Flags memcpy/memmove/RtlCopyMemory or C-style copy calls in IOCTL paths that are not preceded by calls to ProbeForRead/ProbeForWrite (or other safety checks), or not wrapped in structured exception handling, suggesting potential user→kernel copy issues.

### Integer overflow / allocation heuristics
Finds ExAllocatePool/ExAllocatePoolWithTag/ExAllocatePoolWithQuota calls where the size argument is derived from user-supplied values without intermediate safe helpers (e.g. RtlULongMult, RtlULongAdd), signalling potential sized-allocation overflows.

### Privilege gating / access checks
Highlights sensitive operations performed in IOCTL paths without nearby privilege or access checks (absence of SeSinglePrivilegeCheck, SeAccessCheck, etc.), a heuristic to find privileged operations exposed to user control.

### I/O port or register access
Looks for port I/O helpers or patterns that indicate read/write to hardware registers reachable from higher-level code.

### How it works:
Decompiler / listing: Uses Ghidra decompiler via DecompInterface to inspect function for dispatch-style artifacts and string literals.
Instruction scanning: Iterates program instructions to find calls/references (e.g., to IoBuildDeviceIoControlRequest, IoCreateDevice, MmMapIoSpace, etc.).
Backward constant recovery: When a call-site is found, the script walks backwards a limited window of instructions to locate the immediate scalar that decodes as an IOCTL.

CTL_CODE decoding: Implements bit-field extraction consistent with CTL_CODE:
device = (value >> 16) & 0xFFFF
access = (value >> 14) & 0x3
function = (value >> 2) & 0xFFF
method = value & 0x3

### Heuristics: 
Uses presence/absence of known API calls and string/constant analysis to flag suspicious functions.

### How to use:
1. Copy ghidra_vuln_finder.py to your Ghidra Script Manager/dbg-scripts folder.
2. Open the driver binary in Ghidra (set correct language/processor if necessary).
3. Run the script from Script Manager or press Shift + A
4. View the printed output in Ghidra’s console, also a log with this output is created in your temp folder.


<img width="2411" height="1138" alt="Screenshot From 2026-03-28 16-42-14" src="https://github.com/user-attachments/assets/43cbc38d-dc9d-41bb-8a58-9aeb2e87aca8" />


### Credits:
IOCTL Decoded: https://github.com/tandasat/WinIoCtlDecoder/blob/master/plugins/WinIoCtlDecoder.py

Original DriverBuddy (IDA): https://github.com/nccgroup/DriverBuddy

This is an extended version for Ghidra of the IDA plugin: https://github.com/VoidSec/DriverBuddyReloaded
