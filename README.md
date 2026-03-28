# Driver Buddy Revolutions for Ghidra

By Juan Sacco <support@exploitpack.com>  
Website: https://exploitpack.com

`ghidra_vuln_finder.py` is a Ghidra analysis script based on DriverBuddy that performs automated static reconnaissance on Windows kernel drivers. It scans drivers for common build patterns, identifies interesting routines, extracts and decodes IOCTLs, maps exposed device interfaces, and helps triage attack surface in dispatch handlers and other user-reachable paths.

## IOCTL Discovery and Decoding

The script detects IOCTLs from multiple sources:

- Dispatch-style handlers by scanning decompiled code for patterns such as `IoControlCode`, `Parameters.DeviceIoControl`, and related IRP field usage
- Caller-side constructions such as `IoBuildDeviceIoControlRequest`
- Direct comparisons inside handlers, including compact or uncommon IOCTL values such as `0x10000` and `0x10004` used by drivers like `Beep.sys`

It decodes `CTL_CODE` values into:

- Device type, such as `FILE_DEVICE_NETWORK`
- Function code
- Access, such as `FILE_ANY_ACCESS`, `FILE_READ_ACCESS`, or `FILE_WRITE_ACCESS`
- Method, such as `METHOD_BUFFERED`, `METHOD_IN_DIRECT`, `METHOD_OUT_DIRECT`, or `METHOD_NEITHER`

This includes lower-value valid IOCTLs and function code `0`, which are used by some Microsoft drivers and should not be discarded by overly strict heuristics.

## Device Names and Symbols

The script extracts literal device names and symbolic link names present in decompiled strings, including patterns such as:

- `\Device\Foo`
- `\DosDevices\Bar`

This helps identify exposed device interfaces and user-visible handles.

## Interesting Opcode and API Detection

The script reports a broad set of interesting, privileged, and security-relevant instructions. This includes low-level CPU, MSR, port I/O, register-access, and other hardware-facing instruction patterns that may indicate powerful primitives or unusual kernel behavior.

It also identifies common C runtime functions and a wide range of Windows kernel APIs across memory management, object handling, process interaction, I/O, mapping, and filter-related operations, then reports the locations where they appear. This helps surface driver functionality that may be useful during vulnerability research.

## Vulnerability Heuristics

The script includes several heuristics to highlight potentially dangerous code patterns for triage. These checks are meant to surface functions that deserve manual review and are not proof of exploitability.

### Physical Memory and Low-Level I/O

Flags references and APIs associated with direct physical memory or MMIO access, including:

- `\Device\PhysicalMemory`
- `MmMapIoSpace`
- `MmMapLockedPagesSpecifyCache`
- `MmGetPhysicalAddress`

### Unsafe User-Copy Patterns

Highlights `memcpy`, `memmove`, `RtlCopyMemory`, and similar copy operations in IOCTL paths when they appear without nearby validation such as:

- `ProbeForRead`
- `ProbeForWrite`
- Structured exception handling

This can indicate possible user-to-kernel copy issues.

### Integer Overflow and Allocation Heuristics

Finds pool allocations where the size appears to come from user-controlled input without safe arithmetic helpers such as:

- `RtlULongMult`
- `RtlULongAdd`

This can help identify sized-allocation overflow risks.

### Privilege Gating and Access Checks

Highlights sensitive operations reachable from IOCTL handlers when nearby privilege or access checks are missing, such as:

- `SeSinglePrivilegeCheck`
- `SeAccessCheck`

This is useful for spotting privileged behavior exposed to user control.

### I/O Port and Register Access

Looks for helpers and patterns that suggest read or write access to hardware ports, CPU registers, MSRs, or device registers from reachable driver code paths.

## How It Works

### Decompiler and Listing Analysis

Uses Ghidra's decompiler through `DecompInterface` to inspect functions for dispatch-related artifacts, string literals, and user-controlled code paths.

### Instruction Scanning

Walks program instructions to locate calls and references to important routines such as `IoBuildDeviceIoControlRequest`, `IoCreateDevice`, `MmMapIoSpace`, and many other sensitive APIs.

### Backward Constant Recovery

When a relevant call site is found, the script walks backward through a limited instruction window to recover immediate constants that decode as IOCTLs.

### CTL_CODE Decoding

Implements standard `CTL_CODE` bit extraction:
```
device   = (value >> 16) & 0xFFFF
access   = (value >> 14) & 0x3
function = (value >> 2)  & 0xFFF
method   = value & 0x3
```

### Heuristics: 
Uses presence/absence of known API calls and string/constant analysis to flag suspicious functions.

### How to use:
1. Copy ghidra_vuln_finder.py to your Ghidra Script Manager/dbg-scripts folder.
2. Open the target driver in Ghidra (set correct language/processor if necessary).
3. Run the script from Script Manager or press Shift + A
4. View the printed output in Ghidra’s console, also a log with this output is created in your temp folder.


<img width="2411" height="1138" alt="Screenshot From 2026-03-28 16-42-14" src="https://github.com/user-attachments/assets/43cbc38d-dc9d-41bb-8a58-9aeb2e87aca8" />


### Credits:
IOCTL Decoded: https://github.com/tandasat/WinIoCtlDecoder/blob/master/plugins/WinIoCtlDecoder.py

Original DriverBuddy (IDA): https://github.com/nccgroup/DriverBuddy

This is an extended version for Ghidra of the IDA plugin: https://github.com/VoidSec/DriverBuddyReloaded
