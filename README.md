### Driver Buddy Revolutions for Ghidra ###
By Juan Sacco <jsacco@exploitpack.com> https://exploitpack.com

# How it works:
Decompiler / listing: Uses Ghidra decompiler via DecompInterface to inspect function for dispatch-style artifacts and string literals.
Instruction scanning: Iterates program instructions to find calls/references (e.g., to IoBuildDeviceIoControlRequest, IoCreateDevice, MmMapIoSpace, etc.).
Backward constant recovery: When a call-site is found, the script walks backwards a limited window of instructions to locate the immediate scalar that decodes as an IOCTL.

CTL_CODE decoding: Implements bit-field extraction consistent with CTL_CODE:
device = (value >> 16) & 0xFFFF
access = (value >> 14) & 0x3
function = (value >> 2) & 0xFFF
method = value & 0x3

# Heuristics: 
Uses presence/absence of known API calls and string/constant analysis to flag suspicious functions.

# How to use:
1. Copy ghidra_vuln_finder.py to your Ghidra Script Manager/dbg-scripts folder.
2. Open the driver binary in Ghidra (set correct language/processor if necessary).
3. Run the script from Script Manager or press Shift + A
4. View the printed output in Ghidra’s console, also a log with this output is created in your temp folder.

<img src="https://iili.io/KNtpwc7.png">


# Credits:
IOCTL Decoded: https://github.com/tandasat/WinIoCtlDecoder/blob/master/plugins/WinIoCtlDecoder.py

Original DriverBuddy (IDA): https://github.com/nccgroup/DriverBuddy

This is an extended version for Ghidra of the IDA plugin: https://github.com/VoidSec/DriverBuddyReloaded
