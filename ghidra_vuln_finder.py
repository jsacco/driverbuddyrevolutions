# Filename: ghidra_vuln_finder.py
#@category Analysis/Vulnerability
#@keybinding Shift A
# This script performs a best-effort static triage of Windows kernel drivers
# and surfaces patterns that often lead to vulnerabilities.
# Author: Juan Sacco <jsacco@exploitpack.com>

from ghidra.util.task import TaskMonitor
from java.io import FileWriter, BufferedWriter, File
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.pcode import PcodeOp

import re
import time

# ----------------------------- Config / Dictionaries ----------------------------

opcode_severity = {'rdpmc':'High','rdmsr':'High','wrmsr':'High'}
c_funcs = ['sprintf','swprintf','snprintf','memcpy','memmove','RtlCopyMemory']
winapi_prefixes = ['ProbeFor','Rtl','Ob','Zw','Mm','IofCallDriver','Io','Flt','ExAllocatePool']

file_device_map = {
    0x0:'FILE_DEVICE_UNKNOWN', 0x1:'FILE_DEVICE_BEEP',0x2:'FILE_DEVICE_CD_ROM',0x3:'FILE_DEVICE_CD_ROM_FILE_SYSTEM',
    0x4:'FILE_DEVICE_CONTROLLER',0x5:'FILE_DEVICE_DATALINK',0x6:'FILE_DEVICE_DFS',0x7:'FILE_DEVICE_DISK',
    0x8:'FILE_DEVICE_DISK_FILE_SYSTEM',0x9:'FILE_DEVICE_FILE_SYSTEM',0x12:'FILE_DEVICE_NETWORK',
    0x13:'FILE_DEVICE_NETWORK_BROWSER',0x14:'FILE_DEVICE_NETWORK_FILE_SYSTEM',0x15:'FILE_DEVICE_NULL',
    0x22:'FILE_DEVICE_UNKNOWN',0x23:'FILE_DEVICE_VIDEO'
}
method_map = {0:'METHOD_BUFFERED',1:'METHOD_IN_DIRECT',2:'METHOD_OUT_DIRECT',3:'METHOD_NEITHER'}
access_map = {0:'FILE_ANY_ACCESS',1:'FILE_READ_ACCESS',2:'FILE_WRITE_ACCESS',3:'FILE_READ_WRITE_ACCESS'}

# Thresholds / tunables
HEURISTIC_LARGE_MAP_SIZE = 4 * 1024 * 1024  # 4MB
BACKWARD_SCAN_DEFAULT = 40                  # for immediate search near calls

# ----------------------------- Decompiler ----------------------------
decomp = None
try:
    decomp = DecompInterface()
    opts = DecompileOptions()
    decomp.setOptions(opts)
    decomp.openProgram(currentProgram)
except Exception:
    decomp = None

def decompile_func(func):
    if not decomp:
        return None
    try:
        return decomp.decompileFunction(func, 60, TaskMonitor.DUMMY)
    except Exception:
        return None

def decompiled_text(func):
    r = decompile_func(func)
    if not r or not r.getDecompiledFunction():
        return ''
    c = r.getDecompiledFunction().getC()
    return c or ''

# ----------------------------- Helpers -------------------------------
def get_symbol_name(addr):
    try:
        s = getSymbolAt(addr)
        if s: return s.getName()
    except Exception: pass
    try:
        e = getExternalEntryPoint(addr)
        if e: return e.getName()
    except Exception: pass
    try:
        f = getFunctionAt(addr)
        if f: return f.getName()
    except Exception: pass
    return None

def ctl_code_decode(vs):
    try:
        v = int(vs,0) if isinstance(vs,str) else int(vs)
    except Exception:
        return None
    v &= 0xFFFFFFFF
    device = (v>>16)&0xFFFF
    access = (v>>14)&0x3
    function = (v>>2)&0xFFF
    method = v & 0x3
    return {'raw':v,'device':device,'access':access,'function':function,'method':method}

def plausible_ioctl(v):
    d = ctl_code_decode(v)
    if not d: return False
    if d['method'] not in (0,1,2,3): return False
    if d['function'] == 0 or d['device'] == 0:
        return False
    return True

def fmt_ioctl_row(addr_str, code_val):
    dec = ctl_code_decode(code_val)
    if not dec: return None
    device = file_device_map.get(dec['device'], "0x%X" % dec['device'])
    method = method_map.get(dec['method'], str(dec['method']))
    access = access_map.get(dec['access'], str(dec['access']))
    # address first, then decoded fields
    return "{0: <20} : 0x{1:06X}   | {2:31s} {3:<10} | 0x{4:<8X} | {5:<17s} {6:<4} | {7} ({8})".format(
        addr_str, dec['raw'], device, "0x%X" % dec['device'], dec['function'], method, dec['method'], access, dec['access']
    )

def find_compare_addresses_for_constant(func, const_val):
    """
    Scan instructions in func to find first instruction that uses const_val as a scalar; return address string.
    """
    listing = currentProgram.getListing()
    try:
        for instr in listing.getInstructions(func.getBody(), True):
            for i in range(instr.getNumOperands()):
                try:
                    so = instr.getScalar(i)
                    if so is not None and (so.getValue() & 0xFFFFFFFF) == (const_val & 0xFFFFFFFF):
                        return instr.getAddress().toString()
                except Exception:
                    pass
    except Exception:
        pass
    return None

def is_dispatch_ioctl_handler(dt):
    # True when the decompiled function references the IRP stack and IoControlCode
    return ('Parameters.DeviceIoControl' in dt) or ('IoControlCode' in dt) or ('IRP_MJ_DEVICE_CONTROL' in dt)

def is_call_to(instr, names):
    try:
        if not instr.getFlowType().isCall():
            return False
        for r in instr.getReferencesFrom():
            nm = get_symbol_name(r.getToAddress())
            if nm:
                for name in names:
                    if nm == name or nm.startswith(name + "@"):
                        return True
    except Exception:
        pass
    return False

def backward_find_ioctl_immediate(start_instr, max_back=BACKWARD_SCAN_DEFAULT):
    """
    Walk backward from start_instr up to max_back instructions, return first plausible CTL_CODE immediate value.
    """
    listing = currentProgram.getListing()
    body = getFunctionContaining(start_instr.getAddress()).getBody()
    insns = [i for i in listing.getInstructions(body, True)]
    try:
        idx = insns.index(start_instr)
    except ValueError:
        return None
    for j in range(idx-1, max(idx-1-max_back, -1), -1):
        ins = insns[j]
        try:
            for opi in range(ins.getNumOperands()):
                sc = ins.getScalar(opi)
                if sc is None:
                    continue
                val = sc.getValue() & 0xFFFFFFFF
                if plausible_ioctl(val):
                    return val
        except Exception:
            pass
    return None

# ---------- Heuristics for user-driven input / validation ----------

def is_ioctl_context_text(dt):
    return ('IRP_MJ_DEVICE_CONTROL' in dt) or ('IoControlCode' in dt) or ('Parameters.DeviceIoControl' in dt)

def looks_user_driven_expr(txt):
    keys = [
        'Parameters.DeviceIoControl.InputBufferLength',
        'Parameters.DeviceIoControl.OutputBufferLength',
        'Parameters.DeviceIoControl.Type3InputBuffer',
        'Irp->AssociatedIrp.SystemBuffer',
        'Irp->UserBuffer',
        'MdlAddress'
    ]
    return any(k in txt for k in keys)

def nearby_has_validation(txt, around_idx, window=300):
    start = max(0, around_idx - window); end = min(len(txt), around_idx + window)
    chunk = txt[start:end]
    checks = [
        'ProbeForRead', 'ProbeForWrite', 'MmIsAddressValid',
        'RtlULongAdd', 'RtlULongLongAdd', 'RtlULongSub', 'RtlULongLongSub',
        'RtlULongMult', 'RtlULongLongMult', 'RtlSizeTAdd', 'RtlSizeTMult',
        'try {', '__try', 'if ('
    ]
    return any(c in chunk for c in checks)

def find_calls_in_text(dt, name):
    hits = []
    if name.endswith('_'):
        for m in re.finditer(r'\b' + re.escape(name) + r'[A-Za-z0-9_]+\b', dt):
            hits.append((m.group(0), m.start()))
    else:
        idx = 0
        while True:
            idx = dt.find(name, idx)
            if idx == -1: break
            hits.append((name, idx)); idx += len(name)
    return hits

def get_instr_addr_str_from_text_hit(func, text_hit_idx):
    # Best-effort: return function entry if we can't map text offset to instruction
    return func.getEntryPoint().toString()

def last_arg_is_const_one_heuristic(func, call_name):
    listing = currentProgram.getListing()
    for instr in listing.getInstructions(func.getBody(), True):
        if is_call_to(instr, [call_name]):
            insns = [i for i in listing.getInstructions(func.getBody(), True)]
            try:
                idx = insns.index(instr)
            except ValueError:
                continue
            for j in range(max(0, idx-6), idx):
                ins = insns[j]
                for opi in range(ins.getNumOperands()):
                    sc = ins.getScalar(opi)
                    if sc and (sc.getValue() & 0xFFFFFFFF) == 1:
                        return instr.getAddress().toString()
    return None

def immediate_nearby_value(func, call_name, max_back=8):
    """
    Return first immediate found near a call to call_name (for size/flags heuristics).
    """
    listing = currentProgram.getListing()
    for instr in listing.getInstructions(func.getBody(), True):
        if is_call_to(instr, [call_name]):
            insns = [i for i in listing.getInstructions(func.getBody(), True)]
            try:
                idx = insns.index(instr)
            except ValueError:
                continue
            for j in range(max(0, idx-max_back), idx):
                ins = insns[j]
                for opi in range(ins.getNumOperands()):
                    sc = ins.getScalar(opi)
                    if sc:
                        return sc.getValue() & 0xFFFFFFFF
    return None

# ----------------------------- Output buffer -------------------------------
lines = []
lines.append("[#] Driver Buddy Revolutions Auto-analysis")
lines.append("[#] By Juan Sacco <jsacco@exploitpack.com>")
lines.append("-----------------------------------------------")

# ----------------------------- DriverEntry discovery ------------------------
driver_entry = None
driver_entry_candidate = None
driver_entry_candidate_score = -1

for f in currentProgram.getListing().getFunctions(True):
    try:
        nm = f.getName()
        if nm == 'DriverEntry' or nm.lower().endswith('driverentry'):
            driver_entry = f; break
    except Exception:
        pass

if not driver_entry:
    indicators = ['IoCreateDevice','IoCreateSymbolicLink','IoRegisterDeviceInterface','IoSetDeviceInterfaceState',
                  'FltRegisterFilter','FltStartFiltering','RtlInitUnicodeString','RtlGetVersion']
    for f in currentProgram.getListing().getFunctions(True):
        dt = decompiled_text(f)
        score = 0
        for ind in indicators:
            if ind in dt: score += 1
        if dt.count('RtlInitUnicodeString') >= 2: score += 1
        if ('IoCreateDevice' in dt) and ('IoCreateSymbolicLink' in dt): score += 2
        if 'FltRegisterFilter' in dt: score += 2
        if score > driver_entry_candidate_score:
            driver_entry_candidate = f; driver_entry_candidate_score = score

if driver_entry:
    lines.append("[+] `DriverEntry` found at: {}".format(driver_entry.getEntryPoint().toString()))
elif driver_entry_candidate and driver_entry_candidate_score >= 2:
    lines.append("[+] `DriverEntry` (heuristic) found at: {}  (name: {})".format(
        driver_entry_candidate.getEntryPoint().toString(), driver_entry_candidate.getName()))
else:
    lines.append("[+] `DriverEntry` NOT found")

# ----------------------------- Device names -------------------------------
lines.append("[>] Searching for `DeviceNames`...")
devices = set()
for f in currentProgram.getListing().getFunctions(True):
    dt = decompiled_text(f)
    if not dt: continue
    for pat in [r'L\"(\\\\\\\\?Device\\\\[^\"]+)\"', r'\"(\\\\Device\\\\[^\"]+)\"',
                r'L\"(\\\\\\\\?DosDevices\\\\[^\"]+)\"', r'\"(\\\\DosDevices\\\\[^\"]+)\"']:
        try:
            for m in re.findall(pat, dt):
                dev = m.replace('\\\\\\\\','\\\\').replace('\\\\','\\')
                devices.add(dev)
        except Exception:
            pass
if devices:
    for d in sorted(devices):
        lines.append("  - " + d)
else:
    lines.append("  - (none detected)")

# ----------------------------- Pooltags (placeholder) ----------------------
lines.append("[>] Searching for `Pooltags`...")
lines.append("  - (none detected)")

# ----------------------------- Opcode / C / APIs ---------------------------
lines.append("[>] Searching for interesting opcodes...")
listing = currentProgram.getListing()
opcode_hits = []
c_hits = []
api_hits = []

for func in listing.getFunctions(True):
    fname = func.getName()
    try:
        for instr in listing.getInstructions(func.getBody(), True):
            try:
                mnem = instr.getMnemonicString().lower()
                if mnem in opcode_severity:
                    opcode_hits.append((mnem, fname, instr.getAddress().toString()))
            except Exception:
                pass
            try:
                for r in instr.getReferencesFrom():
                    t = get_symbol_name(r.getToAddress())
                    if not t: continue
                    for c in c_funcs:
                        if t == c:
                            c_hits.append((t, fname, instr.getAddress().toString()))
                    for p in winapi_prefixes:
                        if t.startswith(p):
                            api_hits.append((t, fname, instr.getAddress().toString()))
            except Exception:
                pass
    except Exception:
        pass

if opcode_hits:
    for mnem, fn, addr in sorted(opcode_hits, key=lambda x:(x[0], x[1], x[2])):
        lines.append("  - Found {} in {} at {}".format(mnem, fn, addr))
else:
    lines.append("  - (none detected)")

lines.append("[>] Searching for interesting C/C++ functions...")
if c_hits:
    for name, fn, addr in sorted(c_hits, key=lambda x:(x[0], x[1], x[2])):
        lines.append("  - Found {} in {} at {}".format(name, fn, addr))
else:
    lines.append("  - (none detected)")

lines.append("[>] Searching for interesting Windows APIs...")
if api_hits:
    for name, fn, addr in sorted(api_hits, key=lambda x:(x[0].lower(), x[1], x[2])):
        lines.append("  - Found {} in {} at {}".format(name, fn, addr))
else:
    lines.append("  - (none detected)")

# ----------------------------- Driver type heuristic -----------------------
driver_type = "Mini-Filter" if any(n.startswith('Flt') for n,_,_ in api_hits) else "Unknown"
lines.append("[+] Driver type detected: {}".format(driver_type))

# ----------------------------- IOCTL discovery -----------------------------
lines.append("[>] Searching for IOCTLs found by analysis...")
rows = []
seen = set()

# A) Decomp scan for dispatch-style handlers
for func in listing.getFunctions(True):
    dt = decompiled_text(func)
    if not is_dispatch_ioctl_handler(dt):
        continue
    for line in dt.splitlines():
        if 'IoControlCode' not in line and 'DeviceIoControl' not in line:
            continue
        for m in re.finditer(r'0x[0-9A-Fa-f]+', line):
            try:
                val = int(m.group(0), 16) & 0xFFFFFFFF
            except Exception:
                continue
            if not plausible_ioctl(val):
                continue
            addr = find_compare_addresses_for_constant(func, val) or "0x0"
            key = (addr, val)
            if key in seen: continue
            row = fmt_ioctl_row(addr, val)
            if row:
                rows.append(row); seen.add(key)

# B) Caller-side detection: IoBuildDeviceIoControlRequest
ioctl_call_names = ["IoBuildDeviceIoControlRequest"]
for func in listing.getFunctions(True):
    try:
        for instr in listing.getInstructions(func.getBody(), True):
            if not is_call_to(instr, ioctl_call_names):
                continue
            v = backward_find_ioctl_immediate(instr, max_back=BACKWARD_SCAN_DEFAULT)
            if v is None or not plausible_ioctl(v):
                continue
            addr = instr.getAddress().toString()
            key = (addr, v)
            if key in seen: continue
            row = fmt_ioctl_row(addr, v)
            if row:
                rows.append(row); seen.add(key)
    except Exception:
        pass

if rows:
    for r in sorted(set(rows)):
        lines.append(r)
else:
    lines.append("  - (none detected)")

# Save decoded IOCTLs log
ioctl_log_path = File.createTempFile(currentProgram.getName() + "-IOCTLs-", ".txt").getAbsolutePath()
try:
    bw = BufferedWriter(FileWriter(ioctl_log_path))
    if rows:
        for r in sorted(set(rows)):
            bw.write(r + "\r\n")
    else:
        bw.write("No IOCTLs decoded\r\n")
    bw.flush(); bw.close()
except Exception:
    pass

# --------------------- Physical memory / IO space checks --------------------
lines.append("[>] Scanning for physical memory / IO space patterns...")

def report_issue(kind, func, addr_str, detail, severity='High'):
    lines.append("[!] {}: {} in {} at {} :: {}".format(severity, kind, func.getName(), addr_str, detail))

physmem_strings = [r'\\Device\\PhysicalMemory']
physmem_api_list = [
    'ZwOpenSection', 'ZwMapViewOfSection',
    'MmCopyMemory', 'MmMapIoSpace', 'MmMapIoSpaceEx',
    'MmGetPhysicalAddress',
    'MmAllocateContiguousMemory', 'MmAllocateContiguousMemorySpecifyCache',
    'MmAllocatePagesForMdl', 'MmAllocatePagesForMdlEx',
    'MmProbeAndLockPages', 'MmMapLockedPagesSpecifyCache', 'MmGetSystemAddressForMdlSafe'
]

for func in currentProgram.getListing().getFunctions(True):
    dt = decompiled_text(func)
    if not dt:
        continue
    in_ioctl_ctx = is_ioctl_context_text(dt)

    # PhysicalMemory section usage
    for s in physmem_strings:
        if s in dt:
            addr = get_instr_addr_str_from_text_hit(func, dt.find(s))
            report_issue("PhysicalMemory section usage", func, addr,
                         "References '\\Device\\PhysicalMemory' (legacy physical mem access path)",
                         severity="High" if in_ioctl_ctx else "Medium")

    # MmCopyMemory(..., MM_COPY_MEMORY_PHYSICAL) ~ last arg == 1 (heuristic)
    if 'MmCopyMemory' in dt:
        call_addr = last_arg_is_const_one_heuristic(func, 'MmCopyMemory')
        if call_addr:
            detail = "MmCopyMemory with MM_COPY_MEMORY_PHYSICAL (arg=1)"
            if in_ioctl_ctx and looks_user_driven_expr(dt):
                detail += " and user-driven source/size indicators present"
            report_issue("Physical copy from/to PA", func, call_addr, detail,
                         severity="High" if in_ioctl_ctx else "Medium")

    # MmMapIoSpace(Ex) with risky size / no validation
    for api_name in ('MmMapIoSpaceEx', 'MmMapIoSpace'):
        for _, idx in find_calls_in_text(dt, api_name):
            addr = get_instr_addr_str_from_text_hit(func, idx)
            risky = looks_user_driven_expr(dt) and not nearby_has_validation(dt, idx)
            sev = "High" if (in_ioctl_ctx and risky) else ("Medium" if in_ioctl_ctx else "Low")
            # Try to extract some immediate (often Size or CacheType flags)
            imm = immediate_nearby_value(func, api_name, max_back=8)
            size_hint = ""
            if imm is not None and imm >= HEURISTIC_LARGE_MAP_SIZE:
                sev = "High"
                size_hint = " (size immediate appears large: {} bytes)".format(imm)
            report_issue("IO space mapping", func, addr,
                         "{} call; check PA/size origin and validation{}".format(api_name, size_hint),
                         severity=sev)

    # MDL -> UserMode mapping
    for _, idx in find_calls_in_text(dt, 'MmMapLockedPagesSpecifyCache'):
        addr = get_instr_addr_str_from_text_hit(func, idx)
        slice_txt = dt[idx:idx+200]
        usermap = ('UserMode' in slice_txt) or (', 1,' in slice_txt)
        sev = "High" if (in_ioctl_ctx and usermap) else ("Medium" if usermap else ("Medium" if in_ioctl_ctx else "Low"))
        report_issue("MDL mapped to UserMode", func, addr,
                     "MmMapLockedPagesSpecifyCache with UserMode (or 1) detected", severity=sev)

    # MmGetPhysicalAddress on likely user buffers
    if 'MmGetPhysicalAddress' in dt and looks_user_driven_expr(dt):
        addr = get_instr_addr_str_from_text_hit(func, dt.find('MmGetPhysicalAddress'))
        report_issue("User buffer -> physical address", func, addr,
                     "MmGetPhysicalAddress used with likely user-sourced VA",
                     severity="High" if in_ioctl_ctx else "Medium")

    # Port/register IO in IOCTL handlers (prefix matches)
    if in_ioctl_ctx:
        for prefix in ('READ_PORT_', 'WRITE_PORT_', 'READ_REGISTER_', 'WRITE_REGISTER_'):
            for name, idx in find_calls_in_text(dt, prefix):
                addr = get_instr_addr_str_from_text_hit(func, idx)
                sev = "High" if name.startswith('WRITE_') else "High"
                report_issue("Port/Register IO from IOCTL", func, addr,
                             "{} used; ensure whitelist, bounds and privilege checks".format(name), severity=sev)

# --------------------- General vuln heuristics (memory, overflow, ACL) -----
lines.append("[>] Scanning for general driver vuln patterns...")

allocation_names = ['ExAllocatePool', 'ExAllocatePoolWithTag', 'ExAllocatePool2']
string_copy_names = ['memcpy', 'memmove', 'RtlCopyMemory']
priv_guard_apis = ['SeSinglePrivilegeCheck', 'SeAccessCheck', 'ZwQueryInformationToken', 'IoIsSystemThread']

for func in currentProgram.getListing().getFunctions(True):
    dt = decompiled_text(func)
    if not dt:
        continue
    in_ioctl_ctx = is_ioctl_context_text(dt)

    # User-copy without obvious probe/length checks
    for name in string_copy_names:
        for _, idx in find_calls_in_text(dt, name):
            addr = get_instr_addr_str_from_text_hit(func, idx)
            # If user-driven data present and no validation near the call, warn.
            if looks_user_driven_expr(dt) and not nearby_has_validation(dt, idx):
                report_issue("User copy w/o validation", func, addr,
                             "{} appears near user-controlled buffer/size and lacks nearby validation".format(name),
                             severity="High" if in_ioctl_ctx else "Medium")

    # Allocations driven by user length without safe arithmetic helpers
    for an in allocation_names:
        for _, idx in find_calls_in_text(dt, an):
            addr = get_instr_addr_str_from_text_hit(func, idx)
            # If the function text references InputBufferLength and does not use Rtl*Add/Mult helpers nearby, warn.
            if looks_user_driven_expr(dt) and not nearby_has_validation(dt, idx):
                report_issue("Potential integer overflow in allocation", func, addr,
                             "{} may be sized from user input without safe arithmetic (Rtl*Add/Mult)".format(an),
                             severity="High" if in_ioctl_ctx else "Medium")

    # Privilege gating: sensitive operations in IOCTL path without privilege checks
    if in_ioctl_ctx:
        sensitive = any(k in dt for k in ['MmMapIoSpace', 'MmCopyMemory', 'ZwOpenSection', 'ZwMapViewOfSection',
                                          'READ_PORT_', 'WRITE_PORT_', 'READ_REGISTER_', 'WRITE_REGISTER_'])
        if sensitive:
            has_guard = any(api in dt for api in priv_guard_apis)
            if not has_guard:
                lines.append("[!] High: Missing privilege gate in {} :: Sensitive ops in IOCTL path without guards".format(func.getName()))

# ----------------------------- Finalize -------------------------------------
lines.append("")
lines.append("[>] Saved decoded IOCTLs log file to \"{}\"".format(ioctl_log_path))
lines.append("[+] Analysis Completed!")
lines.append("-----------------------------------------------")

auto_path = File.createTempFile(currentProgram.getName() + "-DriverBuddyReloaded_autoanalysis-", ".txt").getAbsolutePath()
try:
    bw = BufferedWriter(FileWriter(auto_path))
    bw.write("\r\n".join(lines))
    bw.flush(); bw.close()
except Exception:
    pass

lines.append("")
lines.append("[>] Saved Autoanalysis log file to \"{}\"".format(auto_path))

for l in lines:
    try:
        print(l)
    except Exception:
        pass
