# Ghidra 'Driver Buddy Revolutions' 
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
from ghidra.util.task import ConsoleTaskMonitor

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

# --- IOCTL table header (ASCII-only) ---
IOCTL_TABLE_HEADER = (
    "Address               | IOCTL Code | Device                           DeviceId | Function | Method              MethodId | Access"
)
IOCTL_TABLE_UNDERLINE = "-" * len(IOCTL_TABLE_HEADER)

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

# ----------------------------- Pooltags (improved) ----------------------
lines.append("[>] Searching for `Pooltags`...")

def _looks_printable_ascii(tag_str):
    return all(32 <= ord(ch) <= 126 for ch in tag_str)

def _decode_pooltag(val):
    # Convert 0xAABBCCDD to 'DDCCBBAA' bytes -> string
    v = val & 0xFFFFFFFF
    bs = [(v >> (8*i)) & 0xFF for i in range(4)]  # little-endian byte order as used by Windows pool tags
    s = ''.join(chr(b) for b in bs)
    return s

def _likely_pooltag_dword(val):
    s = _decode_pooltag(val)
    if not _looks_printable_ascii(s):
        return False
    # Require at least 2 alnum characters to reduce noise
    alnum = sum(ch.isalnum() for ch in s)
    return alnum >= 2

def _collect_pooltags():
    tags = {}  # tag -> set(callers)
    listing = currentProgram.getListing()
    alloc_names = ['ExAllocatePool', 'ExAllocatePoolWithTag', 'ExAllocatePool2', 'ExFreePoolWithTag']
    for func in listing.getFunctions(True):
        fname = func.getName()
        try:
            insns = [i for i in listing.getInstructions(func.getBody(), True)]
        except Exception:
            continue
        for idx, instr in enumerate(insns):
            if not is_call_to(instr, alloc_names):
                continue
            # walk backward up to ~8 instructions to find a 32-bit immediate that looks like a tag
            for j in range(max(0, idx-8), idx):
                ins = insns[j]
                try:
                    for opi in range(ins.getNumOperands()):
                        sc = ins.getScalar(opi)
                        if sc is None:
                            continue
                        val = sc.getValue() & 0xFFFFFFFF
                        if _likely_pooltag_dword(val):
                            tag = _decode_pooltag(val)
                            # trim non-printables to be safe
                            tag = ''.join(ch if 32 <= ord(ch) <= 126 else '.' for ch in tag)
                            if tag not in tags:
                                tags[tag] = set()
                            tags[tag].add(fname)
                except Exception:
                    pass
    return tags

_pooltags = _collect_pooltags()

if _pooltags:
    drv = currentProgram.getName()
    for tag in sorted(_pooltags.keys()):
        callers = sorted(_pooltags[tag])
        lines.append("  - {0} - {1} - Called by: {2}".format(tag, drv, ", ".join(callers)))
else:
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

# =============================================================================
# =============== NEW IOCTL DISCOVERY (dispatch/regex approach) ===============
# =============================================================================

def _extract_function_name_from_line(line):
    # FUN_XXXXXXXX first
    m = re.search(r'(FUN_[0-9a-fA-F]+)', line)
    if m:
        return m.group(1)
    # or an assignment to a named function
    m = re.search(r'=\s*&?([a-zA-Z_][a-zA-Z0-9_]*)\s*;', line)
    if m:
        return m.group(1)
    return None

def _resolve_fun_name_to_function(fun_name):
    """
    Accepts either 'FUN_XXXXXXXX' or a symbol name; returns a Ghidra Function or None.
    """
    fm = currentProgram.getFunctionManager()
    if fun_name.startswith("FUN_"):
        try:
            addr = currentProgram.getAddressFactory().getAddress(fun_name[4:])
            return fm.getFunctionAt(addr)
        except Exception:
            return None
    # try by name
    try:
        for f in fm.getFunctions(True):
            if f.getName() == fun_name:
                return f
    except Exception:
        pass
    return None

def _find_dispatch_routines():
    """
    Find IRP_MJ_DEVICE_CONTROL dispatch routines by scanning decompiled C for:
      - (param_X + 0xe0) = ...
      - MajorFunction[0xe] / MajorFunction[14]
    Returns a list of Ghidra Function objects (deduped).
    """
    fm = currentProgram.getFunctionManager()
    routines = []
    seen = set()

    patterns = [
        r'\(param_[1-9] \+ 0xe0\)\s*=',
        r'MajorFunction\[0xe\]',
        r'MajorFunction\[14\]'
    ]

    for f in fm.getFunctions(True):
        dt = decompiled_text(f)
        if not dt:
            continue
        for line in dt.splitlines():
            for pat in patterns:
                if re.search(pat, line):
                    name = _extract_function_name_from_line(line)
                    if not name:
                        continue
                    tgt = _resolve_fun_name_to_function(name)
                    if tgt and tgt.getEntryPoint().toString() not in seen:
                        seen.add(tgt.getEntryPoint().toString())
                        routines.append(tgt)
    return routines

def _find_ioctls_in_decompiled_text(c_code):
    """
    Find IOCTL hex constants in decompiled C text (>= 0x200000 typical 3rd-party range).
    """
    ioctls = set()
    if not c_code:
        return []
    normalized = re.sub(r'\s+', ' ', c_code)

    patterns = [
        r'case\s+0x([0-9A-Fa-f]+)\s*:',
        r'ioControlCode\s*==\s*0x([0-9A-Fa-f]+)',
        r'(?:if|else if)\s*\(\s*(?:\([^)]*\))?\s*(?:iVar\d+|uVar\d+|\w+)\s*==\s*0x([0-9A-Fa-f]+)',
        r'(?:\(\s*)+(?:iVar\d+|uVar\d+|\w+)\s*==\s*0x([0-9A-Fa-f]+)(?:\s*\))+',
        r'(?:iVar\d+|uVar\d+|\w+)\s*==\s*0x([0-9A-Fa-f]+)',
        r'\(\s*(?:\([^)]*\)\s*&&\s*)*[^)]*==\s*0x([0-9A-Fa-f]+)',
        r'else\s*{[^}]*==\s*0x([0-9A-Fa-f]+)[^}]*}',
        r'IOCTL_[A-Z_]+\s*=\s*0x([0-9A-Fa-f]+)',
        r'#define\s+IOCTL_[A-Z_]+\s+0x([0-9A-Fa-f]+)'
    ]

    for pat in patterns:
        try:
            for m in re.finditer(pat, normalized, re.IGNORECASE | re.MULTILINE | re.DOTALL):
                val = int(m.group(1), 16)
                if val >= 0x200000 and plausible_ioctl(val):
                    ioctls.add(val & 0xFFFFFFFF)
        except Exception:
            pass
    return sorted(ioctls)

# ----------------------------- IOCTL discovery -----------------------------
lines.append("[>] Searching for IOCTLs found by analysis...")
rows = []
seen = set()

dispatch_funcs = _find_dispatch_routines()

for df in dispatch_funcs:
    try:
        c_text = decompiled_text(df)
        codes = _find_ioctls_in_decompiled_text(c_text)
        for code in codes:
            addr = find_compare_addresses_for_constant(df, code) or df.getEntryPoint().toString()
            key = (addr, code)
            if key in seen:
                continue
            row = fmt_ioctl_row(addr, code)
            if row:
                rows.append(row)
                seen.add(key)
    except Exception:
        pass

# ----------------------------- Fallback: scan all funcs --------------------
# Many drivers inline or obfuscate dispatch registration; as a fallback,
# scan every decompiled function for IOCTL-like constants and record them.
for f in currentProgram.getListing().getFunctions(True):
    try:
        c_text = decompiled_text(f)
        codes = _find_ioctls_in_decompiled_text(c_text)
        if not codes:
            continue
        for code in codes:
            addr = find_compare_addresses_for_constant(f, code) or f.getEntryPoint().toString()
            key = (addr, code)
            if key in seen:
                continue
            row = fmt_ioctl_row(addr, code)
            if row:
                rows.append(row)
                seen.add(key)
    except Exception:
        pass

# ----- Header-only change: show a table header before rows -----
if rows:
    lines.append("")
    lines.append("[>] Decoded IOCTLs:")
    lines.append(IOCTL_TABLE_HEADER)
    lines.append(IOCTL_TABLE_UNDERLINE)
    for r in sorted(set(rows)):
        lines.append(r)
else:
    lines.append("  - (none detected)")

# Save decoded IOCTLs log (include the same header)
ioctl_log_path = File.createTempFile(currentProgram.getName() + "-IOCTLs-", ".txt").getAbsolutePath()
try:
    bw = BufferedWriter(FileWriter(ioctl_log_path))
    if rows:
        bw.write(IOCTL_TABLE_HEADER + "\r\n")
        bw.write(IOCTL_TABLE_UNDERLINE + "\r\n")
        for r in sorted(set(rows)):
            bw.write(r + "\r\n")
    else:
        bw.write("No IOCTLs decoded\r\n")
    bw.flush(); bw.close()
except Exception:
    pass

# --------------------- Physical memory / IO space checks --------------------
lines.append("\n[>] Scanning for physical memory / IO space patterns...")

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
                sev = "High"  # writes and reads are both sensitive without gating
                report_issue("Port/Register IO from IOCTL", func, addr,
                             "{} used; ensure whitelist, bounds and privilege checks".format(name), severity=sev)

# --------------------- General vuln heuristics (memory, overflow, ACL) -----
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

    # (ORIGINAL) User-copy without obvious probe/length checks
    for name in string_copy_names:
        for _, idx in find_calls_in_text(dt, name):
            addr = get_instr_addr_str_from_text_hit(func, idx)
            if looks_user_driven_expr(dt) and not nearby_has_validation(dt, idx):
                lines.append("[!] {}: {} in {} at {} :: {}".format(
                    "High" if in_ioctl_ctx else "Medium",
                    "User copy w/o validation",
                    func.getName(),
                    addr,
                    "{} appears near user-controlled buffer/size and lacks nearby validation".format(name)
                ))

    # (ORIGINAL) Allocations driven by user length without safe arithmetic helpers
    for an in allocation_names:
        for _, idx in find_calls_in_text(dt, an):
            addr = get_instr_addr_str_from_text_hit(func, idx)
            if looks_user_driven_expr(dt) and not nearby_has_validation(dt, idx):
                lines.append("[!] {}: {} in {} at {} :: {}".format(
                    "High" if in_ioctl_ctx else "Medium",
                    "Potential integer overflow in allocation",
                    func.getName(),
                    addr,
                    "{} may be sized from user input without safe arithmetic (Rtl*Add/Mult)".format(an)
                ))

    # (ORIGINAL) Privilege gating: sensitive operations in IOCTL path without privilege checks
    if in_ioctl_ctx:
        sensitive = any(k in dt for k in ['MmMapIoSpace', 'MmCopyMemory', 'ZwOpenSection', 'ZwMapViewOfSection',
                                          'READ_PORT_', 'WRITE_PORT_', 'READ_REGISTER_', 'WRITE_REGISTER_'])
        if sensitive:
            has_guard = any(api in dt for api in priv_guard_apis)
            if not has_guard:
                lines.append("[!] High: Missing privilege gate in {} :: Sensitive ops in IOCTL path without guards".format(func.getName()))

# ===================== NEW: POPKORN-style deep checks (High/Critical only) =====================
# Conservative p-code/SSA taint from IOCTL user sources to dangerous sinks, with rationale.

# Local (section-scoped) config to avoid altering globals
_DEEP_STRING_COPIES = ['memcpy','memmove','RtlCopyMemory','RtlMoveMemory']
_DEEP_DANG_STR = ['strcpy','wcscpy','strcat','sprintf','swprintf']
_DEEP_ALLOC = ['ExAllocatePool','ExAllocatePoolWithTag','ExAllocatePool2']
_DEEP_PHYS = ['ZwOpenSection','ZwMapViewOfSection','MmCopyMemory','MmMapIoSpace','MmMapIoSpaceEx','MmGetPhysicalAddress']
_DEEP_PORT_PREFIXES = ('READ_PORT_','WRITE_PORT_','READ_REGISTER_','WRITE_REGISTER_')
_DEEP_VALIDATION = ['ProbeForRead','ProbeForWrite','MmIsAddressValid']
_DEEP_SAFE_ARITH = ['RtlULongAdd','RtlULongLongAdd','RtlULongSub','RtlULongLongSub','RtlULongMult','RtlULongLongMult','RtlSizeTAdd','RtlSizeTMult']
_DEEP_USER_SEEDS = [
    'Parameters.DeviceIoControl.InputBufferLength',
    'Parameters.DeviceIoControl.OutputBufferLength',
    'Parameters.DeviceIoControl.Type3InputBuffer',
    'Irp->AssociatedIrp.SystemBuffer',
    'Irp->UserBuffer',
    'MdlAddress'
]

def _deep_is_port_or_reg(name):
    for p in _DEEP_PORT_PREFIXES:
        if name and name.startswith(p):
            return True
    return False

def _deep_hf(func):
    try:
        r = decompile_func(func)
        if r and r.getHighFunction():
            return r.getHighFunction()
    except Exception:
        pass
    return None

def _deep_seed_user_taint(hf):
    seeds = []
    it = hf.getPcodeOps()
    while it.hasNext():
        op = it.next()
        for v in op.getInputs():
            try:
                h = v.getHigh()
                nm = h.getName() if h else ''
                if nm and any(k in nm for k in _DEEP_USER_SEEDS):
                    seeds.append(v)
            except Exception:
                pass
    return seeds

def _deep_taint_walk(hf, seeds):
    tainted = set(seeds)
    changed = True
    while changed:
        changed = False
        it = hf.getPcodeOps()
        while it.hasNext():
            op = it.next()
            opc = op.getOpcode()
            # Forward-propagate through common ops
            if opc in (PcodeOp.COPY, PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT,
                       PcodeOp.PTRADD, PcodeOp.PTRSUB, PcodeOp.CAST, PcodeOp.SEXT, PcodeOp.ZEXT):
                if any(inp in tainted for inp in op.getInputs()):
                    outv = op.getOutput()
                    if outv and outv not in tainted:
                        tainted.add(outv); changed = True
            elif opc == PcodeOp.CALL:
                # Conservative: any tainted input -> taint output (if present)
                if any(inp in tainted for inp in op.getInputs()):
                    outv = op.getOutput()
                    if outv and outv not in tainted:
                        tainted.add(outv); changed = True
    return tainted

def _deep_call_name_from_op(op):
    try:
        callee_vn = op.getInputs()[0]
        h = callee_vn.getHigh()
        if h and h.getSymbol():
            return h.getSymbol().getName()
    except Exception:
        pass
    return None

def _deep_has_validation_near(dt, idx):
    # Reuse existing utility but with added safe-arith list
    if nearby_has_validation(dt, idx):
        return True
    window = 300
    s = max(0, idx - window); e = min(len(dt), idx + window)
    chunk = dt[s:e]
    return any(api in chunk for api in _DEEP_SAFE_ARITH)

# Walk all functions again for deep taint to sinks
for func in currentProgram.getListing().getFunctions(True):
    dt = decompiled_text(func)
    if not dt:
        continue
    in_ioctl_ctx = is_ioctl_context_text(dt)

    hf = _deep_hf(func)
    if not hf:
        continue

    # Heuristic: immediately flag METHOD_NEITHER / UserBuffer usage without probes in IOCTL path
    if in_ioctl_ctx and (('Parameters.DeviceIoControl.Type3InputBuffer' in dt) or ('Irp->UserBuffer' in dt)):
        has_probe = any(v in dt for v in _DEEP_VALIDATION) or ('__try' in dt or 'try {' in dt)
        if not has_probe:
            sev = "Critical" if 'Type3InputBuffer' in dt else "High"
            lines.append("[!] {}: Direct user pointer access in {} at {} :: {}"
                         .format(sev, func.getName(), func.getEntryPoint().toString(),
                                 "Type3InputBuffer/Irp->UserBuffer used without ProbeForRead/Write or SEH guard"))
            lines.append("    Rationale: METHOD_NEITHER/user pointer lets kernel touch arbitrary user VA; missing probes/guards makes this exploitable.")

    seeds = _deep_seed_user_taint(hf)
    if not seeds:
        continue

    tainted = _deep_taint_walk(hf, seeds)

    # Scan p-code calls (sinks)
    it = hf.getPcodeOps()
    while it.hasNext():
        op = it.next()
        if op.getOpcode() != PcodeOp.CALL:
            continue

        callee = _deep_call_name_from_op(op)
        args = list(op.getInputs())[1:]  # skip target (slot 0)
        tainted_idxs = [i for i, a in enumerate(args) if a in tainted]
        call_addr = op.getSeqnum().getTarget().toString()

        # memcpy/memmove family with tainted pointer/length
        if callee in _DEEP_STRING_COPIES and tainted_idxs and in_ioctl_ctx:
            idx_in_text = dt.find(callee) if callee else -1
            if idx_in_text == -1 or not _deep_has_validation_near(dt, idx_in_text):
                lines.append("[!] High: User copy without validation in {} at {} :: {}".format(
                    func.getName(), call_addr, callee))
                lines.append("    Rationale: tainted src/len reaches {} from IOCTL path without nearby Probe/length checks; overflow/info leak risk."
                             .format(callee))

        # strcpy/strcat/sprintf family with tainted data
        if callee in _DEEP_DANG_STR and tainted_idxs and in_ioctl_ctx:
            lines.append("[!] High: Dangerous string op with user data in {} at {} :: {}".format(
                func.getName(), call_addr, callee))
            lines.append("    Rationale: {} with user-controlled input in kernel context can overflow fixed buffers.".format(callee))

        # Pool allocation sized by tainted value without safe arithmetic
        if callee in _DEEP_ALLOC and tainted_idxs and in_ioctl_ctx:
            idx_in_text = dt.find(callee)
            has_safe_arith = any(api in dt for api in _DEEP_SAFE_ARITH)
            if not has_safe_arith:
                lines.append("[!] High: Potential integer overflow in allocation in {} at {} :: {}".format(
                    func.getName(), call_addr, callee))
                lines.append("    Rationale: allocation size derived from user length without Rtl*Add/Mult/SizeT guards -> wrap then overflow on copy.")

        # Physical memory / IO mapping / physical copy with tainted args
        if callee in _DEEP_PHYS and tainted_idxs and in_ioctl_ctx:
            sev = "Critical" if callee in ('MmCopyMemory','MmMapIoSpace','MmMapIoSpaceEx') else "High"
            lines.append("[!] {}: Physical/IO access with user data in {} at {} :: {}".format(
                sev, func.getName(), call_addr, callee))
            lines.append("    Rationale: user-controlled PA/size drives {}; enables arbitrary physical/MMIO access.".format(callee))

        # MDL -> UserMode mapping with tainted args
        if callee == 'MmMapLockedPagesSpecifyCache' and tainted_idxs and in_ioctl_ctx and ('UserMode' in dt):
            lines.append("[!] High: MDL mapped to UserMode (user-influenced) in {} at {} :: MmMapLockedPagesSpecifyCache".format(
                func.getName(), call_addr))
            lines.append("    Rationale: user-controlled pages mapped to user mode from IOCTL path; kernel memory leak/write primitive.")

        # Port/Register I/O with tainted args
        if _deep_is_port_or_reg(callee) and tainted_idxs and in_ioctl_ctx:
            lines.append("[!] High: Port/Register I/O with user data in {} at {} :: {}".format(
                func.getName(), call_addr, callee))
            lines.append("    Rationale: tainted values reach hardware access routine from IOCTL path; device state corruption possible.")

    # Missing privilege gates around sensitive operations (rationale version; keep original too)
    sensitive_txt = any(k in dt for k in ['MmMapIoSpace','MmCopyMemory','ZwOpenSection','ZwMapViewOfSection']) or \
                    any(p in dt for p in _DEEP_PORT_PREFIXES)
    if in_ioctl_ctx and sensitive_txt and not any(api in dt for api in priv_guard_apis):
        lines.append("[!] High: Missing privilege gate in {} at {} :: Sensitive ops reachable from IOCTL".format(
            func.getName(), func.getEntryPoint().toString()))
        lines.append("    Rationale: no Se*/AccessCheck/Token validation near sensitive memory/IO operations; unprivileged callers may reach dangerous code paths.")
# =================== END NEW: POPKORN-style deep checks (High/Critical) ===================
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
            if looks_user_driven_expr(dt) and not nearby_has_validation(dt, idx):
                lines.append("[!] {}: {} in {} at {} :: {}".format(
                    "High" if in_ioctl_ctx else "Medium",
                    "User copy w/o validation",
                    func.getName(),
                    addr,
                    "{} appears near user-controlled buffer/size and lacks nearby validation".format(name)
                ))

    # Allocations driven by user length without safe arithmetic helpers
    for an in allocation_names:
        for _, idx in find_calls_in_text(dt, an):
            addr = get_instr_addr_str_from_text_hit(func, idx)
            if looks_user_driven_expr(dt) and not nearby_has_validation(dt, idx):
                lines.append("[!] {}: {} in {} at {} :: {}".format(
                    "High" if in_ioctl_ctx else "Medium",
                    "Potential integer overflow in allocation",
                    func.getName(),
                    addr,
                    "{} may be sized from user input without safe arithmetic (Rtl*Add/Mult)".format(an)
                ))

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

auto_path = File.createTempFile(currentProgram.getName() + "-DriverBuddyRevolutions_autoanalysis-", ".txt").getAbsolutePath()
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
