#!/usr/bin/env python3
"""
Pure-Python MIPS32 Little-Endian Emulator for Wida HD80 (MStar SoC) firmware.
No external emulation libraries. Register-level UART detection.

Usage: python mips_emulator.py [firmware.bin] [--trace] [--max N]
"""

import struct
import sys
import re

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MASK32 = 0xFFFFFFFF

def s32(v):
    """Interpret as signed 32-bit."""
    v &= MASK32
    return v if v < 0x80000000 else v - 0x100000000

def sign_extend_16(v):
    """Sign-extend 16-bit immediate to 32-bit."""
    if v & 0x8000:
        return v | 0xFFFF0000
    return v

def sign_extend_8(v):
    if v & 0x80:
        return v | 0xFFFFFF00
    return v

def sign_extend_half(v):
    if v & 0x8000:
        return v | 0xFFFF0000
    return v


# ---------------------------------------------------------------------------
# MStar SoC Memory Map
# ---------------------------------------------------------------------------
# ROM (SPI Flash):  0xBFC00000  (physical 0x1FC00000), 4 MB
# RAM:              0x80000000  (physical 0x00000000), 32 MB
# KSEG1 RAM mirror: 0xA0000000  (physical 0x00000000), 32 MB
# MMIO (RIU):       0xBF000000  (physical 0x1F000000)
# MMIO (RIU ext):   0xBF200000  (physical 0x1F200000)
#
# MStar UART0 registers (RIU bank 0x0980):
#   TX data:   0xBF201300 / physical 0x1F201300
#   RX data:   0xBF201300
#   DLH/DLL:   0xBF201300 / 0xBF201308 (when DLAB=1)
#   IER:       0xBF201308
#   IIR/FCR:   0xBF201310
#   LCR:       0xBF201318
#   MCR:       0xBF201320
#   LSR:       0xBF201328  (bit5=THRE, bit6=TEMT — TX empty)
#   MSR:       0xBF201330

ROM_BASE   = 0x1FC00000
ROM_SIZE   = 4 * 1024 * 1024   # 4 MB
RAM_BASE   = 0x00000000
RAM_SIZE   = 128 * 1024 * 1024  # 128 MB
MMIO_BASE  = 0x1F000000
MMIO_END   = 0x1F300000

UART0_TX   = 0x1F201300
UART0_LSR  = 0x1F201328
BOOT_PROG  = 0x1F206700

# Exception vectors (physical)
EXCV_RESET = 0x1FC00000
EXCV_GENERAL = 0x00000180   # general exception in RAM (kseg0)
EXCV_BEV_GENERAL = 0x1FC00380  # BEV=1 general exception


# ---------------------------------------------------------------------------
# Register names (for tracing)
# ---------------------------------------------------------------------------
REG_NAMES = [
    "$zero","$at","$v0","$v1","$a0","$a1","$a2","$a3",
    "$t0","$t1","$t2","$t3","$t4","$t5","$t6","$t7",
    "$s0","$s1","$s2","$s3","$s4","$s5","$s6","$s7",
    "$t8","$t9","$k0","$k1","$gp","$sp","$fp","$ra",
]

CP0_NAMES = {
    0: "Index", 1: "Random", 2: "EntryLo0", 3: "EntryLo1",
    4: "Context", 5: "PageMask", 6: "Wired", 8: "BadVAddr",
    9: "Count", 10: "EntryHi", 11: "Compare", 12: "Status",
    13: "Cause", 14: "EPC", 15: "PRId", 16: "Config",
    17: "LLAddr", 18: "WatchLo", 19: "WatchHi",
    23: "Debug", 24: "DEPC", 25: "PerfCnt",
    26: "ErrCtl", 28: "TagLo", 29: "TagHi", 30: "ErrorEPC",
}


# ---------------------------------------------------------------------------
# CPU class
# ---------------------------------------------------------------------------

class MipsCPU:
    def __init__(self):
        # General-purpose registers
        self.gpr = [0] * 32
        self.pc = 0xBFC00000
        self.hi = 0
        self.lo = 0

        # CP0 registers: [32 regs][8 selects]
        self.cp0 = [[0]*8 for _ in range(32)]

        # Set PRId to something MStar-like
        self.cp0[15][0] = 0x00019556  # MIPS 34Kf
        # Config0
        self.cp0[16][0] = 0x80000082  # MIPS32r2, LE
        # Status: BEV=1 (boot exception vectors)
        self.cp0[12][0] = 0x00400004  # BEV=1, ERL=1

        # Instruction counter
        self.count = 0

    def get_reg(self, idx):
        return self.gpr[idx] & MASK32

    def set_reg(self, idx, val):
        if idx != 0:
            self.gpr[idx] = val & MASK32


# ---------------------------------------------------------------------------
# Memory subsystem
# ---------------------------------------------------------------------------

class Memory:
    def __init__(self):
        self.rom = bytearray(ROM_SIZE)
        self.ram = bytearray(RAM_SIZE)
        self.mmio = {}  # addr -> value (byte-level for flexibility)
        self.uart_output = []

    def _translate(self, vaddr):
        """Translate virtual address to physical by stripping MIPS kseg bits."""
        va = vaddr & MASK32
        if 0x80000000 <= va < 0xA0000000:
            return va & 0x1FFFFFFF  # kseg0: strip top 3 bits
        if 0xA0000000 <= va < 0xC0000000:
            return va & 0x1FFFFFFF  # kseg1: strip top 3 bits
        if va < 0x80000000:
            return va  # kuseg: identity (for user mode)
        # kseg2/kseg3 — treat as physical
        return va & 0x1FFFFFFF

    def read8(self, vaddr):
        pa = self._translate(vaddr)

        if ROM_BASE <= pa < ROM_BASE + ROM_SIZE:
            return self.rom[pa - ROM_BASE]
        if RAM_BASE <= pa < RAM_BASE + RAM_SIZE:
            return self.ram[pa - RAM_BASE]
        if MMIO_BASE <= pa < MMIO_END:
            return self._mmio_read(pa, 1)
        # Unmapped — return 0
        return 0

    def read16(self, vaddr):
        pa = self._translate(vaddr)
        if ROM_BASE <= pa < ROM_BASE + ROM_SIZE:
            off = pa - ROM_BASE
            if off + 2 <= len(self.rom):
                return struct.unpack_from('<H', self.rom, off)[0]
            return 0
        if RAM_BASE <= pa < RAM_BASE + RAM_SIZE:
            if pa - RAM_BASE + 2 <= len(self.ram):
                return struct.unpack_from('<H', self.ram, pa - RAM_BASE)[0]
            return 0
        if MMIO_BASE <= pa < MMIO_END:
            return self._mmio_read(pa, 2)
        return 0

    def read32(self, vaddr):
        pa = self._translate(vaddr)
        if ROM_BASE <= pa < ROM_BASE + ROM_SIZE:
            off = pa - ROM_BASE
            if off + 4 <= len(self.rom):
                return struct.unpack_from('<I', self.rom, off)[0]
            return 0
        if RAM_BASE <= pa < RAM_BASE + RAM_SIZE:
            if pa - RAM_BASE + 4 <= len(self.ram):
                return struct.unpack_from('<I', self.ram, pa - RAM_BASE)[0]
            return 0
        if MMIO_BASE <= pa < MMIO_END:
            return self._mmio_read(pa, 4)
        return 0

    def write8(self, vaddr, val):
        pa = self._translate(vaddr)
        val &= 0xFF
        if RAM_BASE <= pa < RAM_BASE + RAM_SIZE:
            self.ram[pa - RAM_BASE] = val
            return
        if MMIO_BASE <= pa < MMIO_END:
            self._mmio_write(pa, val, 1)
            return
        if ROM_BASE <= pa < ROM_BASE + ROM_SIZE:
            return  # ignore writes to ROM

    def write16(self, vaddr, val):
        pa = self._translate(vaddr)
        val &= 0xFFFF
        if RAM_BASE <= pa < RAM_BASE + RAM_SIZE:
            struct.pack_into('<H', self.ram, pa - RAM_BASE, val)
            return
        if MMIO_BASE <= pa < MMIO_END:
            self._mmio_write(pa, val, 2)
            return

    def write32(self, vaddr, val):
        pa = self._translate(vaddr)
        val &= MASK32
        if RAM_BASE <= pa < RAM_BASE + RAM_SIZE:
            struct.pack_into('<I', self.ram, pa - RAM_BASE, val)
            return
        if MMIO_BASE <= pa < MMIO_END:
            self._mmio_write(pa, val, 4)
            return
        if ROM_BASE <= pa < ROM_BASE + ROM_SIZE:
            return  # ignore writes to ROM

    # -- MMIO handlers --

    def _mmio_read(self, pa, size):
        # UART0 Line Status Register
        if pa == UART0_LSR or pa == UART0_LSR + 1:
            res = 0x60
            if hasattr(self, 'rx_queue') and self.rx_queue:
                res |= 0x01
            return res

        # UART0 RX
        if pa == UART0_TX:
            if hasattr(self, 'rx_queue') and self.rx_queue:
                return self.rx_queue.pop(0)
            return 0

        # Specific polling registers
        if pa == 0x1F202400:
            return self.mmio.get(pa, 0) | 0x8000 # Pretend bit 15 (init done) is set
            
        if pa == 0x1F2025C0:
            # We saw polling for bit 15 (0x8000), and later it checks bits 14:13 (0x6000).
            # To pass both, we can just return 0xE000 mask.
            return self.mmio.get(pa, 0) | 0xE000

        if pa == 0x1F203104:
            # Polled during early boot (wait bit 8) and during spi_rdc (wait bit 10)
            return self.mmio.get(pa, 0) | 0x0500

        if pa in (0x1F001050, 0x1F001054, 0x1F001058, 0x1F00105C):
            # U-Boot polling loops, waits for bit 0
            return self.mmio.get(pa, 0) | 0x0001

        # General case
        val = 0
        for i in range(size):
            val |= self.mmio.get(pa + i, 0) << (i * 8)
        return val & MASK32

    def _mmio_write(self, pa, val, size):
        # UART0 TX data register — capture the character
        if pa == UART0_TX and size <= 2:
            ch = val & 0xFF
            self.uart_output.append(ch)
            if not hasattr(self, 'uart_history'): self.uart_history = []
            self.uart_history.append(ch)
            if len(self.uart_history) > 1024: self.uart_history = self.uart_history[-1024:]
            
            # Check if U-Boot just printed 'Hit any key to stop autoboot: '
            if ch == ord(':'):
                out_str = bytes(self.uart_history[-60:]).decode('ascii', errors='ignore')
                if "autoboot" in out_str:
                    if getattr(self, 'bypass_autoboot', False):
                        if not hasattr(self, 'rx_queue'):
                            self.rx_queue = list(b"\r\n\r\ngo 0x80000224\r\n")

            if ch == 0x0A or ch == 0x0D or True: # Force flush on every character for real-time trace
                self._flush_uart()
                
            if ch == ord('\n'):
                text = bytes(self.uart_history).decode('ascii', errors='ignore')
                lines = text.replace('\r', '').split('\n')
                if len(lines) >= 2:
                    last_line = lines[-2].strip()
                    m = re.search(r'spi_rdc\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)\s+(0x[0-9A-Fa-f]+)', last_line)
                    if m:
                        try:
                            dst = int(m.group(1), 16)
                            src = int(m.group(2), 16)
                            sz = int(m.group(3), 16)
                            sys.stderr.write(f"\n[MAGIC] spi_rdc copy {hex(sz)} from ROM {hex(src)} to RAM {hex(dst)}\n")
                            pa_dst = self._translate(dst)
                            if 0 <= pa_dst < RAM_SIZE and 0 <= src < len(self.rom):
                                self.ram[pa_dst:pa_dst+sz] = self.rom[src:src+sz]
                        except Exception as e:
                            sys.stderr.write(f"\n[MAGIC] spi_rdc error: {e}\n")

            return

        # Boot progress register
        if pa == BOOT_PROG:
            sys.stderr.write(f"[BOOT STAGE] {val}\n")

        if 0x1F203100 <= pa <= 0x1F2031FC:
            sys.stderr.write(f"[BDMA] pa=0x{pa:08x} val=0x{val:08x} size={size}\n")


        # Store all MMIO writes
        for i in range(size):
            self.mmio[pa + i] = (val >> (i * 8)) & 0xFF

    def _flush_uart(self):
        if self.uart_output:
            try:
                text = bytes(self.uart_output).decode('ascii', errors='replace')
            except:
                text = ''.join(chr(c) if 32 <= c < 127 else '.' for c in self.uart_output)
            sys.stderr.write(text)
            sys.stderr.flush()
            self.uart_output.clear()

    def load_rom(self, data):
        n = min(len(data), ROM_SIZE)
        self.rom[:n] = data[:n]


# ---------------------------------------------------------------------------
# Instruction decoder & executor
# ---------------------------------------------------------------------------

class Emulator:
    def __init__(self, rom_data, trace=False, max_insns=0, bypass_autoboot=False):
        self.cpu = MipsCPU()
        self.mem = Memory()
        self.bypass_autoboot = bypass_autoboot
        self.mem.bypass_autoboot = bypass_autoboot
        self.mem.load_rom(rom_data)
        self.trace = trace
        self.max_insns = max_insns
        self.insn_count = 0
        self.running = True

        # For delay slot handling
        self.in_delay_slot = False
        self.next_pc = 0
        self.branch_taken = False

        # NOP sled detector
        self.consecutive_nops = 0

        # Polling loop breaker
        self._loop_pc = 0       # PC of last branch-back target
        self._loop_count = 0    # how many times we've looped
        self._loop_threshold = 64  # trips before auto-breaking

    def run(self):
        sys.stderr.write("Starting Emulation...\n")
        self.recent_pcs = [0] * 65536
        self.recent_pcs_idx = 0

        try:
            while self.running:
                self.step()
                if self.max_insns > 0 and self.insn_count >= self.max_insns:
                    sys.stderr.write(f"Max instruction count ({self.max_insns}) reached.\n")
                    break
        except KeyboardInterrupt:
            sys.stderr.write("Interrupted by user.\n")
            
        sys.stderr.write("Dumping trace to trace_log.txt...\n")
        with open("trace_log.txt", "w") as f:
            for i in range(65536):
                pc = self.recent_pcs[(self.recent_pcs_idx + i) & 0xFFFF]
                if pc != 0:
                    f.write(f"0x{pc:08x}\n")

        # Dump RAM for analysis
        with open("ram_dump.bin", "wb") as f:
            f.write(self.mem.ram)
        sys.stderr.write("RAM dumped to ram_dump.bin (128MB).\n")

        self.mem._flush_uart()
        sys.stderr.write("Emulation finished.\n")

    def step(self):
        cpu = self.cpu
        pc = cpu.pc & MASK32

        # U-Boot MsOS_GetSystemTime hook (at jr ra)
        if pc == 0x87617474:
            cpu.gpr[2] = (self.insn_count // 100) & MASK32

        # Inject Fast-forward for payload memcpy loop
        if pc == 0x80252540:
            fp = cpu.get_reg(30)
            dest = self.mem.read32(fp)
            src = self.mem.read32(fp + 4)
            end_dest = 0x80755fc0
            length = end_dest - dest
            if 0 < length < 10000000:
                sys.stderr.write(f"[HOOK] Fast-forwarding memcpy: src={hex(src)} dst={hex(dest)} len={hex(length)}\n")
                pa_dst = self.mem._translate(dest)
                pa_src = self.mem._translate(src)
                self.mem.ram[pa_dst:pa_dst+length] = self.mem.ram[pa_src:pa_src+length]
                self.mem.write32(fp, end_dest)
                self.mem.write32(fp + 4, src + length)
                cpu.pc = 0x80252584
                return

        # Inject Fast-forward for memset loop (BSS clearing)
        if pc == 0x80143820:
            a0 = cpu.get_reg(4)
            a3 = cpu.get_reg(7)
            if a0 < a3:
                pa_start = self.mem._translate(a0)
                length = a3 - a0
                if 0 < length < 100000000:
                    sys.stderr.write(f"[HOOK] Fast-forwarding memset 0: dst={hex(a0)}, len={hex(length)}\n")
                    # Set zeros directly
                    self.mem.ram[pa_start:pa_start + length] = bytearray(length)
                cpu.set_reg(4, a3)
                cpu.pc = 0x8014384c # Jump to bne branch target fail path
                return

        self.recent_pcs[self.recent_pcs_idx] = pc
        self.recent_pcs_idx = (self.recent_pcs_idx + 1) & 0xFFFF

        # Fetch
        insn = self.mem.read32(pc)
        self.insn_count += 1

        # Increment CP0 Count (fast-forward to bypass large udelay loops during boot)
        cpu.cp0[9][0] = (cpu.cp0[9][0] + 1000) & MASK32

        # NOP sled detection
        if insn == 0:
            self.consecutive_nops += 1
            if self.consecutive_nops > 16:
                sys.stderr.write(f">>> FATAL: NOP sled detected at PC=0x{pc:08x}. Halting.\n")
                sys.stderr.write("Registers:\n")
                for i in range(32):
                    sys.stderr.write(f"r{i:02d}: 0x{self.cpu.gpr[i]:08x}\n")
                self.running = False
                return
        else:
            self.consecutive_nops = 0

        # Trace
        if self.trace:
            self._trace_insn(pc, insn)

        # Decode
        op = (insn >> 26) & 0x3F
        rs = (insn >> 21) & 0x1F
        rt = (insn >> 16) & 0x1F
        rd = (insn >> 11) & 0x1F
        shamt = (insn >> 6) & 0x1F
        funct = insn & 0x3F
        imm16 = insn & 0xFFFF
        simm = sign_extend_16(imm16)
        target26 = insn & 0x03FFFFFF

        # Default: advance PC by 4
        advance_pc = True

        # ===== R-type (op=0) =====
        if op == 0x00:
            if funct == 0x00:    # SLL
                cpu.set_reg(rd, (cpu.get_reg(rt) << shamt) & MASK32)
            elif funct == 0x02:  # SRL
                cpu.set_reg(rd, (cpu.get_reg(rt) >> shamt) & MASK32)
            elif funct == 0x03:  # SRA
                v = s32(cpu.get_reg(rt))
                cpu.set_reg(rd, (v >> shamt) & MASK32)
            elif funct == 0x04:  # SLLV
                sh = cpu.get_reg(rs) & 0x1F
                cpu.set_reg(rd, (cpu.get_reg(rt) << sh) & MASK32)
            elif funct == 0x06:  # SRLV
                sh = cpu.get_reg(rs) & 0x1F
                cpu.set_reg(rd, (cpu.get_reg(rt) >> sh) & MASK32)
            elif funct == 0x07:  # SRAV
                sh = cpu.get_reg(rs) & 0x1F
                v = s32(cpu.get_reg(rt))
                cpu.set_reg(rd, (v >> sh) & MASK32)
            elif funct == 0x08:  # JR
                target = cpu.get_reg(rs) & MASK32
                self._do_branch(target)
                advance_pc = False
            elif funct == 0x09:  # JALR
                target = cpu.get_reg(rs) & MASK32
                cpu.set_reg(rd if rd != 0 else 31, (pc + 8) & MASK32)
                self._do_branch(target)
                advance_pc = False
            elif funct == 0x0A:  # MOVZ
                if cpu.get_reg(rt) == 0:
                    cpu.set_reg(rd, cpu.get_reg(rs))
            elif funct == 0x0B:  # MOVN
                if cpu.get_reg(rt) != 0:
                    cpu.set_reg(rd, cpu.get_reg(rs))
            elif funct == 0x0C:  # SYSCALL
                self._exception(8, pc)  # Syscall exception code = 8
                advance_pc = False
            elif funct == 0x0D:  # BREAK
                self._exception(9, pc)
                advance_pc = False
            elif funct == 0x0F:  # SYNC
                pass  # NOP for emulator
            elif funct == 0x10:  # MFHI
                cpu.set_reg(rd, cpu.hi)
            elif funct == 0x11:  # MTHI
                cpu.hi = cpu.get_reg(rs) & MASK32
            elif funct == 0x12:  # MFLO
                cpu.set_reg(rd, cpu.lo)
            elif funct == 0x13:  # MTLO
                cpu.lo = cpu.get_reg(rs) & MASK32
            elif funct == 0x18:  # MULT
                a = s32(cpu.get_reg(rs))
                b = s32(cpu.get_reg(rt))
                result = a * b
                cpu.lo = result & MASK32
                cpu.hi = (result >> 32) & MASK32
            elif funct == 0x19:  # MULTU
                a = cpu.get_reg(rs) & MASK32
                b = cpu.get_reg(rt) & MASK32
                result = a * b
                cpu.lo = result & MASK32
                cpu.hi = (result >> 32) & MASK32
            elif funct == 0x1A:  # DIV
                a = s32(cpu.get_reg(rs))
                b = s32(cpu.get_reg(rt))
                if b != 0:
                    # Python's integer division truncates toward -inf, MIPS truncates toward 0
                    q = int(a / b)  # truncate toward zero
                    r = a - q * b
                    cpu.lo = q & MASK32
                    cpu.hi = r & MASK32
            elif funct == 0x1B:  # DIVU
                a = cpu.get_reg(rs) & MASK32
                b = cpu.get_reg(rt) & MASK32
                if b != 0:
                    cpu.lo = (a // b) & MASK32
                    cpu.hi = (a % b) & MASK32
            elif funct == 0x20:  # ADD (trap on overflow — we ignore trap)
                cpu.set_reg(rd, (cpu.get_reg(rs) + cpu.get_reg(rt)) & MASK32)
            elif funct == 0x21:  # ADDU
                cpu.set_reg(rd, (cpu.get_reg(rs) + cpu.get_reg(rt)) & MASK32)
            elif funct == 0x22:  # SUB
                cpu.set_reg(rd, (cpu.get_reg(rs) - cpu.get_reg(rt)) & MASK32)
            elif funct == 0x23:  # SUBU
                cpu.set_reg(rd, (cpu.get_reg(rs) - cpu.get_reg(rt)) & MASK32)
            elif funct == 0x24:  # AND
                cpu.set_reg(rd, cpu.get_reg(rs) & cpu.get_reg(rt))
            elif funct == 0x25:  # OR
                cpu.set_reg(rd, cpu.get_reg(rs) | cpu.get_reg(rt))
            elif funct == 0x26:  # XOR
                cpu.set_reg(rd, cpu.get_reg(rs) ^ cpu.get_reg(rt))
            elif funct == 0x27:  # NOR
                cpu.set_reg(rd, (~(cpu.get_reg(rs) | cpu.get_reg(rt))) & MASK32)
            elif funct == 0x2A:  # SLT
                cpu.set_reg(rd, 1 if s32(cpu.get_reg(rs)) < s32(cpu.get_reg(rt)) else 0)
            elif funct == 0x2B:  # SLTU
                cpu.set_reg(rd, 1 if (cpu.get_reg(rs) & MASK32) < (cpu.get_reg(rt) & MASK32) else 0)
            elif funct == 0x30:  # TGE — trap (ignore)
                pass
            elif funct == 0x34:  # TEQ — trap (ignore)
                pass
            else:
                self._unimplemented(pc, insn, f"R-type funct=0x{funct:02x}")

        # ===== LWC1 (op=49, 0x31), LDC1 (op=53, 0x35) =====
        elif op in (0x31, 0x35):
            pass  # FPU load stubs

        # ===== SWC1 (op=57, 0x39), SDC1 (op=61, 0x3d) =====
        elif op in (0x39, 0x3d):
            pass  # FPU store stubs

        # ===== REGIMM (op=1): BLTZ, BGEZ, BLTZAL, BGEZAL =====
        elif op == 0x01:
            val_rs = s32(cpu.get_reg(rs))
            if rt == 0x00:    # BLTZ
                if val_rs < 0:
                    self._do_branch((pc + 4 + (simm << 2)) & MASK32)
                    advance_pc = False
                # else: fall through, advance_pc stays True (delay slot still runs)
                else:
                    self._do_branch_not_taken(pc)
                    advance_pc = False
            elif rt == 0x01:  # BGEZ
                if val_rs >= 0:
                    self._do_branch((pc + 4 + (simm << 2)) & MASK32)
                    advance_pc = False
                else:
                    self._do_branch_not_taken(pc)
                    advance_pc = False
            elif rt == 0x02:  # BLTZL
                if val_rs < 0:
                    self._do_branch((pc + 4 + (simm << 2)) & MASK32)
                    advance_pc = False
                else:
                    self._do_branch_not_taken_likely(pc)
                    advance_pc = False
            elif rt == 0x03:  # BGEZL
                if val_rs >= 0:
                    self._do_branch((pc + 4 + (simm << 2)) & MASK32)
                    advance_pc = False
                else:
                    self._do_branch_not_taken_likely(pc)
                    advance_pc = False
            elif rt == 0x10:  # BLTZAL
                cpu.set_reg(31, (pc + 8) & MASK32)
                if val_rs < 0:
                    self._do_branch((pc + 4 + (simm << 2)) & MASK32)
                    advance_pc = False
                else:
                    self._do_branch_not_taken(pc)
                    advance_pc = False
            elif rt == 0x11:  # BGEZAL (BAL when rs=0)
                cpu.set_reg(31, (pc + 8) & MASK32)
                if val_rs >= 0:
                    self._do_branch((pc + 4 + (simm << 2)) & MASK32)
                    advance_pc = False
                else:
                    self._do_branch_not_taken(pc)
                    advance_pc = False
            elif rt == 0x12:  # BLTZALL
                cpu.set_reg(31, (pc + 8) & MASK32)
                if val_rs < 0:
                    self._do_branch((pc + 4 + (simm << 2)) & MASK32)
                    advance_pc = False
                else:
                    self._do_branch_not_taken_likely(pc)
                    advance_pc = False
            elif rt == 0x13:  # BGEZALL
                cpu.set_reg(31, (pc + 8) & MASK32)
                if val_rs >= 0:
                    self._do_branch((pc + 4 + (simm << 2)) & MASK32)
                    advance_pc = False
                else:
                    self._do_branch_not_taken_likely(pc)
                    advance_pc = False
            else:
                self._unimplemented(pc, insn, f"REGIMM rt=0x{rt:02x}")

        # ===== J (op=2) =====
        elif op == 0x02:
            target = ((pc + 4) & 0xF0000000) | (target26 << 2)
            self._do_branch(target & MASK32)
            advance_pc = False

        # ===== JAL (op=3) =====
        elif op == 0x03:
            cpu.set_reg(31, (pc + 8) & MASK32)
            target = ((pc + 4) & 0xF0000000) | (target26 << 2)
            self._do_branch(target & MASK32)
            advance_pc = False

        # ===== BEQ (op=4) =====
        elif op == 0x04:
            if cpu.get_reg(rs) == cpu.get_reg(rt):
                self._do_branch((pc + 4 + (simm << 2)) & MASK32)
            else:
                self._do_branch_not_taken(pc)
            advance_pc = False

        # ===== BNE (op=5) =====
        elif op == 0x05:
            if cpu.get_reg(rs) != cpu.get_reg(rt):
                self._do_branch((pc + 4 + (simm << 2)) & MASK32)
            else:
                self._do_branch_not_taken(pc)
            advance_pc = False

        # ===== BLEZ (op=6) =====
        elif op == 0x06:
            if s32(cpu.get_reg(rs)) <= 0:
                self._do_branch((pc + 4 + (simm << 2)) & MASK32)
            else:
                self._do_branch_not_taken(pc)
            advance_pc = False

        # ===== BGTZ (op=7) =====
        elif op == 0x07:
            if s32(cpu.get_reg(rs)) > 0:
                self._do_branch((pc + 4 + (simm << 2)) & MASK32)
            else:
                self._do_branch_not_taken(pc)
            advance_pc = False

        # ===== BEQL (op=20, 0x14) =====
        elif op == 0x14:
            if cpu.get_reg(rs) == cpu.get_reg(rt):
                self._do_branch((pc + 4 + (simm << 2)) & MASK32)
            else:
                self._do_branch_not_taken_likely(pc)
            advance_pc = False

        # ===== BNEL (op=21, 0x15) =====
        elif op == 0x15:
            if cpu.get_reg(rs) != cpu.get_reg(rt):
                self._do_branch((pc + 4 + (simm << 2)) & MASK32)
            else:
                self._do_branch_not_taken_likely(pc)
            advance_pc = False

        # ===== BLEZL (op=22, 0x16) =====
        elif op == 0x16:
            if s32(cpu.get_reg(rs)) <= 0:
                self._do_branch((pc + 4 + (simm << 2)) & MASK32)
            else:
                self._do_branch_not_taken_likely(pc)
            advance_pc = False

        # ===== BGTZL (op=23, 0x17) =====
        elif op == 0x17:
            if s32(cpu.get_reg(rs)) > 0:
                self._do_branch((pc + 4 + (simm << 2)) & MASK32)
            else:
                self._do_branch_not_taken_likely(pc)
            advance_pc = False

        # ===== ADDI (op=8) =====
        elif op == 0x08:
            cpu.set_reg(rt, (cpu.get_reg(rs) + simm) & MASK32)

        # ===== ADDIU (op=9) =====
        elif op == 0x09:
            cpu.set_reg(rt, (cpu.get_reg(rs) + simm) & MASK32)

        # ===== SLTI (op=10) =====
        elif op == 0x0A:
            cpu.set_reg(rt, 1 if s32(cpu.get_reg(rs)) < s32(simm) else 0)

        # ===== SLTIU (op=11) =====
        elif op == 0x0B:
            cpu.set_reg(rt, 1 if (cpu.get_reg(rs) & MASK32) < (simm & MASK32) else 0)

        # ===== ANDI (op=12) =====
        elif op == 0x0C:
            cpu.set_reg(rt, cpu.get_reg(rs) & imm16)

        # ===== ORI (op=13) =====
        elif op == 0x0D:
            cpu.set_reg(rt, cpu.get_reg(rs) | imm16)

        # ===== XORI (op=14) =====
        elif op == 0x0E:
            cpu.set_reg(rt, cpu.get_reg(rs) ^ imm16)

        # ===== LUI (op=15) =====
        elif op == 0x0F:
            cpu.set_reg(rt, (imm16 << 16) & MASK32)

        # ===== COP0 (op=16) =====
        elif op == 0x10:
            cop_rs = rs  # the sub-opcode
            if cop_rs == 0x00:    # MFC0
                sel = insn & 0x07
                cpu.set_reg(rt, cpu.cp0[rd][sel] & MASK32)
            elif cop_rs == 0x04:  # MTC0
                sel = insn & 0x07
                cpu.cp0[rd][sel] = cpu.get_reg(rt) & MASK32
            elif cop_rs == 0x10:  # CO=1 instructions
                if funct == 0x18:  # ERET
                    status = cpu.cp0[12][0]
                    if status & 0x04:  # ERL
                        cpu.pc = cpu.cp0[30][0]  # ErrorEPC
                        cpu.cp0[12][0] &= ~0x04  # clear ERL
                    else:
                        cpu.pc = cpu.cp0[14][0]  # EPC
                        cpu.cp0[12][0] &= ~0x02  # clear EXL
                    advance_pc = False
                elif funct == 0x01:  # TLBR
                    pass
                elif funct == 0x02:  # TLBWI
                    pass
                elif funct == 0x06:  # TLBWR
                    pass
                elif funct == 0x08:  # TLBP
                    pass
                elif funct == 0x20:  # WAIT
                    pass
                else:
                    pass  # Ignore unknown CP0 CO
            elif cop_rs == 0x0B:  # MFMC0 (like DI/EI)
                # EI: rt=bit5 of instruction
                if (insn >> 5) & 1:  # EI
                    cpu.set_reg(rt, cpu.cp0[12][0])
                    cpu.cp0[12][0] |= 1
                else:  # DI
                    cpu.set_reg(rt, cpu.cp0[12][0])
                    cpu.cp0[12][0] &= ~1
            else:
                pass  # Ignore

        # ===== COP1 (op=17), COP2 (op=18) — stubs =====
        elif op in (0x11, 0x12):
            pass  # FPU / COP2 — ignore

        # ===== SPECIAL2 (op=28) =====
        elif op == 0x1C:
            if funct == 0x02:  # MUL (rd = rs * rt, low 32 bits)
                a = s32(cpu.get_reg(rs))
                b = s32(cpu.get_reg(rt))
                cpu.set_reg(rd, (a * b) & MASK32)
            elif funct == 0x00:  # MADD
                a = s32(cpu.get_reg(rs))
                b = s32(cpu.get_reg(rt))
                acc = (cpu.hi << 32) | cpu.lo
                acc = (acc + a * b) & 0xFFFFFFFFFFFFFFFF
                cpu.lo = acc & MASK32
                cpu.hi = (acc >> 32) & MASK32
            elif funct == 0x01:  # MADDU
                a = cpu.get_reg(rs) & MASK32
                b = cpu.get_reg(rt) & MASK32
                acc = (cpu.hi << 32) | cpu.lo
                acc = (acc + a * b) & 0xFFFFFFFFFFFFFFFF
                cpu.lo = acc & MASK32
                cpu.hi = (acc >> 32) & MASK32
            elif funct == 0x04:  # MSUB
                a = s32(cpu.get_reg(rs))
                b = s32(cpu.get_reg(rt))
                acc = (cpu.hi << 32) | cpu.lo
                acc = (acc - a * b) & 0xFFFFFFFFFFFFFFFF
                cpu.lo = acc & MASK32
                cpu.hi = (acc >> 32) & MASK32
            elif funct == 0x20:  # CLZ
                v = cpu.get_reg(rs) & MASK32
                if v == 0:
                    cpu.set_reg(rd, 32)
                else:
                    n = 0
                    while (v & 0x80000000) == 0:
                        n += 1
                        v <<= 1
                    cpu.set_reg(rd, n)
            elif funct == 0x21:  # CLO
                v = cpu.get_reg(rs) & MASK32
                n = 0
                while n < 32 and (v & 0x80000000):
                    n += 1
                    v = (v << 1) & MASK32
                cpu.set_reg(rd, n)
            else:
                self._unimplemented(pc, insn, f"SPECIAL2 funct=0x{funct:02x}")

        # ===== SPECIAL3 (op=31) — EXT, INS, etc =====
        elif op == 0x1F:
            if funct == 0x00:  # EXT: extract bit field
                pos = shamt
                sz = rd + 1
                cpu.set_reg(rt, (cpu.get_reg(rs) >> pos) & ((1 << sz) - 1))
            elif funct == 0x04:  # INS: insert bit field
                pos = shamt
                sz = rd - pos + 1
                mask = ((1 << sz) - 1) << pos
                v = cpu.get_reg(rt) & MASK32
                v = (v & ~mask) | ((cpu.get_reg(rs) << pos) & mask)
                cpu.set_reg(rt, v & MASK32)
            elif funct == 0x20:  # BSHFL
                bshfl_op = (insn >> 6) & 0x1F
                if bshfl_op == 0x10:  # SEB (sign extend byte)
                    cpu.set_reg(rd, sign_extend_8(cpu.get_reg(rt) & 0xFF) & MASK32)
                elif bshfl_op == 0x18:  # SEH (sign extend half)
                    cpu.set_reg(rd, sign_extend_half(cpu.get_reg(rt) & 0xFFFF) & MASK32)
                elif bshfl_op == 0x02:  # WSBH (word swap bytes within halfwords)
                    v = cpu.get_reg(rt) & MASK32
                    cpu.set_reg(rd, (((v & 0x00FF00FF) << 8) | ((v & 0xFF00FF00) >> 8)) & MASK32)
                else:
                    self._unimplemented(pc, insn, f"BSHFL op=0x{bshfl_op:02x}")
            elif funct == 0x3B:  # RDHWR
                # Hardware register reads — return 0
                cpu.set_reg(rt, 0)
            else:
                self._unimplemented(pc, insn, f"SPECIAL3 funct=0x{funct:02x}")

        # ===== LB (op=32) =====
        elif op == 0x20:
            addr = (cpu.get_reg(rs) + simm) & MASK32
            v = self.mem.read8(addr)
            cpu.set_reg(rt, sign_extend_8(v) & MASK32)

        # ===== LH (op=33) =====
        elif op == 0x21:
            addr = (cpu.get_reg(rs) + simm) & MASK32
            v = self.mem.read16(addr)
            cpu.set_reg(rt, sign_extend_half(v) & MASK32)

        # ===== LWL (op=34) — load word left =====
        elif op == 0x22:
            addr = (cpu.get_reg(rs) + simm) & MASK32
            aligned = addr & ~3
            word = self.mem.read32(aligned)
            byte_off = addr & 3
            cur = cpu.get_reg(rt) & MASK32
            if byte_off == 0:
                cur = (cur & 0x00FFFFFF) | ((word & 0xFF) << 24)
            elif byte_off == 1:
                cur = (cur & 0x0000FFFF) | ((word & 0xFFFF) << 16)
            elif byte_off == 2:
                cur = (cur & 0x000000FF) | ((word & 0xFFFFFF) << 8)
            elif byte_off == 3:
                cur = word
            cpu.set_reg(rt, cur & MASK32)

        # ===== LW (op=35) =====
        elif op == 0x23:
            addr = (cpu.get_reg(rs) + simm) & MASK32
            cpu.set_reg(rt, self.mem.read32(addr))

        # ===== LBU (op=36) =====
        elif op == 0x24:
            addr = (cpu.get_reg(rs) + simm) & MASK32
            cpu.set_reg(rt, self.mem.read8(addr))

        # ===== LHU (op=37) =====
        elif op == 0x25:
            addr = (cpu.get_reg(rs) + simm) & MASK32
            cpu.set_reg(rt, self.mem.read16(addr))

        # ===== LWR (op=38) — load word right =====
        elif op == 0x26:
            addr = (cpu.get_reg(rs) + simm) & MASK32
            aligned = addr & ~3
            word = self.mem.read32(aligned)
            byte_off = addr & 3
            cur = cpu.get_reg(rt) & MASK32
            if byte_off == 0:
                cur = word
            elif byte_off == 1:
                cur = (cur & 0xFF000000) | ((word >> 8) & 0x00FFFFFF)
            elif byte_off == 2:
                cur = (cur & 0xFFFF0000) | ((word >> 16) & 0x0000FFFF)
            elif byte_off == 3:
                cur = (cur & 0xFFFFFF00) | ((word >> 24) & 0x000000FF)
            cpu.set_reg(rt, cur & MASK32)

        # ===== SB (op=40) =====
        elif op == 0x28:
            addr = (cpu.get_reg(rs) + simm) & MASK32
            self.mem.write8(addr, cpu.get_reg(rt) & 0xFF)

        # ===== SH (op=41) =====
        elif op == 0x29:
            addr = (cpu.get_reg(rs) + simm) & MASK32
            self.mem.write16(addr, cpu.get_reg(rt) & 0xFFFF)

        # ===== SWL (op=42) =====
        elif op == 0x2A:
            addr = (cpu.get_reg(rs) + simm) & MASK32
            aligned = addr & ~3
            word = self.mem.read32(aligned)
            byte_off = addr & 3
            val = cpu.get_reg(rt) & MASK32
            if byte_off == 0:
                word = (word & 0xFFFFFF00) | ((val >> 24) & 0xFF)
            elif byte_off == 1:
                word = (word & 0xFFFF0000) | ((val >> 16) & 0xFFFF)
            elif byte_off == 2:
                word = (word & 0xFF000000) | ((val >> 8) & 0xFFFFFF)
            elif byte_off == 3:
                word = val
            self.mem.write32(aligned, word)

        # ===== SW (op=43) =====
        elif op == 0x2B:
            addr = (cpu.get_reg(rs) + simm) & MASK32
            self.mem.write32(addr, cpu.get_reg(rt))

        # ===== SWR (op=46) =====
        elif op == 0x2E:
            addr = (cpu.get_reg(rs) + simm) & MASK32
            aligned = addr & ~3
            word = self.mem.read32(aligned)
            byte_off = addr & 3
            val = cpu.get_reg(rt) & MASK32
            if byte_off == 0:
                word = val
            elif byte_off == 1:
                word = (word & 0x000000FF) | ((val << 8) & 0xFFFFFF00)
            elif byte_off == 2:
                word = (word & 0x0000FFFF) | ((val << 16) & 0xFFFF0000)
            elif byte_off == 3:
                word = (word & 0x00FFFFFF) | ((val << 24) & 0xFF000000)
            self.mem.write32(aligned, word)

        # ===== CACHE (op=47) =====
        elif op == 0x2F:
            pass  # Cache ops — NOP

        # ===== LL (op=48) — Load Linked =====
        elif op == 0x30:
            addr = (cpu.get_reg(rs) + simm) & MASK32
            cpu.set_reg(rt, self.mem.read32(addr))

        # ===== PREF (op=51) =====
        elif op == 0x33:
            pass  # Prefetch — NOP

        # ===== SC (op=56) — Store Conditional =====
        elif op == 0x38:
            addr = (cpu.get_reg(rs) + simm) & MASK32
            self.mem.write32(addr, cpu.get_reg(rt))
            cpu.set_reg(rt, 1)  # Always succeed

        else:
            self._unimplemented(pc, insn, f"op=0x{op:02x}")

        # Advance PC
        if advance_pc:
            if self.in_delay_slot:
                # We just executed the delay slot instruction
                cpu.pc = self.next_pc
                self.in_delay_slot = False
            else:
                cpu.pc = (pc + 4) & MASK32

    def _do_branch(self, target):
        """Set up a branch — execute delay slot, then jump."""
        cpu = self.cpu
        pc = cpu.pc & MASK32
        # Execute delay slot instruction first
        delay_pc = (pc + 4) & MASK32
        # Save state
        self.in_delay_slot = True
        self.next_pc = target
        cpu.pc = delay_pc

    def _do_branch_not_taken(self, pc):
        """Branch not taken — still need to execute delay slot, then continue."""
        self.in_delay_slot = True
        self.next_pc = (pc + 8) & MASK32
        self.cpu.pc = (pc + 4) & MASK32

    def _do_branch_not_taken_likely(self, pc):
        """Branch not taken for 'Likely' branches — skip the delay slot entirely."""
        self.in_delay_slot = False
        self.cpu.pc = (pc + 8) & MASK32

    def _exception(self, code, pc):
        """Trigger a MIPS exception."""
        cpu = self.cpu
        # Set Cause.ExcCode
        cpu.cp0[13][0] = (cpu.cp0[13][0] & ~0x7C) | ((code & 0x1F) << 2)
        # Save PC to EPC
        cpu.cp0[14][0] = pc & MASK32
        # Set EXL in Status
        cpu.cp0[12][0] |= 0x02

        # Determine vector
        status = cpu.cp0[12][0]
        if status & (1 << 22):  # BEV
            cpu.pc = 0xBFC00380
        else:
            cpu.pc = 0x80000180

    def _unimplemented(self, pc, insn, desc):
        sys.stderr.write(f"[UNIMPL] PC=0x{pc:08x} insn=0x{insn:08x} ({desc})\n")
        try:
            input("Paused at UNIMPL. Press Enter to continue...")
        except EOFError:
            pass

    def _trace_insn(self, pc, insn):
        cpu = self.cpu
        op = (insn >> 26) & 0x3F
        rs = (insn >> 21) & 0x1F
        rt = (insn >> 16) & 0x1F
        rd = (insn >> 11) & 0x1F
        shamt = (insn >> 6) & 0x1F
        funct = insn & 0x3F
        imm16 = insn & 0xFFFF
        simm = sign_extend_16(imm16)
        target26 = insn & 0x03FFFFFF

        mnem = ""
        args = ""

        if op == 0:
            fmap = {
                0x00: "sll", 0x02: "srl", 0x03: "sra", 0x04: "sllv",
                0x06: "srlv", 0x07: "srav", 0x08: "jr", 0x09: "jalr",
                0x0A: "movz", 0x0B: "movn", 0x0C: "syscall", 0x0D: "break",
                0x0F: "sync", 0x10: "mfhi", 0x11: "mthi", 0x12: "mflo",
                0x13: "mtlo", 0x18: "mult", 0x19: "multu", 0x1A: "div",
                0x1B: "divu", 0x20: "add", 0x21: "addu", 0x22: "sub",
                0x23: "subu", 0x24: "and", 0x25: "or", 0x26: "xor",
                0x27: "nor", 0x2A: "slt", 0x2B: "sltu", 0x30: "tge",
                0x34: "teq",
            }
            mnem = fmap.get(funct, f"r_0x{funct:02x}")
            if funct in (0x00, 0x02, 0x03):
                if insn == 0:
                    mnem = "nop"
                    args = ""
                else:
                    args = f"{REG_NAMES[rd]}, {REG_NAMES[rt]}, {shamt}"
            elif funct == 0x08:
                args = REG_NAMES[rs]
            elif funct == 0x09:
                args = f"{REG_NAMES[rd]}, {REG_NAMES[rs]}"
            elif funct in (0x10, 0x12):
                args = REG_NAMES[rd]
            elif funct in (0x11, 0x13):
                args = REG_NAMES[rs]
            elif funct in (0x0A, 0x0B):
                args = f"{REG_NAMES[rd]}, {REG_NAMES[rs]}, {REG_NAMES[rt]}"
            else:
                args = f"{REG_NAMES[rd]}, {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif op == 0x01:
            rmap = {0: "bltz", 1: "bgez", 0x10: "bltzal", 0x11: "bgezal"}
            mnem = rmap.get(rt, f"regimm_{rt}")
            target = (pc + 4 + (simm << 2)) & MASK32
            args = f"{REG_NAMES[rs]}, 0x{target:08x}"
        elif op == 0x02:
            mnem = "j"
            args = f"0x{(((pc+4)&0xF0000000)|(target26<<2)):08x}"
        elif op == 0x03:
            mnem = "jal"
            args = f"0x{(((pc+4)&0xF0000000)|(target26<<2)):08x}"
        elif op in (0x04, 0x05):
            mnem = "beq" if op == 4 else "bne"
            target = (pc + 4 + (simm << 2)) & MASK32
            args = f"{REG_NAMES[rs]}, {REG_NAMES[rt]}, 0x{target:08x}"
        elif op in (0x06, 0x07):
            mnem = "blez" if op == 6 else "bgtz"
            target = (pc + 4 + (simm << 2)) & MASK32
            args = f"{REG_NAMES[rs]}, 0x{target:08x}"
        elif op in (0x08, 0x09):
            mnem = "addi" if op == 8 else "addiu"
            args = f"{REG_NAMES[rt]}, {REG_NAMES[rs]}, {simm}"
        elif op == 0x0A:
            mnem = "slti"
            args = f"{REG_NAMES[rt]}, {REG_NAMES[rs]}, {simm}"
        elif op == 0x0B:
            mnem = "sltiu"
            args = f"{REG_NAMES[rt]}, {REG_NAMES[rs]}, {simm}"
        elif op == 0x0C:
            mnem = "andi"
            args = f"{REG_NAMES[rt]}, {REG_NAMES[rs]}, 0x{imm16:04x}"
        elif op == 0x0D:
            mnem = "ori"
            args = f"{REG_NAMES[rt]}, {REG_NAMES[rs]}, 0x{imm16:04x}"
        elif op == 0x0E:
            mnem = "xori"
            args = f"{REG_NAMES[rt]}, {REG_NAMES[rs]}, 0x{imm16:04x}"
        elif op == 0x0F:
            mnem = "lui"
            args = f"{REG_NAMES[rt]}, 0x{imm16:04x}"
        elif op == 0x10:
            if rs == 0:
                mnem = "mfc0"
                sel = insn & 7
                args = f"{REG_NAMES[rt]}, {REG_NAMES[rd]}, {sel}"
            elif rs == 4:
                mnem = "mtc0"
                sel = insn & 7
                args = f"{REG_NAMES[rt]}, {REG_NAMES[rd]}, {sel}"
            elif rs == 0x10 and funct == 0x18:
                mnem = "eret"
            else:
                mnem = f"cop0_0x{rs:02x}"
        elif op == 0x1C:
            fmap2 = {0x02: "mul", 0x00: "madd", 0x01: "maddu", 0x20: "clz", 0x21: "clo"}
            mnem = fmap2.get(funct, f"special2_0x{funct:02x}")
            args = f"{REG_NAMES[rd]}, {REG_NAMES[rs]}, {REG_NAMES[rt]}"
        elif op == 0x1F:
            if funct == 0:
                mnem = "ext"
            elif funct == 4:
                mnem = "ins"
            elif funct == 0x20:
                bsh = (insn >> 6) & 0x1F
                bmap = {0x10: "seb", 0x18: "seh", 0x02: "wsbh"}
                mnem = bmap.get(bsh, f"bshfl_0x{bsh:02x}")
            else:
                mnem = f"special3_0x{funct:02x}"
            args = f"{REG_NAMES[rt]}, {REG_NAMES[rs]}"
        elif op in (0x20, 0x21, 0x23, 0x24, 0x25):
            lmap = {0x20: "lb", 0x21: "lh", 0x23: "lw", 0x24: "lbu", 0x25: "lhu"}
            mnem = lmap[op]
            addr = (cpu.get_reg(rs) + simm) & MASK32
            args = f"{REG_NAMES[rt]}, {simm}({REG_NAMES[rs]})  # [0x{addr:08x}]"
        elif op in (0x22, 0x26):
            mnem = "lwl" if op == 0x22 else "lwr"
            args = f"{REG_NAMES[rt]}, {simm}({REG_NAMES[rs]})"
        elif op in (0x28, 0x29, 0x2B):
            smap = {0x28: "sb", 0x29: "sh", 0x2B: "sw"}
            mnem = smap[op]
            addr = (cpu.get_reg(rs) + simm) & MASK32
            val = cpu.get_reg(rt) & MASK32
            args = f"{REG_NAMES[rt]}, {simm}({REG_NAMES[rs]})  # [0x{addr:08x}] = 0x{val:08x}"
        elif op in (0x2A, 0x2E):
            mnem = "swl" if op == 0x2A else "swr"
            args = f"{REG_NAMES[rt]}, {simm}({REG_NAMES[rs]})"
        elif op == 0x2F:
            mnem = "cache"
            args = f"0x{rt:02x}, {simm}({REG_NAMES[rs]})"
        elif op == 0x30:
            mnem = "ll"
            args = f"{REG_NAMES[rt]}, {simm}({REG_NAMES[rs]})"
        elif op == 0x33:
            mnem = "pref"
            args = f"{rt}, {simm}({REG_NAMES[rs]})"
        elif op == 0x38:
            mnem = "sc"
            args = f"{REG_NAMES[rt]}, {simm}({REG_NAMES[rs]})"
        else:
            mnem = f"op_0x{op:02x}"

        line = f"0x{pc:08x}: {mnem}\t{args}"
        sys.stderr.write(f">>> [PC=0x{pc:08x} RA=0x{cpu.get_reg(31):08x} #{self.insn_count}] {line}\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Wida HD80 MIPS Emulator")
    parser.add_argument("firmware", nargs="?", default="Wida_HD80.bin",
                        help="Path to firmware binary (default: Wida_HD80.bin)")
    parser.add_argument("--trace", action="store_true",
                        help="Enable instruction trace to stderr")
    parser.add_argument("--max", type=int, default=5000000,
                        help="Max instructions to execute (default: 5M)")
    args = parser.parse_args()

    with open(args.firmware, "rb") as f:
        rom_data = f.read()

    sys.stderr.write(f"Loaded {len(rom_data)} bytes from {args.firmware}\n")

    emu = Emulator(rom_data, trace=args.trace, max_insns=args.max)
    emu.run()

    # Print summary
    sys.stderr.write(f"\n=== Emulation Summary ===\n")
    sys.stderr.write(f"Instructions executed: {emu.insn_count}\n")
    sys.stderr.write(f"Final PC: 0x{emu.cpu.pc:08x}\n")

    # Print any remaining UART output
    if emu.mem.uart_output:
        emu.mem._flush_uart()

    # Print captured UART as summary
    sys.stderr.write(f"\n=== UART Output ===\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
