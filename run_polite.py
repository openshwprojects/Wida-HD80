import time
import sys
import threading
from mips_emulator import Emulator, ROM_SIZE, RAM_SIZE

def main():
    rom_data = open('Wida_HD80.bin', 'rb').read()
    emu = Emulator(rom_data, trace=False, max_insns=60000000, bypass_autoboot=True)
    
    # Load decompressed payload directly into RAM to bypass slow LZMA decompression
    dec_payload = open('decompressed_payload.bin', 'rb').read()
    start_addr = 0x180
    emu.mem.ram[start_addr:start_addr+len(dec_payload)] = dec_payload

    # Run directly
    emu.run()
    print(f"Final PC: 0x{emu.cpu.pc:08x}, insns: {emu.insn_count}", file=sys.stderr)

if __name__ == '__main__':
    main()
