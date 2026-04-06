import time
import sys
import threading
from mips_emulator import Emulator, ROM_SIZE, RAM_SIZE

def main():
    rom_data = open('Wida_HD80.bin', 'rb').read()
    # Provide a generous instruction limit for full LZMA decompression
    emu = Emulator(rom_data, trace=False, max_insns=600000000, bypass_autoboot=False)
    
    # Run in a thread
    t = threading.Thread(target=emu.run)
    t.start()
    
    start = time.time()
    # Let it run for x seconds  since full LZMA decompression is slow
    while time.time() - start < 1500:
        time.sleep(1)
        if not t.is_alive():
            break
            
    print("Time up or done. Stopping politely...", file=sys.stderr)
    emu.running = False
    t.join()
    print(f"Final PC: 0x{emu.cpu.pc:08x}, insns: {emu.insn_count}", file=sys.stderr)

if __name__ == '__main__':
    main()
