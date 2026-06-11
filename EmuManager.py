from __future__ import annotations
"""
Makes use of Qiling emulaton framework
"""
from qiling import Qiling
from qiling.extensions import pipe
import lief
from lief import Binary
import os

class RootFS:
    _base = "/Resources/QilingRootFsTemplates/"
    x8664_linux_rootFS = _base + "x8664_linux_glibc2.39/"
    arm_linux_rootFS = _base + "arm_linux/"
    arm64_linux_rootFS = _base + "arm64_linux/"
    x8664_windows_rootFS = _base + "x8664_windows/"
    x8664_macos_rootFS = _base + "x8664_macos/"


class QilingSession:
    def __init__(self, pathToBinary: str, ghidraBaseAddr: int, args: list=None):
        if args is None:
            args = []
        
        if not os.path.exists(pathToBinary):
            raise FileNotFoundError(f"Invalid file path: {pathToBinary}")
    
        binary = lief.parse(pathToBinary)

        if binary is None:
            raise ValueError(f"Failed to parse binary: {pathToBinary}")

        if binary.format == Binary.FORMATS.ELF:
            arch = binary.header.machine_type
            if arch == lief.ELF.ARCH.X86_64:
                rfs = RootFS.x8664_linux_rootFS
                self.endAddr = 0xFFFFFFFFFFFFFFFF
            elif arch == lief.ELF.ARCH.ARM:
                rfs = RootFS.arm_linux_rootFS
                self.endAddr = 0xFFFFFFFF
            elif arch == lief.ELF.ARCH.AARCH64:
                rfs = RootFS.arm64_linux_rootFS
                self.endAddr = 0xFFFFFFFFFFFFFFFF
            else:
                raise ValueError(f"Binary format unknown/unsupported: {pathToBinary}")
        elif binary.format == Binary.FORMATS.MACHO:
            rfs = RootFS.x8664_macos_rootFS
            self.endAddr = 0xFFFFFFFFFFFFFFFF
        elif binary.format == Binary.FORMATS.PE:
            rfs = RootFS.x8664_windows_rootFS
            self.endAddr = 0xFFFFFFFFFFFFFFFF
        else:
            raise ValueError(f"Binary format unknown/unsupported: {pathToBinary}")
        

        self.ql = Qiling(
            [pathToBinary] + args,
            rootfs=os.path.dirname(os.path.abspath(__file__)) + rfs
        )
        self.ghidraBase = ghidraBaseAddr
        self.hookedAddrs = dict()
        self.outStream = pipe.SimpleOutStream(0)
        self.ql.os.stdout = self.outStream
        self.ql.os.stdin = pipe.SimpleInStream(0)
        self.firstRun = True

        
    
    def ghidraToQilingAddress(self, ghidraAddress):
        return ghidraAddress - self.ghidraBase + self.ql.loader.images[0].base

    def qilingToGhidraAddress(self, qilingAddress):
        return qilingAddress - self.ql.loader.images[0].base + self.ghidraBase

    def setBreakpoint(self, qilingAddr, handler=None):
        if handler is None:
            handler = QilingSession.genericHandler
        if qilingAddr in self.hookedAddrs:
            raise ValueError(f"Breakpoint already set at {hex(self.qilingToGhidraAddress(qilingAddr))}.")
        hook = self.ql.hook_address(handler, qilingAddr)
        self.hookedAddrs.update({qilingAddr : hook})
    
    def removeBreakpoint(self, qilingAddr):
        if qilingAddr not in self.hookedAddrs:
            raise ValueError(f"No breakpoint set at {hex(self.qilingToGhidraAddress(qilingAddr))}")
        self.ql.hook_del(self.hookedAddrs[qilingAddr])
        self.hookedAddrs.pop(qilingAddr)

    def getBreakpoints(self):
        return set([hex(self.qilingToGhidraAddress(a)) for a in list(self.hookedAddrs.keys())])

    @staticmethod
    def genericHandler(ql: Qiling):
        ql.emu_stop()

    def setPC(self, qilingAddr):
        self.ql.arch.regs.arch_pc = qilingAddr
    
    def getPC(self):
        return self.qilingToGhidraAddress(self.ql.arch.regs.arch_pc)
    
    def runTillBreak(self, timeout_us=5e+6):
        try:
            if self.firstRun:
                self.firstRun = False
                self.ql.run(timeout=int(timeout_us))
            elif self.ql.arch.regs.arch_pc in self.hookedAddrs: # Handle case where current starting address is a breakpoint
                addr = self.ql.arch.regs.arch_pc
                self.removeBreakpoint(addr)
                try:
                    self.ql.emu_start(begin=self.ql.arch.regs.arch_pc, end=self.endAddr, timeout=int(timeout_us))
                finally:
                    self.setBreakpoint(addr)
            else:
                self.ql.emu_start(begin=self.ql.arch.regs.arch_pc, end=self.endAddr, timeout=int(timeout_us))
            
            return (True, self.getPC())
        except Exception as e:
            return (False, str(e))

    def step(self):
        if self.ql.arch.regs.arch_pc in self.hookedAddrs:
            addr = self.ql.arch.regs.arch_pc
            self.removeBreakpoint(addr)
            try:
                self.ql.emu_start(begin=self.ql.arch.regs.arch_pc, end=self.endAddr, count=1)
            finally:
                self.setBreakpoint(addr)
        else:
            self.ql.emu_start(begin=self.ql.arch.regs.arch_pc, end=self.endAddr, count=1)

    def readRegister(self, reg: str):
        return self.ql.arch.regs.read(reg)
    
    def writeRegister(self, reg: str, value: int):
        self.ql.arch.regs.write(reg, value)
    
    def readMem(self, addr: int, length: int):
        return self.ql.mem.read(addr, length).hex()
    
    def writeMem(self, addr: int, data: bytes):
        self.ql.mem.write(addr, data)

    def getStdout(self):
        return self.outStream.read()