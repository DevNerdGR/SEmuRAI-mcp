from fastmcp import FastMCP
from EmuManager import QilingSession
import ghidra_bridge
import prompts

mcp = FastMCP(name="SEmuRAI (Qiling Backend)")

bridge = None
emuSession = None

# ===== TOOLS =====

@mcp.tool
def greet(name : str) -> str:
    """Sanity check"""
    return f"Hello, {name}!! :))"

@mcp.tool
def setup_emulator(pathToBinary: str, mainFunctionAddr: str, args: list[str] | None):
    """
    RUN THIS BEFORE ANY EMULATION WORK!
    Running this will also cause emulation session to reset.

    - pathToBinary argument refers to the absolute path referencing the binary loaded in ghidra on the user's system (not your, AI agent's, mounted disk). If in doubt, prompt the user for it.
    - mainFunctionAddr refers to the address of the main function. Make sure address starts with 0x.
    - args allows you to supply addition command line arguments to the binary
    """
    try:
        global bridge
        global emuSession

        if bridge is not None:
            try: 
                bridge.__exit__(None, None, None)
            except: 
                pass

        bridge = ghidra_bridge.GhidraBridge(namespace=globals())
        
        currentProgram = bridge.remote_eval("currentProgram") # Sanity check

        if currentProgram is None:
            return "No program currently loaded in Ghidra"
        
        emuSession = QilingSession(pathToBinary, int(currentProgram.getImageBase().toString(), 16), args=args)

        emuSession.setBreakpoint(emuSession.ghidraToQilingAddress(int(mainFunctionAddr, 16)))
        res = emuSession.runTillBreak()
        if res[0]:
            pc = hex(res[1])
            return f"Emulator session set up. PC at main function ({pc})"
        else:
            return f"Error: {res[1]}"
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool
def get_current_program_name() -> str:
    """Get name of current loaded program, second sanity check"""
    global bridge
    try:
        if bridge is None:
            return "Setup required before usage. Run setupEmulator()"
        return bridge.remote_eval("currentProgram.getName()")
    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"

@mcp.tool
def read_register(registerName : str, astype:str="raw"):
    """Reads the value in the specified register.
    astype argument specifies if the returned value is represented as a raw value ("raw") pointer value ("addr").
    """
    global bridge
    global emuSession
    try:
        if bridge is None or emuSession is None:
            return "Setup required before usage. Run setupEmulator()"
        return (hex(emuSession.qilingToGhidraAddress(emuSession.readRegister(registerName))) if astype == "addr" else emuSession.readRegister(registerName))
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool
def write_register(registerName : str, value : int) -> str:
    """Writes the value in the specified register. Take note of endianess."""
    global bridge
    global emuSession
    try:
        if bridge is None or emuSession is None:
            return "Setup required before usage. Run setupEmulator()"
        emuSession.writeRegister(registerName, value)
        return "OK"
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool
def read_memory(startAddress : str, length : int) -> str:
    """Reads n number of bytes (specified by length parameter) from startAddress. Make sure startAddress starts with 0x. Bytes read are parsed and returned as a hex string."""
    global bridge
    global emuSession
    try:
        if bridge is None or emuSession is None:
            return "Setup required before usage. Run setupEmulator()"
        if length <= 0 or length > 4096:
            return "Invalid length! Length must be 1 <= length <= 4096"
        return emuSession.readMem(emuSession.ghidraToQilingAddress(int(startAddress, 16)), length)
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool
def write_memory(startAddress : str, bytesToWrite : str) -> str:
    """Write bytes (specified by bytesToWrite in hex string format) from startAddress onwards. Make sure startAddress starts with 0x. Bytes must be supplied as hex string, without 0x in front."""
    global bridge
    global emuSession
    try:
        if bridge is None or emuSession is None:
            return "Setup required before usage. Run setupEmulator()"
        
        byteStr = bytes.fromhex(bytesToWrite)
        emuSession.writeMem(emuSession.ghidraToQilingAddress(int(startAddress, 16)), byteStr)
        return "OK"
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool
def set_breakpoint(address : str) -> str:
    """Establishes a breakpoint at the specified address. Make sure address starts with 0x"""
    global bridge
    global emuSession
    try:
        if bridge is None or emuSession is None:
            return "Setup required before usage. Run setupEmulator()"
        emuSession.setBreakpoint(emuSession.ghidraToQilingAddress(int(address, 16)))
        return "OK"
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool
def remove_breakpoint(address : str) -> str:
    """Removes breakpoint at the specified address. Make sure address starts with 0x"""
    global bridge
    global emuSession
    try:
        if bridge is None or emuSession is None:
            return "Setup required before usage. Run setupEmulator()"
        emuSession.removeBreakpoint(emuSession.ghidraToQilingAddress(int(address, 16)))
        return "OK"
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool
def get_breakpoints() -> list:
    """Returns set containing addresses of breakpoints."""
    global bridge
    global emuSession
    try:
        if bridge is None or emuSession is None:
            return "Setup required before usage. Run setupEmulator()"
        return list(emuSession.getBreakpoints())
    except Exception as e:
        return f"Error connecting to Ghidra: {str(e)}"

@mcp.tool
def run() -> str:
    """Starts emulation from address pointed to by program counter/instruction pointer. Will stop when breakpoint hit. To make this meaningful, ensure that memory/registers and breakpoints are set up."""
    global bridge
    global emuSession
    try:
        if bridge is None or emuSession is None:
            return "Setup required before usage. Run setupEmulator()"
        res = emuSession.runTillBreak()
        if res[0]:
            return f"PC at {hex(res[1])}"
        else:
            return f"Emulation failed.\n{res[1]}"
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool
def hex_to_decimal(hexValue : str) -> str:
    """Converts hexadecimal value into its decimal representation. Use this whenever you need to do a conversion, do not do it on your own."""
    try:
        return str(int(hexValue.strip(), 16))
    except ValueError:
        return f"Error: Invalid hex value: {hexValue}"

@mcp.tool
def set_PC_register(address : str) -> str:
    """Sets the program counter/instruction pointer to address specified by address argument. Make sure address starts with 0x"""
    global bridge
    global emuSession
    try:
        if bridge is None or emuSession is None:
            return "Setup required before usage. Run setupEmulator()"
        emuSession.setPC(emuSession.ghidraToQilingAddress(int(address, 16)))
        return "OK"
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool
def get_PC_register() -> str:
    """Gets the value in the program counter/instruction pointer, returned as a hex value."""
    global bridge
    global emuSession
    try:
        if bridge is None or emuSession is None:
            return "Setup required before usage. Run setupEmulator()"
        return hex(emuSession.getPC())
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool
def read_stdout() -> str:
    """Read stdout stream."""
    global bridge
    global emuSession
    try:
        if bridge is None or emuSession is None:
            return "Setup required before usage. Run setupEmulator()"
        return emuSession.getStdout().decode('utf-8', errors='replace')
    except Exception as e:
        return f"Error: {str(e)}"

# ===== PROMPTS =====
@mcp.prompt
def analyse_prompt(binary_path: str, additional_information: str=""):
    """Prompt template for triggering binary analysis task"""
    return prompts.initprompt.format(binary_path, additional_information)


if __name__ == "__main__":
    mcp.run()