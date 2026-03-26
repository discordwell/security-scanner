# Ghidra headless analyzer script.
# Run via: analyzeHeadless <project_dir> <project_name> -import <binary>
#          -postScript ghidra_export.py -scriptlog /dev/null
#
# Outputs JSON to stdout with the structure:
# {
#   "functions": [
#     {
#       "name": "FUN_00401000",
#       "entry": "0x00401000",
#       "end": "0x004010ff",
#       "size": 256,
#       "decompiled": "<decompiled source or null>",
#       "calling": ["FUN_00402000"],
#       "called_by": ["main"]
#     }
#   ]
# }
#
# This script runs inside Ghidra's Jython environment.
# It uses Ghidra's Flat API (available as globals in headless scripts).

import json
import sys

try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
except ImportError:
    # Allow reading the script outside Ghidra for testing
    pass


def run():
    monitor = ConsoleTaskMonitor()
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    function_manager = currentProgram.getFunctionManager()
    functions = []
    max_decompile = int(getScriptArgs()[0]) if getScriptArgs() else 50

    decompiled_count = 0

    for func in function_manager.getFunctions(True):
        entry = func.getEntryPoint()
        body = func.getBody()
        size = body.getNumAddresses()
        name = func.getName()

        decompiled_src = None
        if decompiled_count < max_decompile:
            result = decomp.decompileFunction(func, 30, monitor)
            if result and result.decompileCompleted():
                decompiled_src = result.getDecompiledFunction().getC()
                decompiled_count += 1

        calling = []
        for called_func in func.getCalledFunctions(monitor):
            calling.append(called_func.getName())

        called_by = []
        for caller_func in func.getCallingFunctions(monitor):
            called_by.append(caller_func.getName())

        functions.append({
            "name": name,
            "entry": "0x" + entry.toString(),
            "end": "0x" + body.getMaxAddress().toString(),
            "size": size,
            "decompiled": decompiled_src,
            "calling": calling,
            "called_by": called_by,
        })

    decomp.dispose()

    output = json.dumps({"functions": functions}, indent=2)
    # Write to a known output file path passed as second script arg
    if len(getScriptArgs()) > 1:
        output_path = getScriptArgs()[1]
        with open(output_path, "w") as f:
            f.write(output)
    else:
        print(output)


run()
