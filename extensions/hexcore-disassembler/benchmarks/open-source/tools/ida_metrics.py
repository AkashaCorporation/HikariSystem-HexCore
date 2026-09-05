import hashlib, json, os
import ida_auto, ida_funcs, ida_nalt, ida_name, idaapi, idautils, idc

def main():
    ida_auto.auto_wait()
    target = ida_nalt.get_input_file_path()
    functions = list(idautils.Functions())
    names = {ida_name.get_name(ea) or idc.get_func_name(ea) for ea in functions}
    focus = [item for item in os.environ.get("HEXCORE_COMPARE_FOCUS", "").split(",") if item]
    found = {}
    for expected in focus:
        matches = sorted(name for name in names if name == expected or name.lstrip("_@") == expected or name.startswith(expected + "@@"))
        found[expected] = matches
    call_edges = 0
    for ea in functions:
        call_edges += sum(1 for item in idautils.FuncItems(ea) for _ in idautils.CodeRefsFrom(item, False))
    with open(target, "rb") as stream:
        binary_sha256 = hashlib.sha256(stream.read()).hexdigest()
    result = {
        "schemaVersion": 1, "tool": "IDA", "version": idaapi.get_kernel_version(),
        "binaryPath": target, "binarySha256": binary_sha256,
        "functions": len(functions), "namedFunctions": sum(1 for name in names if name and not name.startswith("sub_")),
        "callAndFlowReferences": call_edges, "focus": found,
    }
    with open(os.environ["HEXCORE_COMPARE_OUTPUT"], "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
    idc.qexit(0)

if __name__ == "__main__": main()
