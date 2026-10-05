# find_and_decompile.py
# Ghidra headless post-script.
# 引数: [0] カンマ区切りの検索文字列(部分一致) [1] 出力先ファイルパス [2] 1関数あたりのdecompileタイムアウト秒(省略可)
# @category Custom

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def run():
    args = getScriptArgs()
    if len(args) < 1 or not args[0].strip():
        terms = ["output_subtract_bit", "comparator", "subtract"]
    else:
        terms = [t.strip() for t in args[0].split(",") if t.strip()]

    out_path = args[1] if len(args) > 1 else "/tmp/ghidra_decompile_output.txt"
    timeout = int(args[2]) if len(args) > 2 and args[2].strip() else 60

    print("Search terms: %s" % terms)
    print("Output path: %s" % out_path)

    monitor = ConsoleTaskMonitor()
    listing = currentProgram.getListing()

    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    results = []
    seen_funcs = set()
    match_count = 0

    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        if not data.hasStringValue():
            continue
        try:
            val = data.getValue()
        except Exception:
            continue
        if val is None:
            continue
        sval = str(val)

        matched_term = None
        for term in terms:
            if term in sval:
                matched_term = term
                break
        if matched_term is None:
            continue

        match_count += 1
        addr = data.getAddress()
        refs = getReferencesTo(addr)

        for ref in refs:
            from_addr = ref.getFromAddress()
            func = getFunctionContaining(from_addr)
            if func is None:
                continue

            func_key = func.getEntryPoint().toString()
            res = decomp.decompileFunction(func, timeout, monitor)
            if not res.decompileCompleted():
                results.append(
                    "==== string match: '%s' in \"%s\" @ %s ====\n"
                    "---- referenced from %s in function %s @ %s ----\n"
                    "[decompile failed/timeout: %s]\n"
                    % (matched_term, sval, addr, from_addr, func.getName(),
                       func.getEntryPoint(), res.getErrorMessage())
                )
                continue

            code = res.getDecompiledFunction().getC()
            header = (
                "==== string match: '%s' in \"%s\" @ %s ====\n"
                "---- referenced from %s in function %s @ %s ----\n"
                % (matched_term, sval, addr, from_addr, func.getName(), func.getEntryPoint())
            )
            # 同じ関数が複数文字列を参照している場合、コード全文は1回だけ出す
            if func_key in seen_funcs:
                results.append(header + "[同一関数は上記で出力済み、見出しのみ記載]\n")
            else:
                seen_funcs.add(func_key)
                results.append(header + code)

    with open(out_path, "w") as f:
        f.write("\n\n".join(results))

    print("Matched strings: %d" % match_count)
    print("Decompiled (or attempted) functions written: %d" % len(results))
    print("Wrote results to %s" % out_path)


run()
