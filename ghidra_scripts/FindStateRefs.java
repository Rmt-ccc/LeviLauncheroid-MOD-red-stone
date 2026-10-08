// Ghidra headless post-script.
//
// For each target string below: finds it in Defined Strings, finds every
// place in code that references it, and dumps the containing function's
// name, address, and decompiled C-like pseudocode to an output text file
// (state_refs_output.txt).

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.ConsoleTaskMonitor;

public class FindStateRefs extends GhidraScript {

    // Only the still-unresolved targets from the previous run (the rest
    // are already fully analyzed - no need to spend time re-decompiling
    // them). "orientation" is dropped: it was too generic and mostly
    // matched unrelated Android-side code, not block states.
    private static final String[] TARGETS = {
        "composter_fill_level",
        "sculk_sensor_phase",
        "bite_counter",
        "lever_direction",
        "respawn_anchor_charge",
        "redstone_signal",
        "honey_level",
        "open_bit",
    };

    // Helper that writes a line to BOTH the output file and the headless
    // stdout log (so results are readable straight from the Actions run
    // page / step log, with no file download or unzip needed).
    private PrintWriter out;

    private void emit(String line) {
        out.println(line);
        println(line); // GhidraScript.println -> headless stdout -> analyze.log
    }

    @Override
    protected void run() throws Exception {
        out = new PrintWriter(new FileWriter("state_refs_output.txt"));
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Cache decompiled output per function entry point so a function
        // referenced many times (e.g. from a 16-case switch) is only
        // decompiled and printed ONCE instead of once per reference.
        Map<Address, String> decompCache = new LinkedHashMap<>();

        for (String target : TARGETS) {
            emit("========== STRING: " + target + " ==========");
            List<Address> hits = findExactStringAddresses(target);
            if (hits.isEmpty()) {
                emit("  (not found as a defined string)");
                emit("");
                continue;
            }
            for (Address strAddr : hits) {
                emit("  string data at " + strAddr);
                ReferenceIterator refs = currentProgram.getReferenceManager()
                        .getReferencesTo(strAddr);

                // Group reference addresses by containing function first.
                Map<Function, List<Address>> byFunction = new LinkedHashMap<>();
                List<Address> noFunctionRefs = new ArrayList<>();
                boolean any = false;
                while (refs.hasNext()) {
                    any = true;
                    Reference ref = refs.next();
                    Address from = ref.getFromAddress();
                    Function fn = getFunctionContaining(from);
                    if (fn == null) {
                        noFunctionRefs.add(from);
                    } else {
                        byFunction.computeIfAbsent(fn, k -> new ArrayList<>()).add(from);
                    }
                }

                for (Map.Entry<Function, List<Address>> e : byFunction.entrySet()) {
                    Function fn = e.getKey();
                    List<Address> froms = e.getValue();
                    StringBuilder fromsStr = new StringBuilder();
                    for (int i = 0; i < froms.size(); i++) {
                        if (i > 0) fromsStr.append(", ");
                        fromsStr.append(froms.get(i));
                    }
                    emit("    referenced from [" + fromsStr + "] (" + froms.size()
                            + " call site(s))  in function " + fn.getName()
                            + " @ " + fn.getEntryPoint());

                    String decompiledText = decompCache.get(fn.getEntryPoint());
                    if (decompiledText == null) {
                        DecompileResults res = decomp.decompileFunction(fn, 60, new ConsoleTaskMonitor());
                        if (res != null && res.decompileCompleted()) {
                            decompiledText = res.getDecompiledFunction().getC();
                        } else {
                            decompiledText = "(decompile failed for " + fn.getName() + ")";
                        }
                        decompCache.put(fn.getEntryPoint(), decompiledText);
                        emit("    ---- decompiled " + fn.getName() + " ----");
                        emit(decompiledText);
                        emit("    ---- end " + fn.getName() + " ----");
                    } else {
                        emit("    (decompiled " + fn.getName()
                                + " already shown above for this run - not repeated)");
                    }
                }
                // No Function object covers these reference sites, so the
                // decompiler can't be used (it needs a Function). Fall back
                // to dumping a raw disassembly window around each address -
                // that's enough to read the aux-value branching logic by
                // hand, same as we'd get from a decompile.
                for (Address from : noFunctionRefs) {
                    emit("    referenced from " + from
                            + "  (not inside a known function - raw disassembly window below)");
                    try {
                        Address winStart = from.subtract(0x100);
                        Address winEnd = from.add(0x100);
                        AddressSet window = new AddressSet(winStart, winEnd);
                        disassemble(window);
                        InstructionIterator insns = currentProgram.getListing()
                                .getInstructions(window, true);
                        while (insns.hasNext()) {
                            Instruction insn = insns.next();
                            emit("      " + insn.getAddress() + ":  " + insn.toString());
                        }
                    } catch (Exception ex) {
                        emit("      (failed to disassemble window: " + ex.getMessage() + ")");
                    }
                }
                if (!any) {
                    emit("    (no references found to this string)");
                }
            }
            emit("");
            out.flush();
        }

        decomp.dispose();
        out.close();
        println("Done. Wrote state_refs_output.txt (also mirrored to stdout above)");
    }

    private List<Address> findExactStringAddresses(String target) throws Exception {
        List<Address> results = new ArrayList<>();
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        while (it.hasNext()) {
            Data d = it.next();
            if (!d.hasStringValue()) continue;
            Object val = d.getValue();
            if (val == null) continue;
            String s = val.toString();
            if (s.equals(target)) {
                results.add(d.getAddress());
            }
        }
        return results;
    }
}
