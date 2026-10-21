// Ghidra headless post-script.
//
// Replaces FindClassVtables.java's approach. That script hand-rolled a
// "scan all initialized memory for an 8-byte-aligned pointer value"
// search to walk RTTI name string -> type_info object -> vtable, and it
// produced garbage: 130+ "vtable" hits all claiming to reference the
// same single type_info object, some of them pointing at plain string
// data mis-decompiled as code. Almost certainly this binary's ELF
// relocation table entries (.rela.dyn) were being misread as genuine
// in-memory pointers by the raw byte scan.
//
// This version instead relies on Ghidra's OWN built-in RTTI analyzer
// (enabled via DisableHeavyAnalyzers.java's allowlist for this run) to
// do that walk correctly - it understands ELF relocations properly and
// builds real typed vtable data + symbols from them, instead of
// guessing from raw bytes. This script just reads back whatever the
// analyzer already recovered: every symbol whose name contains "Block"
// (RTTI-derived class/vtable symbols are named directly after the
// class, e.g. "Block", "vtable for Block", "Block::vftable" - the exact
// wording varies by Ghidra version, hence the broad substring match),
// and for any of those that resolve to a defined array-of-pointers Data
// object, dumps + decompiles each slot - the same output shape as
// FindClassVtables.java so the two are easy to compare.

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Iterator;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.ConsoleTaskMonitor;

public class FindClassVtablesViaRTTI extends GhidraScript {

    // Substrings to match against symbol names. Broad on purpose - we
    // don't know this Ghidra build's exact RTTI symbol-naming
    // convention ahead of time, so better to over-match and read the
    // dump than to miss the real one with too narrow a filter.
    private static final String[] NAME_SUBSTRINGS = {
        "Block",
        "BlockType",
    };

    private static final int SLOTS_TO_DUMP = 32;

    private PrintWriter out;

    private void emit(String line) {
        out.println(line);
        println(line);
    }

    @Override
    protected void run() throws Exception {
        out = new PrintWriter(new FileWriter("rtti_vtable_refs_output.txt"));
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        SymbolTable symTable = currentProgram.getSymbolTable();

        emit("Listing every symbol whose name contains any of: "
                + String.join(", ", NAME_SUBSTRINGS));
        emit("(This relies on DisableHeavyAnalyzers.java having kept Ghidra's own");
        emit(" RTTI analyzer enabled for this run - if the list below is empty,");
        emit(" either that analyzer didn't run/find anything, or this Ghidra");
        emit(" build names its RTTI symbols differently than expected.)");
        emit("");

        int matched = 0;
        Iterator<Symbol> all = symTable.getAllSymbols(true);
        while (all.hasNext()) {
            Symbol sym = all.next();
            String name = sym.getName();
            boolean hit = false;
            for (String sub : NAME_SUBSTRINGS) {
                if (name.contains(sub)) {
                    hit = true;
                    break;
                }
            }
            if (!hit) continue;
            matched++;

            Address addr = sym.getAddress();
            emit("========== SYMBOL: " + name + " @ " + addr
                    + "  (namespace: " + sym.getParentNamespace().getName(true)
                    + ", type: " + sym.getSymbolType() + ") ==========");

            Data data = currentProgram.getListing().getDataAt(addr);
            if (data == null) {
                emit("  (no defined Data here - not a recognized vtable array; address alone, see raw disasm/data manually if needed)");
                emit("");
                continue;
            }
            if (!data.isArray()) {
                emit("  (Data here is " + data.getDataType().getName()
                        + ", not an array - probably not a vtable itself, e.g. the type_info object or a single vtable entry)");
                emit("");
                continue;
            }

            int count = Math.min(data.getNumComponents(), SLOTS_TO_DUMP);
            emit("  array of " + data.getNumComponents() + " element(s), dumping first " + count + ":");
            for (int i = 0; i < count; i++) {
                Data comp = data.getComponent(i);
                Object value = comp.getValue();
                if (!(value instanceof Address)) {
                    emit("    slot " + i + ": " + value + " (not a pointer-typed slot)");
                    continue;
                }
                Address target = (Address) value;
                Function fn = getFunctionContaining(target);
                if (fn == null) {
                    try {
                        fn = createFunction(target, null);
                    } catch (Exception ignore) {
                        fn = null;
                    }
                }
                if (fn == null) {
                    emit("    slot " + i + ": " + target + " (no Function recoverable)");
                    continue;
                }
                emit("    slot " + i + ": " + fn.getName() + " @ " + fn.getEntryPoint()
                        + "  params=" + fn.getParameterCount());
                DecompileResults res = decomp.decompileFunction(fn, 30, new ConsoleTaskMonitor());
                if (res != null && res.decompileCompleted()) {
                    String[] lines = res.getDecompiledFunction().getC().split("\n");
                    int cap = Math.min(lines.length, 20);
                    for (int j = 0; j < cap; j++) {
                        emit("      " + lines[j]);
                    }
                    if (lines.length > cap) {
                        emit("      ... (" + (lines.length - cap) + " more line(s) truncated)");
                    }
                } else {
                    emit("      (decompile failed or timed out)");
                }
            }
            emit("");
            out.flush();
        }

        emit("Total matching symbols: " + matched);

        decomp.dispose();
        out.close();
        println("Done. Wrote rtti_vtable_refs_output.txt (also mirrored to stdout above)");
    }
}
