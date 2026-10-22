// Ghidra headless post-script.
//
// Follow-up to FindClassVtablesViaRTTI.java (1327 noisy substring hits
// on "Block") and this script's own first version (filtered on
// SymbolType.CLASS, which found 0 matches - apparently this Ghidra
// build/run doesn't actually promote demangled namespaces to
// SymbolType.CLASS, even for namespaces we already confirmed exist,
// like leveldb::Block, from FindClassVtablesViaRTTI.java's output).
//
// This version drops the SymbolType.CLASS requirement entirely and
// instead collects, from every symbol's immediate parent namespace, the
// distinct namespaces whose own (last path component) name is EXACTLY
// "Block" or "BlockType" - no substring matching, and no dependency on
// Ghidra having specifically flagged it as a "class". This still fixes
// FindClassVtablesViaRTTI.java's actual bug (it substring-matched a
// symbol's OWN name against "Block", so e.g. "NumBlocksInBatch" - a
// symbol with nothing to do with any Block namespace at all - matched;
// here we instead check the ENCLOSING namespace's exact leaf name).

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class FindExactBlockClasses extends GhidraScript {

    private static final String[] EXACT_NAMES = {
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
        out = new PrintWriter(new FileWriter("exact_block_classes_output.txt"));
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        SymbolTable symTable = currentProgram.getSymbolTable();

        emit("Listing every distinct namespace whose own (leaf) name is exactly: "
                + String.join(" or ", EXACT_NAMES));
        emit("(Found by checking every symbol's immediate parent namespace - no substring");
        emit(" matching, and no dependency on Ghidra having tagged it as a 'class' symbol.)");
        emit("");

        Set<Namespace> matches = new LinkedHashSet<>();
        Iterator<Symbol> all = symTable.getAllSymbols(true);
        while (all.hasNext()) {
            Symbol sym = all.next();
            Namespace ns = sym.getParentNamespace();
            if (ns == null) continue;
            String name = ns.getName();
            for (String target : EXACT_NAMES) {
                if (name.equals(target)) {
                    matches.add(ns);
                    break;
                }
            }
        }

        emit("Found " + matches.size() + " matching namespace(s).");
        emit("");

        for (Namespace ns : matches) {
            String fullPath = ns.getSymbol().getName(true); // full qualified "A::B::Block"
            emit("========== NAMESPACE: " + fullPath + "  (own name: " + ns.getName() + ") ==========");

            SymbolIterator members = symTable.getSymbols(ns);
            List<Symbol> memberList = new ArrayList<>();
            while (members.hasNext()) {
                memberList.add(members.next());
            }
            emit("  " + memberList.size() + " direct member symbol(s):");
            for (Symbol m : memberList) {
                emit("    " + m.getSymbolType() + "  " + m.getName() + " @ " + m.getAddress());
            }
            emit("");

            for (Symbol m : memberList) {
                Address addr = m.getAddress();
                Data data = currentProgram.getListing().getDataAt(addr);
                boolean nameHints = m.getName().toLowerCase().contains("vtable")
                        || m.getName().toLowerCase().contains("vftable");
                boolean looksLikePointerArray = data != null && data.isArray();
                if (!nameHints && !looksLikePointerArray) {
                    continue;
                }
                emit("  ---- dumping possible vtable: " + m.getName() + " @ " + addr + " ----");
                if (data == null || !data.isArray()) {
                    emit("    (no array Data defined here - nothing to dump)");
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
                    DecompileResults res = decomp.decompileFunction(fn, 30, new ghidra.util.task.ConsoleTaskMonitor());
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
            }
            emit("");
            out.flush();
        }

        decomp.dispose();
        out.close();
        println("Done. Wrote exact_block_classes_output.txt (also mirrored to stdout above)");
    }
}
