// Ghidra headless post-script.
//
// Follow-up to FindClassVtablesViaRTTI.java. That script substring-
// matched "Block" against EVERY symbol name and got 1327 hits, almost
// all noise: third-party libraries bundled into this binary (leveldb,
// v8, abseil, cohtml, ...) each have their own, completely unrelated
// class also literally named "Block" (e.g. leveldb::Block is a real
// on-disk storage data structure, nothing to do with Minecraft blocks).
// Worse, this likely explains why FindClassVtables.java's very first
// attempt (searching raw bytes for the RTTI name string "5Block")
// probably found one of THOSE classes' RTTI, not Minecraft's own Block
// class - Itanium name mangling concatenates length-prefixed name
// components with no separator, so "7leveldb" + "5Block" still
// contains the literal byte sequence "5Block" as a sub-string, same as
// an unqualified global "5Block" would.
//
// This script narrows the search properly: instead of a raw substring
// match against every symbol, it asks Ghidra's symbol table for actual
// recognized C++ CLASS NAMESPACES (GhidraClass objects - only real
// classes the RTTI/demangler analysis identified, not arbitrary
// symbols) whose own, exact name is "Block" or "BlockType" - then lists
// every one found together with its FULL qualified path (so leveldb::Block
// etc. are immediately distinguishable from Minecraft's own, presumably
// unqualified, global ::Block), and dumps each such class's direct
// member symbols (vftable included, if the analyzer created one).

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.GhidraClass;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.ConsoleTaskMonitor;

public class FindExactBlockClasses extends GhidraScript {

    // Exact class-name match only (not substring) - this is the whole
    // point of this script versus FindClassVtablesViaRTTI.java.
    private static final String[] EXACT_CLASS_NAMES = {
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

        emit("Listing every recognized C++ class namespace whose own name is exactly: "
                + String.join(" or ", EXACT_CLASS_NAMES));
        emit("(Unlike the previous script, this does NOT substring-match - a class named");
        emit(" e.g. 'BlockEntity' or a namespace merely containing 'Block' will NOT show up here.)");
        emit("");

        List<GhidraClass> matches = new ArrayList<>();
        Iterator<GhidraClass> classIt = symTable.getClassNamespaces();
        while (classIt.hasNext()) {
            GhidraClass cls = classIt.next();
            for (String target : EXACT_CLASS_NAMES) {
                if (cls.getName().equals(target)) {
                    matches.add(cls);
                    break;
                }
            }
        }

        emit("Found " + matches.size() + " matching class namespace(s).");
        emit("");

        for (GhidraClass cls : matches) {
            String fullPath = cls.getSymbol().getName(true); // full qualified "A::B::Block"
            emit("========== CLASS: " + fullPath + "  (own name: " + cls.getName() + ") ==========");

            SymbolIterator members = symTable.getSymbols(cls);
            int memberCount = 0;
            List<Symbol> memberList = new ArrayList<>();
            while (members.hasNext()) {
                memberList.add(members.next());
                memberCount++;
            }
            emit("  " + memberCount + " direct member symbol(s):");
            for (Symbol m : memberList) {
                emit("    " + m.getSymbolType() + "  " + m.getName() + " @ " + m.getAddress());
            }
            emit("");

            // For each member that looks like it could be the vtable
            // (name mentions vtable/vftable, OR is simply an array of
            // pointers regardless of name - the RTTI analyzer doesn't
            // always label it obviously), dump its slots.
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
            }
            emit("");
            out.flush();
        }

        decomp.dispose();
        out.close();
        println("Done. Wrote exact_block_classes_output.txt (also mirrored to stdout above)");
    }
}
