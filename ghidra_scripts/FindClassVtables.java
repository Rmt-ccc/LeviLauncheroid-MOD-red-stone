// Ghidra headless post-script.
//
// Follow-up to FindStateRefs.java / FindCallers.java / FindAccessorStrings.java.
// All three previous approaches failed to find a *live* "read this
// block's current state/legacy-data value" accessor:
//   - FindStateRefs.java only found world-load-time legacy-data ->
//     BlockState CONSTRUCTOR functions (one value built per switch case).
//   - FindCallers.java's two leads (the shared helper the constructors
//     call, and the redstone_signal constructor itself) both dead-ended.
//   - FindAccessorStrings.java's 6 guessed method/class name strings
//     (LegacyBlock, getSerializationId, BlockLegacy, ...) were ALL
//     absent from the binary - wrong naming guesses entirely.
//
// New approach: stop guessing accessor NAMES and instead inspect the
// "Block" C++ class's actual vtable directly. pl::memory::resolveVtableFunction
// (in LeviLaunchroid's preloader-android) can resolve a virtual function
// by RTTI typeinfo-name + slot index at MOD RUNTIME without needing a
// fixed offset - so if we can identify, from Ghidra, which vtable SLOT
// of class "Block" holds something like getSerializationId()/getState(),
// the MOD can call it reliably across builds via that same API (see
// BedrockTools' shulkerpreview.cpp/lightoverlay.cpp for prior art using
// exactly this hookVtable/resolveVtableFunction pattern).
//
// Steps, reusing proven helpers from the earlier scripts:
//   1. Find the Itanium ABI RTTI typeinfo-NAME string for each candidate
//      class (stored as plain bytes like "5Block" for class "Block" -
//      length-prefixed, no "_ZTS" symbol prefix in raw memory).
//   2. Find the std::type_info OBJECT that points to that name string
//      (its "name" field, 8 bytes after the type_info's own vtable
//      pointer) by scanning for 8-byte-aligned pointers equal to the
//      name string's address.
//   3. Find every VTABLE that points to that type_info object (its
//      "typeinfo" field, which sits right before the first virtual
//      function slot) by scanning for 8-byte-aligned pointers equal to
//      the type_info object's address.
//   4. For each vtable found, dump the first N virtual function slots:
//      target address, containing Function, and a short decompile, so
//      a human can eyeball which slot looks like a state/data reader
//      (small integer return, simple bit-math body, matches the already
//      -known aux-value formulas from FindStateRefs.java).

import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.ConsoleTaskMonitor;

public class FindClassVtables extends GhidraScript {

    // Raw RTTI typeinfo-name strings (Itanium ABI: length-prefixed
    // identifier, no "_ZTS" symbol prefix - that prefix only names the
    // *symbol*, the bytes actually stored in memory are just this).
    private static final String[] CLASS_NAME_CANDIDATES = {
        "5Block",      // class Block (holds mBlockType per BedrockTools offsets)
        "9BlockType",  // class BlockType (holds mNameInfo per BedrockTools offsets)
    };

    // How many virtual function slots to dump per vtable found.
    private static final int SLOTS_TO_DUMP = 32;

    private PrintWriter out;

    private void emit(String line) {
        out.println(line);
        println(line);
    }

    @Override
    protected void run() throws Exception {
        out = new PrintWriter(new FileWriter("vtable_refs_output.txt"));
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        emit("Force-disassembling all executable memory (closing analyzer coverage gaps)...");
        int newlyDisassembled = disassembleAllExecutableCode();
        emit("Force-disassembly pass added " + newlyDisassembled + " new instruction(s).");
        emit("");

        for (String className : CLASS_NAME_CANDIDATES) {
            emit("========== CLASS: " + className + " ==========");
            List<Address> nameHits = findExactStringAddresses(className);
            if (nameHits.isEmpty()) {
                emit("  (RTTI name string not found as raw bytes - class name guess is wrong, or stripped)");
                emit("");
                continue;
            }
            for (Address nameAddr : nameHits) {
                emit("  name string at " + nameAddr);

                List<Address> typeInfoHits = findPointerReferences(nameAddr);
                if (typeInfoHits.isEmpty()) {
                    emit("    (no type_info object references this name string's address - not actually RTTI data, or not 8-byte aligned)");
                    continue;
                }
                for (Address nameFieldAddr : typeInfoHits) {
                    // type_info layout: [vtable ptr (8)][name ptr (8)].
                    // nameFieldAddr is where the name pointer itself lives,
                    // i.e. typeInfoObj + 8.
                    Address typeInfoObj = nameFieldAddr.subtract(8);
                    emit("    candidate type_info object at " + typeInfoObj
                            + " (name field at " + nameFieldAddr + ")");

                    List<Address> vtableHits = findPointerReferences(typeInfoObj);
                    if (vtableHits.isEmpty()) {
                        emit("      (no vtable references this type_info object)");
                        continue;
                    }
                    for (Address typeInfoFieldInVtable : vtableHits) {
                        // Itanium vtable layout: [offset-to-top (8)][typeinfo ptr (8)][vfunc0]...
                        // typeInfoFieldInVtable is where the typeinfo pointer
                        // itself lives; the address POINT (vfunc0) is 8 past it.
                        Address addressPoint = typeInfoFieldInVtable.add(8);
                        emit("      vtable address point at " + addressPoint
                                + " (typeinfo slot at " + typeInfoFieldInVtable + ")");
                        dumpVtableSlots(addressPoint, decomp);
                    }
                }
            }
            emit("");
            out.flush();
        }

        decomp.dispose();
        out.close();
        println("Done. Wrote vtable_refs_output.txt (also mirrored to stdout above)");
    }

    private void dumpVtableSlots(Address addressPoint, DecompInterface decomp) {
        Memory mem = currentProgram.getMemory();
        for (int slot = 0; slot < SLOTS_TO_DUMP; slot++) {
            Address slotAddr;
            long targetOffset;
            try {
                slotAddr = addressPoint.add((long) slot * 8);
                targetOffset = mem.getLong(slotAddr);
            } catch (Exception ex) {
                emit("        slot " + slot + ": (out of mapped memory, stopping)");
                break;
            }
            if (targetOffset == 0) {
                emit("        slot " + slot + ": 0 (end of this vtable's mapped region, or a null slot)");
                continue;
            }
            Address target;
            try {
                target = toAddr(targetOffset);
            } catch (Exception ex) {
                emit("        slot " + slot + ": 0x" + Long.toHexString(targetOffset) + " (not a valid address, stopping)");
                break;
            }
            Function fn = getFunctionContaining(target);
            if (fn == null) {
                try {
                    fn = createFunction(target, null);
                } catch (Exception ignore) {
                    fn = null;
                }
            }
            if (fn == null) {
                emit("        slot " + slot + ": " + target + " (no Function recoverable)");
                continue;
            }
            emit("        slot " + slot + ": " + fn.getName() + " @ " + fn.getEntryPoint()
                    + "  params=" + fn.getParameterCount());
            DecompileResults res = decomp.decompileFunction(fn, 30, new ConsoleTaskMonitor());
            if (res != null && res.decompileCompleted()) {
                String[] lines = res.getDecompiledFunction().getC().split("\n");
                int cap = Math.min(lines.length, 20);
                for (int i = 0; i < cap; i++) {
                    emit("          " + lines[i]);
                }
                if (lines.length > cap) {
                    emit("          ... (" + (lines.length - cap) + " more line(s) truncated)");
                }
            } else {
                emit("          (decompile failed or timed out)");
            }
        }
    }

    // Scans all initialized memory for 8-byte-aligned occurrences of a
    // pointer value equal to `target`'s address. Used both to find the
    // type_info object pointing at a name string, and to find vtables
    // pointing at a type_info object.
    private List<Address> findPointerReferences(Address target) {
        List<Address> results = new ArrayList<>();
        long targetOffset = target.getOffset();
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address start = block.getStart();
            Address end = block.getEnd();
            // Align start up to the next 8-byte boundary.
            long alignedStartOffset = (start.getOffset() + 7) & ~7L;
            Address a;
            try {
                a = start.getNewAddress(alignedStartOffset);
            } catch (Exception ex) {
                continue;
            }
            while (a != null && a.compareTo(end) <= 0) {
                try {
                    long v = mem.getLong(a);
                    if (v == targetOffset) {
                        results.add(a);
                    }
                } catch (Exception ignore) {
                    // unmapped/partial read at this address - skip
                }
                try {
                    a = a.add(8);
                } catch (Exception overflow) {
                    break;
                }
            }
        }
        return results;
    }

    private List<Address> findExactStringAddresses(String target) throws Exception {
        List<Address> results = new ArrayList<>();
        byte[] pattern = (target + "\0").getBytes(StandardCharsets.US_ASCII);
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address start = block.getStart();
            Address end = block.getEnd();
            Address cursor = start;
            while (cursor != null && cursor.compareTo(end) <= 0) {
                Address hit = mem.findBytes(cursor, end, pattern, null, true, monitor);
                if (hit == null) break;
                results.add(hit);
                try {
                    cursor = hit.add(1);
                } catch (Exception overflow) {
                    break;
                }
            }
        }
        return results;
    }

    private int disassembleAllExecutableCode() {
        int count = 0;
        long deadline = System.currentTimeMillis() + (2L * 60 * 60 * 1000);
        Memory mem = currentProgram.getMemory();
        outer:
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute()) continue;
            Address a = block.getStart();
            Address end = block.getEnd();
            long checkCounter = 0;
            while (a != null && a.compareTo(end) <= 0) {
                if (currentProgram.getListing().getInstructionAt(a) == null) {
                    try {
                        if (disassemble(a)) {
                            count++;
                        }
                    } catch (Exception ignore) {
                    }
                }
                try {
                    a = a.add(4);
                } catch (Exception overflow) {
                    break;
                }
                if ((++checkCounter & 0xFFFF) == 0) {
                    if (monitor.isCancelled() || System.currentTimeMillis() > deadline) {
                        println("disassembleAllExecutableCode: stopping early after " + count + " new instruction(s)");
                        break outer;
                    }
                }
            }
        }
        return count;
    }
}
