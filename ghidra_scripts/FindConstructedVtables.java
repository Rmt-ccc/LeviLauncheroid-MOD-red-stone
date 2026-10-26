// Ghidra headless post-script.
//
// User's choice after FUN_09053250's thread fully dead-ended (confirmed
// zero indirect references either, in FindFunctionPointerRefs.java's
// run - combined with FindCallers.java's "only 2 direct bl callers,
// both confirmed low-frequency world-diff utilities", that function
// itself has nothing further to pull on): go back to option (a), the
// vtable brute-force idea from FindVtableSlot4Candidates.java (now in
// Ghidra-Analysis-Data/Failure-File/), but narrowed using what's been
// learned since that attempt failed from being too broad (92,747
// shape-matching candidates, no way to correlate back to anything).
//
// What's new since that attempt: FindFunctionPointerRefs.java proved
// out, on this exact binary, a cheap whole-program "what addresses get
// materialized via adrp+add, and where" index (604,094 distinct target
// addresses in one pass, no OOM). This script combines that technique
// with FindVtableSlot4Candidates.java's two-stage shape filter, adding
// a THIRD, much stronger filter stage that the old attempt didn't have:
//
//   Stage 1 (unchanged): scan non-executable memory for vtable-shaped
//     runs (slots 0..4 all land on disassembled executable code).
//   Stage 2 (unchanged): keep only candidates whose slot-4 (offset
//     0x20) target function has the "x1/w1 index arithmetic -> load"
//     instruction shape - the known vtable+0x20 getBlock-equivalent
//     accessor pattern.
//   Stage 3 (NEW): a REAL C++ vtable isn't just vtable-shaped data -
//     it's a value some constructor actually computes (via adrp+add)
//     and stores into a fresh object, typically as the very first write
//     to that object (`this->vtable = &SomeClass::vtable;`, i.e. a
//     "str x<reg>, [x0]" or "str x<reg>, [x0, #0]" shortly after the
//     add that materializes the vtable's address). Stage 1/2 alone
//     can't distinguish a genuine vtable from any other data that
//     happens to look vtable-shaped (a jump table, a const array of
//     function pointers used for something else, etc.) - this stage
//     does, and should cut the candidate set from tens of thousands
//     down to a short, human-reviewable list.
//
// Only stage-3 survivors get decompiled and printed, keeping this
// bounded even though stage 1/2 still scan the whole binary.

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.task.ConsoleTaskMonitor;

public class FindConstructedVtables extends GhidraScript {

    private static final int SLOTS_CHECKED = 5;
    private static final long SLOT4_OFFSET = 0x20L;
    private static final int SHAPE_WALK_MAX_INSNS = 60;
    private static final int CONSTRUCTOR_STORE_WINDOW = 15;
    private static final int MAX_DECOMPILED_OUTPUT = 40;

    private PrintWriter out;

    private void emit(String line) {
        out.println(line);
        println(line);
    }

    @Override
    protected void run() throws Exception {
        out = new PrintWriter(new FileWriter("constructed_vtables_output.txt"));
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();

        emit("Force-disassembling all executable memory (closing analyzer coverage gaps)...");
        int newlyDisassembled = disassembleAllExecutableCode();
        emit("Force-disassembly pass added " + newlyDisassembled + " new instruction(s).");
        emit("");

        emit("Stage 1: scanning non-executable initialized memory for vtable-shaped "
                + "runs (slots 0..4 all pointing at disassembled executable code)...");
        List<Address> vtableHits = new ArrayList<>();
        long scanned = 0;
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || block.isExecute()) continue;
            Address addr = block.getStart();
            Address blockEnd = block.getEnd();
            while (addr != null && addr.compareTo(blockEnd) < 0) {
                scanned++;
                if (fitsVtableShape(mem, listing, addr, blockEnd)) {
                    vtableHits.add(addr);
                }
                if ((scanned & 0xFFFFFF) == 0) {
                    println("FindConstructedVtables: scanned " + scanned + " word(s), "
                            + vtableHits.size() + " vtable-shaped hit(s) so far");
                }
                try {
                    addr = addr.add(8);
                } catch (Exception overflow) {
                    break;
                }
            }
        }
        emit("Scanned " + scanned + " candidate word(s). Vtable-shaped hits: " + vtableHits.size());
        emit("");

        emit("Stage 2: cheap instruction-shape check on each hit's slot-4 target "
                + "(x1/w1 index arithmetic followed by a load)...");
        Set<Address> stage2Vtables = new LinkedHashSet<>();
        for (Address vtAddr : vtableHits) {
            Address slot4Target = readPointer(mem, vtAddr.add(SLOT4_OFFSET));
            if (slot4Target == null) continue;
            if (looksLikeIndexAccessor(listing, slot4Target)) {
                stage2Vtables.add(vtAddr);
            }
        }
        emit("Vtables surviving stage 2 (slot-4 shape matches): " + stage2Vtables.size());
        emit("");

        emit("Stage 3: building whole-program adrp+add materialization index, keeping "
                + "only ADD-instruction hits whose target address is one of the stage-2 "
                + "survivors above (bounded memory - we only ever retain hits for "
                + stage2Vtables.size() + " candidate address(es), not all ~600K materialized "
                + "addresses in the binary)...");
        Map<Long, List<AddHit>> addHitsByTarget = buildFilteredAdrpAddIndex(stage2Vtables);
        emit("Materialization sites found for " + addHitsByTarget.size()
                + " of the " + stage2Vtables.size() + " stage-2 candidate(s).");
        emit("");

        emit("Stage 3b: for each materialization site, checking the next "
                + CONSTRUCTOR_STORE_WINDOW + " instructions for a 'str <reg>, [x0, ...]' "
                + "(the computed vtable address being stored into what looks like a fresh "
                + "object's first field - the standard AArch64 constructor vtable-install idiom)...");
        Set<Address> constructedVtables = new LinkedHashSet<>();
        Map<Address, Address> constructorSiteOf = new HashMap<>();
        for (Map.Entry<Long, List<AddHit>> e : addHitsByTarget.entrySet()) {
            Address vtAddr = toAddr(e.getKey());
            for (AddHit hit : e.getValue()) {
                Address storeSite = findStoreIntoX0Forward(listing, hit.addInsnAddr, hit.destReg);
                if (storeSite != null) {
                    constructedVtables.add(vtAddr);
                    constructorSiteOf.put(vtAddr, storeSite);
                    break;
                }
            }
        }
        emit("Vtables confirmed CONSTRUCTED (materialized then stored into [x0, ...] "
                + "nearby - strong real-vtable signal): " + constructedVtables.size());
        emit("");

        // Resolve every constructed candidate's constructor-function entry
        // point first (cheap - no decompiling), so stage 4 below can
        // filter on it before any decompiling happens at all. This also
        // fixes the previous run's blind spot: with potentially thousands
        // of real constructed vtables (this binary has many legitimate
        // C++ classes), decompiling in plain iteration order and
        // stopping after MAX_DECOMPILED_OUTPUT only ever showed an
        // arbitrary early slice - never a representative sample, and
        // never anything explicitly tied back to the one region of the
        // binary we actually care about.
        Map<Address, Address> ctorEntryOf = new HashMap<>();
        for (Address vtAddr : constructedVtables) {
            Address constructorSite = constructorSiteOf.get(vtAddr);
            Function ctorFn = getFunctionContaining(constructorSite);
            Address entry;
            if (ctorFn != null) {
                entry = ctorFn.getEntryPoint();
            } else {
                entry = findContainingPrologue(listing, constructorSite);
            }
            ctorEntryOf.put(vtAddr, entry);
        }

        emit("Stage 4: cheap summary of ALL " + constructedVtables.size()
                + " constructed-vtable candidate(s) - vtable address, slot-4 target, "
                + "constructor entry point - no decompiling yet, so nothing here is capped:");
        for (Address vtAddr : constructedVtables) {
            Address slot4Target = readPointer(mem, vtAddr.add(SLOT4_OFFSET));
            emit("  vtable " + vtAddr + "  slot4 " + slot4Target
                    + "  ctor_entry " + ctorEntryOf.get(vtAddr));
        }
        emit("");

        // Locality filter: FUN_09053250 (the function with the one
        // confirmed vtable+0x20 getBlock-equivalent call) and both of
        // its known callers (FUN_09054334, FUN_090647b8) all sit within
        // 0x09050000-0x09070000 - almost certainly the same translation
        // unit / object file as whatever class this vtable belongs to,
        // since AArch64/Android NDK builds keep one .o's functions
        // contiguous in .text. Candidates whose CONSTRUCTOR also falls
        // in that neighborhood are far likelier to be the right class
        // than the thousands of unrelated constructed vtables elsewhere
        // in this huge engine binary - only these get decompiled.
        final long localityStart = 0x09000000L;
        final long localityEnd = 0x09100000L;
        List<Address> localityMatches = new ArrayList<>();
        for (Address vtAddr : constructedVtables) {
            Address entry = ctorEntryOf.get(vtAddr);
            if (entry == null) continue;
            long off = entry.getOffset();
            if (off >= localityStart && off < localityEnd) {
                localityMatches.add(vtAddr);
            }
        }
        emit("Stage 4 locality filter: constructor entry point within ["
                + toAddr(localityStart) + ", " + toAddr(localityEnd)
                + ") - the same neighborhood as FUN_09053250 and its 2 known callers. "
                + "Survivors: " + localityMatches.size() + " of " + constructedVtables.size());
        emit("");

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        int shown = 0;
        for (Address vtAddr : localityMatches) {
            shown++;
            if (shown > MAX_DECOMPILED_OUTPUT) {
                emit("(stopping decompile output after " + MAX_DECOMPILED_OUTPUT
                        + " locality-filtered candidates - see count above)");
                break;
            }
            Address slot4Target = readPointer(mem, vtAddr.add(SLOT4_OFFSET));
            Address constructorSite = constructorSiteOf.get(vtAddr);
            emit("========== LOCALITY-MATCHED VTABLE CANDIDATE @ " + vtAddr + " ==========");
            emit("  slot-4 (getBlock-equivalent) target: " + slot4Target);
            emit("  constructor install site (str into [x0,...]): " + constructorSite);
            Function ctorFn = getFunctionContaining(constructorSite);
            if (ctorFn == null) {
                ctorFn = createFunction(findContainingPrologue(listing, constructorSite), null);
            }
            if (ctorFn != null) {
                emit("  constructor function: " + ctorFn.getName() + " @ " + ctorFn.getEntryPoint());
                DecompileResults ctorRes = decomp.decompileFunction(ctorFn, 60, new ConsoleTaskMonitor());
                if (ctorRes != null && ctorRes.decompileCompleted()) {
                    emit("  ---- decompiled constructor " + ctorFn.getName() + " ----");
                    emit(ctorRes.getDecompiledFunction().getC());
                    emit("  ---- end constructor " + ctorFn.getName() + " ----");
                } else {
                    emit("  (constructor decompile failed)");
                }
            } else {
                emit("  (could not resolve a Function for the constructor site)");
            }

            Function slot4Fn = getFunctionAt(slot4Target);
            if (slot4Fn == null && slot4Target != null) {
                slot4Fn = createFunction(slot4Target, null);
            }
            if (slot4Fn != null) {
                DecompileResults res = decomp.decompileFunction(slot4Fn, 60, new ConsoleTaskMonitor());
                emit("  ---- decompiled slot-4 accessor " + slot4Fn.getName() + " ----");
                if (res != null && res.decompileCompleted()) {
                    emit(res.getDecompiledFunction().getC());
                } else {
                    emit("  (decompile failed)");
                }
                emit("  ---- end slot-4 accessor " + slot4Fn.getName() + " ----");
            }
            emit("========== end candidate @ " + vtAddr + " ==========");
            emit("");
            out.flush();
        }

        decomp.dispose();
        out.close();
        println("Done. Wrote constructed_vtables_output.txt (also mirrored to stdout above)");
    }

    private static final class AddHit {
        final Address addInsnAddr;
        final String destReg;
        AddHit(Address addInsnAddr, String destReg) {
            this.addInsnAddr = addInsnAddr;
            this.destReg = destReg;
        }
    }

    // Same vtable-shape check as FindVtableSlot4Candidates.java.
    private boolean fitsVtableShape(Memory mem, Listing listing, Address addr, Address blockEnd) {
        try {
            if (addr.add(SLOT4_OFFSET).compareTo(blockEnd) > 0) return false;
        } catch (Exception overflow) {
            return false;
        }
        for (int slot = 0; slot < SLOTS_CHECKED; slot++) {
            Address target = readPointer(mem, addr.add((long) slot * 8));
            if (target == null) return false;
            MemoryBlock targetBlock = mem.getBlock(target);
            if (targetBlock == null || !targetBlock.isExecute()) return false;
            if (listing.getInstructionAt(target) == null) return false;
        }
        return true;
    }

    private Address readPointer(Memory mem, Address at) {
        try {
            long v = mem.getLong(at);
            if (v == 0) return null;
            return toAddr(v);
        } catch (Exception e) {
            return null;
        }
    }

    // Same cheap shape check as FindVtableSlot4Candidates.java: does the
    // slot-4 target read x1/w1 (the index parameter) through arithmetic
    // and later issue a load.
    private boolean looksLikeIndexAccessor(Listing listing, Address start) {
        Instruction insn = listing.getInstructionAt(start);
        boolean sawIndexArithmetic = false;
        int count = 0;
        while (insn != null && count < SHAPE_WALK_MAX_INSNS) {
            String mn = insn.getMnemonicString().toLowerCase();
            String rep = insn.toString().toLowerCase();
            boolean usesParam2Reg = rep.contains("x1") || rep.contains("w1");
            boolean isArithOp = mn.equals("mul") || mn.equals("umull") || mn.equals("smull")
                    || mn.equals("lsl") || mn.equals("add") || mn.equals("sub")
                    || mn.equals("ubfx") || mn.equals("sbfx") || mn.equals("sxtw") || mn.equals("uxtw");
            if (isArithOp && usesParam2Reg) {
                sawIndexArithmetic = true;
            }
            if (sawIndexArithmetic && mn.startsWith("ldr")) {
                return true;
            }
            if (mn.equals("ret")) {
                return false;
            }
            insn = insn.getNext();
            count++;
        }
        return false;
    }

    // Single whole-program pass building the adrp+add materialization
    // index, same technique as FindFunctionPointerRefs.java's
    // buildAdrpReferenceIndex(), but bounded: only ADD-instruction hits
    // whose computed target address is in `wanted` are ever retained,
    // so memory use stays proportional to the (small) candidate set
    // instead of the ~600K total materialized addresses in the binary.
    private Map<Long, List<AddHit>> buildFilteredAdrpAddIndex(Set<Address> wanted) {
        Set<Long> wantedOffsets = new java.util.HashSet<>();
        for (Address a : wanted) wantedOffsets.add(a.getOffset());

        Map<Long, List<AddHit>> result = new HashMap<>();
        Map<String, Long> pendingAdrp = new HashMap<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction insn = it.next();
            String mn = insn.getMnemonicString();
            if (mn == null) continue;
            mn = mn.toLowerCase();
            try {
                if (mn.equals("adrp")) {
                    Register destReg = firstRegister(insn, 0);
                    Long page = firstScalarOrAddress(insn, 1);
                    if (destReg != null && page != null) {
                        pendingAdrp.put(destReg.getName(), page);
                    }
                } else if (mn.equals("add")) {
                    Register destReg = firstRegister(insn, 0);
                    Register srcReg = firstRegister(insn, 1);
                    Long imm = firstScalarOrAddress(insn, 2);
                    if (srcReg != null && imm != null) {
                        Long page = pendingAdrp.get(srcReg.getName());
                        if (page != null) {
                            long full = page + imm;
                            if (wantedOffsets.contains(full) && destReg != null) {
                                result.computeIfAbsent(full, k -> new ArrayList<>())
                                        .add(new AddHit(insn.getAddress(), destReg.getName()));
                            }
                        }
                    }
                }
            } catch (Exception ignore) {
            }
        }
        return result;
    }

    // Walks forward from the ADD instruction that computed the vtable
    // address into `destReg`, looking within CONSTRUCTOR_STORE_WINDOW
    // instructions for a "str <destReg-or-a-register-copied-from-it>,
    // [x0, ...]" - the AArch64 idiom for "this->vtable = computedAddr;"
    // in a freshly-entered constructor (x0 is the AAPCS64 'this'
    // parameter). Simple, register-name-based (no real dataflow), but
    // good enough: constructors overwhelmingly do this within a handful
    // of instructions of computing the vtable address, with no
    // intervening reassignment of the same register to something else.
    private Address findStoreIntoX0Forward(Listing listing, Address addInsnAddr, String destReg) {
        Instruction insn = listing.getInstructionAt(addInsnAddr);
        if (insn == null) return null;
        String reg = destReg;
        for (int i = 0; i < CONSTRUCTOR_STORE_WINDOW && insn != null; i++) {
            insn = insn.getNext();
            if (insn == null) break;
            String mn = insn.getMnemonicString();
            if (mn == null) continue;
            mn = mn.toLowerCase();
            String rep = insn.toString().toLowerCase();

            if (mn.equals("str") && rep.contains(reg.toLowerCase()) && rep.contains("[x0")) {
                return insn.getAddress();
            }
            // Track a simple register-to-register copy of our value
            // (e.g. "mov x1, x8") so the store check above still fires
            // if the compiler moved it before storing.
            if (mn.equals("mov") && insn.getNumOperands() >= 2) {
                Register d = firstRegister(insn, 0);
                Register s = firstRegister(insn, 1);
                if (d != null && s != null && s.getName().equalsIgnoreCase(reg)) {
                    reg = d.getName();
                }
            }
            // A "bl" call is a natural boundary for "did this constructor
            // move on to something else" - stop looking past one, to
            // avoid false positives from an unrelated later store that
            // happens to reuse the same register name after a call.
            if (mn.equals("bl")) {
                break;
            }
        }
        return null;
    }

    private Address findContainingPrologue(Listing listing, Address from) {
        Instruction insn = listing.getInstructionAt(from);
        Instruction walker = insn;
        for (int i = 0; i < 2000 && walker != null; i++) {
            walker = walker.getPrevious();
            if (walker == null) break;
            String mn = walker.getMnemonicString();
            if (mn != null && mn.equalsIgnoreCase("stp")) {
                String rep = walker.toString().toLowerCase();
                if (rep.contains("x29") && rep.contains("x30") && rep.contains("sp")) {
                    Instruction prev = walker.getPrevious();
                    if (prev != null && "sub".equalsIgnoreCase(prev.getMnemonicString())
                            && prev.toString().toLowerCase().contains("sp")) {
                        return prev.getAddress();
                    }
                    return walker.getAddress();
                }
            }
        }
        return from;
    }

    private Register firstRegister(Instruction insn, int opIndex) {
        if (opIndex >= insn.getNumOperands()) return null;
        Object[] objs = insn.getOpObjects(opIndex);
        if (objs == null) return null;
        for (Object o : objs) {
            if (o instanceof Register) return (Register) o;
        }
        return null;
    }

    private Long firstScalarOrAddress(Instruction insn, int opIndex) {
        if (opIndex >= insn.getNumOperands()) return null;
        Object[] objs = insn.getOpObjects(opIndex);
        if (objs == null) return null;
        for (Object o : objs) {
            if (o instanceof Scalar) return ((Scalar) o).getUnsignedValue();
            if (o instanceof Address) return ((Address) o).getOffset();
        }
        return null;
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
                        println("disassembleAllExecutableCode: stopping early (time cap or cancel) after "
                                + count + " new instruction(s)");
                        break outer;
                    }
                }
            }
        }
        return count;
    }
}
