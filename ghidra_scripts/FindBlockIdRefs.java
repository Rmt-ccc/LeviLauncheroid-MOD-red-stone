// Ghidra headless post-script.
//
// Strategic pivot after FindStateRefs.java -> FindCallers.java ->
// FindFunctionPointerRefs.java -> ScanRelocationsForTarget.java all
// converged on the same dead end: FUN_11633944 (the redstone_signal
// per-aux-value constructor) is not called directly (no 'bl'), not
// materialized as a code-computed address (no adrp+add/ldr/str), not a
// raw baked-in pointer anywhere in memory, and not referenced by any
// ELF relocation record either. Every representation Ghidra exposes
// came back empty across 3 independent techniques.
//
// Conclusion: that function is schema/registration-time code (it runs
// once, at block-state-table setup, to enumerate the 16 possible
// redstone_signal values) - not the runtime code path that reads a
// LIVE block's CURRENT redstone signal during normal gameplay (tick
// simulation, rendering, etc.). Those are architecturally different:
// registration code names properties by STRING ("redstone_signal");
// runtime simulation code identifies blocks by comparing BLOCK ID
// strings ("minecraft:redstone_wire") and then reads/writes a live
// struct field directly - no property-name string involved at all.
//
// This script reuses FindStateRefs.java's proven technique (which DID
// successfully find real code: raw string scan + manual adrp+add/ldr
// reference index + decompile), but retargets it at BLOCK ID strings
// instead of property-name strings. Functions that reference
// "minecraft:redstone_wire" are strong candidates for the engine's own
// redstone tick/simulation/render logic, which is where a live power
// level actually gets read - exactly what the LeviLaunchroid MOD needs.

import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.task.ConsoleTaskMonitor;

public class FindBlockIdRefs extends GhidraScript {

    private static final String[] TARGETS = {
        "minecraft:redstone_wire",
        "redstone_wire",
    };

    private static final long FUNC_PROLOGUE_MARKER_OFFSET = 0x0e656420L;

    private PrintWriter out;

    private void emit(String line) {
        out.println(line);
        println(line);
    }

    @Override
    protected void run() throws Exception {
        out = new PrintWriter(new FileWriter("blockid_refs_output.txt"));
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Map<Address, String> decompCache = new LinkedHashMap<>();
        Address marker = toAddr(FUNC_PROLOGUE_MARKER_OFFSET);
        clearNoReturnChain(marker);

        emit("Force-disassembling all executable memory (closing analyzer coverage gaps)...");
        int newlyDisassembled = disassembleAllExecutableCode();
        emit("Force-disassembly pass added " + newlyDisassembled + " new instruction(s).");

        emit("Building adrp+add/ldr/str reference index over the whole program (one pass)...");
        Map<Long, List<Address>> refIndex = buildAdrpReferenceIndex();
        emit("Index built: " + refIndex.size() + " distinct target addresses materialized in code.");
        emit("");

        for (String target : TARGETS) {
            emit("========== STRING: " + target + " ==========");
            List<Address> hits = findExactStringAddresses(target);
            if (hits.isEmpty()) {
                emit("  (not found as raw bytes in any initialized memory block)");
                emit("");
                continue;
            }
            for (Address strAddr : hits) {
                emit("  string data at " + strAddr);
                List<Address> refs = refIndex.get(strAddr.getOffset());
                if (refs == null) refs = new ArrayList<>();

                Map<Function, List<Address>> byFunction = new LinkedHashMap<>();
                List<Address> noFunctionRefs = new ArrayList<>();
                for (Address from : refs) {
                    Function fn = getFunctionContaining(from);
                    if (fn == null) {
                        fn = tryForceCreateFunction(from, marker);
                    }
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
                for (Address from : noFunctionRefs) {
                    emit("    referenced from " + from
                            + "  (no Function recoverable here - raw disassembly window below)");
                    try {
                        Address winStart = from.subtract(0x40);
                        Address winEnd = from.add(0x40);
                        AddressSet window = new AddressSet(winStart, winEnd);
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
                if (refs.isEmpty()) {
                    emit("    (no code references found materializing this address)");
                }
            }
            emit("");
            out.flush();
        }

        decomp.dispose();
        out.close();
        println("Done. Wrote blockid_refs_output.txt (also mirrored to stdout above)");
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

    private Map<Long, List<Address>> buildAdrpReferenceIndex() {
        Map<Long, List<Address>> result = new HashMap<>();
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
                            result.computeIfAbsent(full, k -> new ArrayList<>()).add(insn.getAddress());
                        }
                    }
                } else if (mn.equals("ldr") || mn.equals("str") || mn.equals("ldrb")
                        || mn.equals("strb") || mn.equals("ldrh") || mn.equals("strh")) {
                    Register baseReg = firstRegister(insn, 1);
                    if (baseReg != null) {
                        Long page = pendingAdrp.get(baseReg.getName());
                        if (page != null) {
                            Long imm = firstScalarOrAddress(insn, 1);
                            long full = page + (imm == null ? 0L : imm);
                            result.computeIfAbsent(full, k -> new ArrayList<>()).add(insn.getAddress());
                        }
                    }
                }
            } catch (Exception ignore) {
            }
        }
        return result;
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

    private void clearNoReturnChain(Address addr) {
        try {
            Function fn = currentProgram.getListing().getFunctionAt(addr);
            if (fn == null) {
                try {
                    fn = createFunction(addr, null);
                } catch (Exception ignore) {
                    fn = null;
                }
            }
            int guard = 0;
            while (fn != null && guard++ < 10) {
                if (fn.hasNoReturn()) {
                    fn.setNoReturn(false);
                    println("Cleared no-return flag on " + fn.getName() + " @ " + fn.getEntryPoint());
                }
                if (fn.isThunk()) {
                    fn = fn.getThunkedFunction(false);
                } else {
                    break;
                }
            }
        } catch (Exception ex) {
            println("clearNoReturnChain failed: " + ex.getMessage());
        }
    }

    private Function tryForceCreateFunction(Address from, Address marker) {
        final int maxBackBytes = 0x4000;
        final int maxForwardDisasmBytes = 0x3000;
        try {
            Address searchStart = from.subtract(maxBackBytes);
            Address a = from;
            Address foundEntry = null;
            while (a.compareTo(searchStart) >= 0) {
                Instruction insn = currentProgram.getListing().getInstructionAt(a);
                if (insn == null) {
                    try {
                        disassemble(a);
                        insn = currentProgram.getListing().getInstructionAt(a);
                    } catch (Exception ignore) {
                        insn = null;
                    }
                }
                if (insn != null && "bl".equals(insn.getMnemonicString())) {
                    Address[] flows = insn.getFlows();
                    if (flows != null) {
                        for (Address flow : flows) {
                            if (flow.equals(marker)) {
                                foundEntry = a;
                                break;
                            }
                        }
                    }
                }
                if (foundEntry != null) break;
                try {
                    a = a.subtract(4);
                } catch (Exception overflow) {
                    break;
                }
            }

            if (foundEntry == null) {
                return null;
            }

            Address fwdEnd = foundEntry.add(maxForwardDisasmBytes);
            Address d = foundEntry;
            while (d != null && d.compareTo(fwdEnd) <= 0) {
                if (currentProgram.getListing().getInstructionAt(d) == null) {
                    try {
                        disassemble(d);
                    } catch (Exception ignore) {
                    }
                }
                try {
                    d = d.add(4);
                } catch (Exception overflow) {
                    break;
                }
            }

            Function fn = currentProgram.getListing().getFunctionAt(foundEntry);
            if (fn == null) {
                fn = createFunction(foundEntry, null);
            }

            if (fn != null && (fn.isThunk() || fn.getBody().getNumAddresses() <= 4)) {
                try {
                    currentProgram.getListing().removeFunction(foundEntry);
                } catch (Exception ignore) {
                }
                AddressSet body = new AddressSet();
                InstructionIterator insns = currentProgram.getListing()
                        .getInstructions(new AddressSet(foundEntry, fwdEnd), true);
                while (insns.hasNext()) {
                    Instruction insn = insns.next();
                    body.add(insn.getMinAddress(), insn.getMaxAddress());
                }
                fn = currentProgram.getListing().createFunction(
                        null, foundEntry, body, ghidra.program.model.symbol.SourceType.USER_DEFINED);
            }
            return fn;
        } catch (Exception ex) {
            return null;
        }
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
}
