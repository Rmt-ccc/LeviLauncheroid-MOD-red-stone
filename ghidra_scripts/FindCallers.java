// Ghidra headless post-script.
//
// Follow-up to FindStateRefs.java. That script found, for each
// BlockState property name (redstone_signal, repeater_delay, ...), the
// function(s) that construct a BlockState value object for every
// possible aux/data value of that property (one function per property,
// containing one switch-case per possible value - these run at world
// load time to convert legacy block data into Bedrock's BlockState
// system).
//
// All of those constructor functions were observed calling the exact
// same low-level helper at address TARGET_HELPER (func_0x1256e808 in
// the earlier decompile output) to intern/register the constructed
// state value. This script's job is to find every caller of a small,
// curated set of addresses - primarily that shared helper, and the
// redstone_signal constructor itself - and dump the caller functions'
// decompiled pseudocode, so we can trace a path from "value exists"
// toward "value can be read back for a live block at runtime" (which is
// what the LeviLaunchroid MOD needs in order to render e.g. a redstone
// wire's current signal strength in-world).
//
// Deliberately narrow in scope (a handful of target addresses, not a
// full-binary string sweep) to keep this a bounded, fast pass that can
// run in the same headless session as FindStateRefs.java.

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.ConsoleTaskMonitor;

public class FindCallers extends GhidraScript {

    // Addresses to find callers of. Named for readability in the output.
    private static final long[] TARGET_ADDRS = {
        0x1256e808L, // shared "intern/register BlockState value" helper,
                     // called identically from every per-property
                     // constructor function FindStateRefs.java found
                     // (redstone_signal's, repeater_delay's, etc.)
        0x11633944L, // redstone_signal's own constructor function
                     // (switch over aux value 0..15) - most relevant
                     // property for this project
    };

    private static final long FUNC_PROLOGUE_MARKER_OFFSET = 0x0e656420L;

    // Safety cap: a hot shared helper could have thousands of call
    // sites across the whole binary (every block property funnels
    // through it). Decompiling and dumping all of them would blow the
    // output file up uselessly - we only need enough examples to see
    // the calling pattern/convention, so cap how many distinct caller
    // FUNCTIONS get decompiled per target address.
    private static final int MAX_CALLER_FUNCTIONS_PER_TARGET = 25;

    private PrintWriter out;

    private void emit(String line) {
        out.println(line);
        println(line);
    }

    @Override
    protected void run() throws Exception {
        out = new PrintWriter(new FileWriter("caller_refs_output.txt"));
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Address marker = toAddr(FUNC_PROLOGUE_MARKER_OFFSET);
        clearNoReturnChain(marker);

        emit("Force-disassembling all executable memory...");
        int newlyDisassembled = disassembleAllExecutableCode();
        emit("Force-disassembly pass added " + newlyDisassembled + " new instruction(s).");

        emit("Building bl-call index over the whole program (one pass)...");
        Map<Long, List<Address>> callIndex = buildCallIndex();
        emit("Index built: " + callIndex.size() + " distinct call targets materialized in code.");
        emit("");

        Map<Address, String> decompCache = new LinkedHashMap<>();

        for (long targetOffset : TARGET_ADDRS) {
            Address target = toAddr(targetOffset);
            emit("========== CALLERS OF: " + target + " ==========");
            List<Address> callSites = callIndex.get(targetOffset);
            if (callSites == null || callSites.isEmpty()) {
                emit("  (no 'bl' instructions found targeting this address)");
                emit("");
                out.flush();
                continue;
            }
            emit("  " + callSites.size() + " call site(s) total");

            Map<Function, List<Address>> byFunction = new LinkedHashMap<>();
            for (Address from : callSites) {
                Function fn = getFunctionContaining(from);
                if (fn == null) {
                    fn = tryForceCreateFunction(from, marker);
                }
                if (fn != null) {
                    byFunction.computeIfAbsent(fn, k -> new ArrayList<>()).add(from);
                }
            }
            emit("  " + byFunction.size() + " distinct caller function(s)");
            emit("");

            int shown = 0;
            for (Map.Entry<Function, List<Address>> e : byFunction.entrySet()) {
                if (shown >= MAX_CALLER_FUNCTIONS_PER_TARGET) {
                    emit("  ... (" + (byFunction.size() - shown)
                            + " more caller function(s) omitted, cap reached)");
                    break;
                }
                Function fn = e.getKey();
                List<Address> froms = e.getValue();
                StringBuilder fromsStr = new StringBuilder();
                for (int i = 0; i < froms.size(); i++) {
                    if (i > 0) fromsStr.append(", ");
                    fromsStr.append(froms.get(i));
                }
                emit("  caller " + fn.getName() + " @ " + fn.getEntryPoint()
                        + "  (calls from [" + fromsStr + "])");

                String decompiledText = decompCache.get(fn.getEntryPoint());
                if (decompiledText == null) {
                    DecompileResults res = decomp.decompileFunction(fn, 60, new ConsoleTaskMonitor());
                    if (res != null && res.decompileCompleted()) {
                        decompiledText = res.getDecompiledFunction().getC();
                    } else {
                        decompiledText = "(decompile failed for " + fn.getName() + ")";
                    }
                    decompCache.put(fn.getEntryPoint(), decompiledText);
                }
                emit("    ---- decompiled " + fn.getName() + " ----");
                emit(decompiledText);
                emit("    ---- end " + fn.getName() + " ----");
                shown++;
                out.flush();
            }
            emit("");
        }

        decomp.dispose();
        out.close();
        println("Done. Wrote caller_refs_output.txt (also mirrored to stdout above)");
    }

    // Same disassembly-coverage pass as FindStateRefs.java - needed
    // again here because each headless run starts from a fresh,
    // deleted project (-deleteProject), so nothing carries over between
    // script runs within the same analyzeHeadless invocation only
    // shares the one already-imported/analyzed program, but we still
    // want to be defensive in case this script ever runs standalone.
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
                        // data mixed into executable block - skip
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

    // One linear pass over every disassembled instruction, recording
    // every "bl <target>" site keyed by the target's raw offset.
    private Map<Long, List<Address>> buildCallIndex() {
        Map<Long, List<Address>> result = new HashMap<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            Instruction insn = it.next();
            String mn = insn.getMnemonicString();
            if (mn == null || !mn.equalsIgnoreCase("bl")) continue;
            try {
                Address[] flows = insn.getFlows();
                if (flows == null) continue;
                for (Address flow : flows) {
                    result.computeIfAbsent(flow.getOffset(), k -> new ArrayList<>()).add(insn.getAddress());
                }
            } catch (Exception ignore) {
                // skip malformed/unsupported operand encodings
            }
        }
        return result;
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
                        // fine
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
            return fn;
        } catch (Exception ex) {
            return null;
        }
    }
}
