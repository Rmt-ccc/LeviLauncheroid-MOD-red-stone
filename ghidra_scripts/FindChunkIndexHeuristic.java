// Ghidra headless post-script.
//
// Self-derived, version-independent alternative to borrowing
// BedrockTools' AOB signatures (which turned out to target a different
// game build than the libminecraftpe.so currently analyzed here, and
// matched nothing / matched unrelated code - see signature_scan_output
// in Ghidra-Analysis-Data/Failure-File/).
//
// Instead of reusing someone else's byte-pattern signature, this script
// looks for a structural fingerprint that comes from Minecraft's own
// well-known, version-stable world storage layout rather than from any
// specific compiled build: a 16x16x16 sub-chunk's block storage is
// indexed by flattening a local (x, y, z) position (each 0..15) into
// one integer, almost always via the textbook formula
//     index = (x & 0xF) | ((z & 0xF) << 4) | ((y & 0xF) << 8)
// (or a permutation of which axis gets which shift - x/z order can
// vary, but the shift amounts 4 and 8 combined with an 0xF mask are
// the structural signature of ANY "get the block at this local
// position" accessor, independent of compiler, optimization level, or
// game version). Any function built around this arithmetic is
// necessarily reading live per-tick block storage - exactly the kind
// of code BlockSource::getBlock (and the block-state readers chained
// off it) must contain, so it's a solid, non-substitute way to
// relocate that function in THIS binary specifically.
//
// Technique: a cheap instruction-level scan (no decompiling needed
// yet) for "AND <reg>, <reg>, #0xf"-style masking followed, within a
// short window, by two LSL-immediate instructions using shift amounts
// 4 and 8 on different source values. Only the resulting handful of
// candidate functions get decompiled for human review.

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.task.ConsoleTaskMonitor;

public class FindChunkIndexHeuristic extends GhidraScript {

    // How many instructions ahead of an "AND #0xf" to look for the two
    // companion shifts. Generous, since a compiler may interleave
    // unrelated instructions (register spills, the other axis' own
    // masking, etc.) between the three operations.
    private static final int WINDOW_INSNS = 48;

    private PrintWriter out;

    private void emit(String line) {
        out.println(line);
        println(line);
    }

    @Override
    protected void run() throws Exception {
        out = new PrintWriter(new FileWriter("chunk_index_heuristic_output.txt"));
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        emit("Force-disassembling all executable memory (closing analyzer coverage gaps)...");
        int newlyDisassembled = disassembleAllExecutableCode();
        emit("Force-disassembly pass added " + newlyDisassembled + " new instruction(s).");
        emit("");
        emit("Scanning for AND #0xf followed within " + WINDOW_INSNS
                + " instructions by LSL-immediate #4 and LSL-immediate #8 "
                + "(the sub-chunk local-position indexing fingerprint)...");

        List<Instruction> allInsns = new ArrayList<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            allInsns.add(it.next());
        }
        emit("Total instructions to scan: " + allInsns.size());
        emit("");

        Set<Address> candidateHits = new LinkedHashSet<>();

        for (int i = 0; i < allInsns.size(); i++) {
            Instruction andInsn = allInsns.get(i);
            if (!isAndWithImmediate(andInsn, 0xfL)) continue;

            boolean sawShift4 = false;
            boolean sawShift8 = false;
            int end = Math.min(i + WINDOW_INSNS, allInsns.size());
            for (int j = i + 1; j < end; j++) {
                Instruction cand = allInsns.get(j);
                Long shiftAmt = lslImmediateAmount(cand);
                if (shiftAmt == null) continue;
                if (shiftAmt == 4L) sawShift4 = true;
                if (shiftAmt == 8L) sawShift8 = true;
                if (sawShift4 && sawShift8) break;
            }

            if (sawShift4 && sawShift8) {
                candidateHits.add(andInsn.getAddress());
            }
        }

        emit("Raw hits (AND#0xf site): " + candidateHits.size());
        emit("");

        Set<Function> candidateFunctions = new LinkedHashSet<>();
        for (Address hit : candidateHits) {
            Function fn = getFunctionContaining(hit);
            if (fn != null) {
                candidateFunctions.add(fn);
            } else {
                emit("  hit at " + hit + " - no containing Function (skipped)");
            }
        }

        emit("Distinct candidate function(s): " + candidateFunctions.size());
        emit("");

        int shown = 0;
        for (Function fn : candidateFunctions) {
            shown++;
            if (shown > 40) {
                emit("(stopping decompile output after 40 candidate functions - see raw hit count above)");
                break;
            }
            emit("========== CANDIDATE: " + fn.getName() + " @ " + fn.getEntryPoint() + " ==========");
            DecompileResults res = decomp.decompileFunction(fn, 60, new ConsoleTaskMonitor());
            String decompiledText;
            if (res != null && res.decompileCompleted()) {
                decompiledText = res.getDecompiledFunction().getC();
            } else {
                decompiledText = "(decompile failed for " + fn.getName() + ")";
            }
            emit(decompiledText);
            emit("========== end " + fn.getName() + " ==========");
            emit("");
            out.flush();
        }

        decomp.dispose();
        out.close();
        println("Done. Wrote chunk_index_heuristic_output.txt (also mirrored to stdout above)");
    }

    // Matches AArch64 "and  Xd, Xn, #imm" / "and Wd, Wn, #imm" where imm
    // equals the target mask exactly.
    private boolean isAndWithImmediate(Instruction insn, long target) {
        String mn = insn.getMnemonicString();
        if (mn == null || !mn.equalsIgnoreCase("and")) return false;
        if (insn.getNumOperands() < 3) return false;
        Long imm = firstScalar(insn, 2);
        return imm != null && imm == target;
    }

    // Matches AArch64 "lsl Xd, Xn, #amt" and returns amt, or null if this
    // instruction isn't an immediate-shift LSL.
    private Long lslImmediateAmount(Instruction insn) {
        String mn = insn.getMnemonicString();
        if (mn == null || !mn.equalsIgnoreCase("lsl")) return null;
        if (insn.getNumOperands() < 3) return null;
        return firstScalar(insn, 2);
    }

    private Long firstScalar(Instruction insn, int opIndex) {
        if (opIndex >= insn.getNumOperands()) return null;
        Object[] objs = insn.getOpObjects(opIndex);
        if (objs == null) return null;
        for (Object o : objs) {
            if (o instanceof Scalar) return ((Scalar) o).getUnsignedValue();
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
