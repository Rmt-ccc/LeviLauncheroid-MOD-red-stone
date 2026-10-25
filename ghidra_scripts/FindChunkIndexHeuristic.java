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
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Iterator;
import java.util.LinkedHashSet;
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

        // Single streaming pass over the instruction iterator - never
        // materializes the full instruction list (which, on this
        // binary's size after force-disassembly, is large enough to
        // exhaust the default headless JVM heap; an earlier version of
        // this script did collect it all into an ArrayList first and
        // the run aborted with OutOfMemoryError). Each "AND #0xf" sighting
        // opens a small pending window (bounded by WINDOW_INSNS) that is
        // checked against every instruction seen afterward and expires on
        // its own; memory use is bounded by the number of concurrently
        // open windows, not by total instruction count.
        Set<Address> candidateHits = new LinkedHashSet<>();
        Deque<PendingAnd> pending = new ArrayDeque<>();

        InstructionIterator it = currentProgram.getListing().getInstructions(true);
        long scanned = 0;
        while (it.hasNext()) {
            Instruction insn = it.next();
            scanned++;

            Long shiftAmt = lslImmediateAmount(insn);
            if (shiftAmt != null) {
                for (PendingAnd p : pending) {
                    if (shiftAmt == 4L) p.sawShift4 = true;
                    if (shiftAmt == 8L) p.sawShift8 = true;
                }
            }

            // Expire windows that have run out of lookahead room, and
            // record any that matched both shifts before expiring.
            Iterator<PendingAnd> pit = pending.iterator();
            while (pit.hasNext()) {
                PendingAnd p = pit.next();
                p.remaining--;
                if (p.sawShift4 && p.sawShift8) {
                    candidateHits.add(p.andAddress);
                    pit.remove();
                } else if (p.remaining <= 0) {
                    pit.remove();
                }
            }

            if (isAndWithImmediate(insn, 0xfL)) {
                pending.addLast(new PendingAnd(insn.getAddress(), WINDOW_INSNS));
            }

            if ((scanned & 0xFFFFFF) == 0) {
                println("FindChunkIndexHeuristic: scanned " + scanned + " instruction(s) so far, "
                        + candidateHits.size() + " hit(s), " + pending.size() + " window(s) open");
            }
        }
        emit("Total instructions scanned: " + scanned);
        emit("");

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

    private static final class PendingAnd {
        final Address andAddress;
        int remaining;
        boolean sawShift4;
        boolean sawShift8;

        PendingAnd(Address andAddress, int remaining) {
            this.andAddress = andAddress;
            this.remaining = remaining;
        }
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
