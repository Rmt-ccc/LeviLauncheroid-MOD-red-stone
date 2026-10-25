// Ghidra headless post-script.
//
// Follow-up to FindChunkIndexHeuristic.java's breakthrough: that script
// located FUN_09053250, whose decompilation contains two concrete call
// sites of the form
//     lVar10 = (**(code **)(*plVar9 + 0x20))(plVar9, index);
// - a virtual dispatch through vtable slot 4 (byte offset 0x20) that,
// given a chunk/subchunk-like object and a flattened local-position
// index, returns a Block* (confirmed by a later identity comparison on
// *(long*)(lVar10 + 0x110), used by FUN_09053250 to tell two blocks
// apart). Ghidra never resolves this call to a concrete function - the
// object's dynamic type isn't known statically (no RTTI in this build),
// so the callee address only exists at runtime, inside *some* vtable
// this binary never names for us directly.
//
// This script doesn't try to resolve that one indirect call. Instead it
// looks for the vtable itself by its shape: a C++ vtable is just a
// contiguous array of code pointers sitting in read-only/relro data, and
// whichever one it is, its slot-4 entry (same byte offset 0x20 as the
// call above) must be a short "index into per-block storage" accessor -
// something that takes the object pointer and the index parameter, does
// some arithmetic on the index (a multiply/shift to turn it into a byte
// offset - the block struct's stride), and loads+returns a pointer. That
// is a structural fingerprint independent of any one build's addresses,
// in the same spirit as FindChunkIndexHeuristic's local-position mask.
//
// Technique, two stages so the expensive part (decompiling) only runs on
// a short list:
//   1. Scan every non-executable, initialized memory block for 8-byte
//      aligned runs where slots 0..4 (offsets 0x00..0x20) are each a
//      value that lands on a disassembled instruction inside executable
//      memory. That is "maybe a vtable with at least 5 live slots."
//   2. For the slot-4 target of each survivor, do a cheap instruction
//      walk (no decompiling) checking for an instruction that operates
//      on x1/w1 (the AAPCS64 second argument - here, the index) via
//      mul/lsl/add/ubfx/sbfx/sxtw, followed later by a load. Only
//      functions matching that shape get decompiled and printed, along
//      with any numeric stride literals found in the decompiled body -
//      that stride is the live Block struct's size, which is exactly
//      what's needed to make sense of the known +0x110 identity field
//      and to go looking for a redstone_signal-equivalent field in the
//      same struct.
//
// Candidates are for human review, same as FindChunkIndexHeuristic's -
// this narrows a binary-wide vtable search down to a short list, it
// doesn't claim to single out the one true BlockSource vtable.

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.app.script.GhidraScript;
import ghidra.util.task.ConsoleTaskMonitor;

public class FindVtableSlot4Candidates extends GhidraScript {

    private static final int SLOTS_CHECKED = 5;
    private static final long SLOT4_OFFSET = 0x20L;
    private static final int SHAPE_WALK_MAX_INSNS = 60;
    private static final int MAX_DECOMPILED_OUTPUT = 50;

    private static final Pattern STRIDE_PATTERN =
            Pattern.compile("(?:<<\\s*0x([0-9a-fA-F]+))|(?:\\*\\s*0x([0-9a-fA-F]+))");

    private PrintWriter out;

    private void emit(String line) {
        out.println(line);
        println(line);
    }

    @Override
    protected void run() throws Exception {
        out = new PrintWriter(new FileWriter("vtable_slot4_candidates_output.txt"));
        Memory mem = currentProgram.getMemory();
        Listing listing = currentProgram.getListing();

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
                    println("FindVtableSlot4Candidates: scanned " + scanned
                            + " candidate word(s), " + vtableHits.size() + " vtable-shaped hit(s) so far");
                }
                try {
                    addr = addr.add(8);
                } catch (Exception overflow) {
                    break;
                }
            }
        }
        emit("Scanned " + scanned + " candidate word(s).");
        emit("Vtable-shaped hits (slots 0..4 all land on disassembled code): " + vtableHits.size());
        emit("");

        emit("Stage 2: cheap instruction-shape check on each hit's slot-4 target "
                + "(x1/w1 index arithmetic followed by a load) before any decompiling...");

        Set<Address> shapeMatches = new LinkedHashSet<>();
        for (Address vtAddr : vtableHits) {
            Address slot4Target = readPointer(mem, vtAddr.add(SLOT4_OFFSET));
            if (slot4Target == null) continue;
            if (looksLikeIndexAccessor(listing, slot4Target)) {
                shapeMatches.add(slot4Target);
            }
        }
        emit("Slot-4 targets matching the index-accessor instruction shape: " + shapeMatches.size());
        emit("(" + vtableHits.size() + " vtable hit(s) may point at the same slot-4 function - "
                + "counted once above)");
        emit("");

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        int shown = 0;
        for (Address fnAddr : shapeMatches) {
            shown++;
            if (shown > MAX_DECOMPILED_OUTPUT) {
                emit("(stopping decompile output after " + MAX_DECOMPILED_OUTPUT
                        + " candidate functions - see hit count above)");
                break;
            }
            Function fn = getFunctionAt(fnAddr);
            if (fn == null) {
                fn = createFunction(fnAddr, null);
            }
            emit("========== CANDIDATE SLOT-4 FUNCTION @ " + fnAddr + " ==========");
            if (fn == null) {
                emit("(could not define a function at this address - skipped)");
                emit("");
                continue;
            }
            DecompileResults res = decomp.decompileFunction(fn, 60, new ConsoleTaskMonitor());
            String decompiledText;
            if (res != null && res.decompileCompleted()) {
                decompiledText = res.getDecompiledFunction().getC();
            } else {
                decompiledText = "(decompile failed for function at " + fnAddr + ")";
            }
            emit(decompiledText);

            Set<String> strides = new LinkedHashSet<>();
            Matcher m = STRIDE_PATTERN.matcher(decompiledText);
            while (m.find()) {
                String hex = m.group(1) != null ? m.group(1) : m.group(2);
                if (hex != null) strides.add("0x" + hex);
            }
            if (!strides.isEmpty()) {
                emit("possible stride/shift literal(s) seen in this function: " + strides);
            }
            emit("========== end function @ " + fnAddr + " ==========");
            emit("");
            out.flush();
        }

        decomp.dispose();
        out.close();
        println("Done. Wrote vtable_slot4_candidates_output.txt (also mirrored to stdout above)");
    }

    // True when addr..addr+0x20 holds 5 consecutive pointer-sized values
    // that each land on an already-disassembled instruction inside
    // executable memory - the cheap first-pass vtable shape check.
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

    // Cheap, decompile-free shape check: does this function read its
    // second argument (x1/w1, the AAPCS64 index parameter) through
    // multiply/shift/bitfield-extract arithmetic, and later issue a
    // load? Crude text-matching on operand representations, same spirit
    // as FindChunkIndexHeuristic's mnemonic/operand checks.
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
}
