// Ghidra headless post-script.
//
// Strategic pivot #2, after FindBlockIdRefs.java confirmed string-based
// searching is architecturally dead for this goal: any string
// ("redstone_signal", "minecraft:redstone_wire", ...) only ever gets
// referenced by cold registration/compat code, because the engine
// resolves strings to numeric IDs once at load time and all later
// hot-path code (tick simulation, rendering) operates purely on those
// IDs/pointers - no string reference survives into the code we
// actually need to find.
//
// QYCottage/BedrockTools (a published, working LeviLaunchroid MOD for
// this same engine) sidesteps this entirely: it never searches by name
// at all. It finds its handful of entry points via hand-reverse-
// engineered AOB (array-of-bytes) signatures - raw instruction-pattern
// matches with wildcard bytes - taken directly from the compiled
// machine code shape of each target function, independent of any
// string or symbol. This script takes BedrockTools' own published
// signatures (src/core/memory/Signatures.cpp in that repo) and runs
// them as AOB scans against THIS build of libminecraftpe.so, to locate
// the same functions here: BlockSource::getBlock (returns a Block*
// for a world position - the starting point for reading ANY live block
// state), BlockSource::getBrightness, and
// BlockSource::isSolidBlockingBlock. Once getBlock's address is
// confirmed in this binary, its callers (found the same way
// FindCallers.java already works) are the next lead: those are real,
// live, per-tick/per-render code that already knows how to read a
// block's current state, which is exactly the pattern a redstone_signal
// reader needs to replicate.
//
// Signature format matches BedrockTools' own Signatures.cpp: a
// space-separated string of two-hex-digit bytes, with "?" as a
// single-byte wildcard (matches anything).

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.ConsoleTaskMonitor;

public class ScanKnownSignatures extends GhidraScript {

    // Taken verbatim from QYCottage/BedrockTools' src/core/memory/Signatures.cpp.
    private static final String[][] SIGNATURES = {
        {"BlockSourceGetBlock",
         "? ? ? D1 ? ? ? A9 ? ? ? A9 ? ? ? A9 ? ? ? 91 56 D0 3B D5 ? ? ? F9 ? ? ? F9 ? ? ? B9 ? ? ? 79 1F 01 09 6B ? ? ? 54 ? ? ? 79 F3 03 00 AA 1F 01 09 6B ? ? ? 54 E0 03 00 91"},
        {"BlockSourceGetBrightness",
         "? ? ? A9 ? ? ? F9 ? ? ? A9 FD 03 00 91 F3 03 00 AA ? ? ? F9 F4 03 01 AA ? ? ? F9 ? ? ? F9 00 01 3F D6 ? ? ? F9 F5 03 00 AA"},
        {"BlockSourceIsSolidBlockingBlock",
         "? ? ? F9 ? ? ? B9 ? ? ? 29 ? ? ? F9 E1 03 08 2A"},
    };

    private PrintWriter out;

    private void emit(String line) {
        out.println(line);
        println(line);
    }

    @Override
    protected void run() throws Exception {
        out = new PrintWriter(new FileWriter("signature_scan_output.txt"));
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        for (String[] sigDef : SIGNATURES) {
            String name = sigDef[0];
            String sigStr = sigDef[1];
            emit("========== SIGNATURE: " + name + " ==========");
            emit("  pattern: " + sigStr);

            byte[] pattern = parsePattern(sigStr);
            byte[] mask = parseMask(sigStr);

            List<Address> hits = scanAllExecutable(pattern, mask);
            emit("  " + hits.size() + " match(es) found.");
            if (hits.isEmpty()) {
                emit("");
                continue;
            }

            for (Address hit : hits) {
                MemoryBlock blk = currentProgram.getMemory().getBlock(hit);
                emit("  match at " + hit + "  (block: " + (blk == null ? "?" : blk.getName()) + ")");

                Function fn = getFunctionContaining(hit);
                if (fn == null) {
                    try {
                        fn = createFunction(hit, null);
                    } catch (Exception ignore) {
                        fn = null;
                    }
                }
                if (fn == null) {
                    emit("    (could not resolve/create a Function at this address)");
                    emit("");
                    continue;
                }
                emit("    resolved to function " + fn.getName() + " @ " + fn.getEntryPoint());

                DecompileResults res = decomp.decompileFunction(fn, 60, new ConsoleTaskMonitor());
                String decompiledText;
                if (res != null && res.decompileCompleted()) {
                    decompiledText = res.getDecompiledFunction().getC();
                } else {
                    decompiledText = "(decompile failed for " + fn.getName() + ")";
                }
                emit("    ---- decompiled " + fn.getName() + " ----");
                emit(decompiledText);
                emit("    ---- end " + fn.getName() + " ----");
                emit("");
            }
            out.flush();
        }

        decomp.dispose();
        out.close();
        println("Done. Wrote signature_scan_output.txt (also mirrored to stdout above)");
    }

    // Parses "? ? ? D1 ..." into the concrete byte array (wildcards as 0x00
    // placeholders - never read without consulting the parallel mask).
    private byte[] parsePattern(String sigStr) {
        String[] toks = sigStr.trim().split("\\s+");
        byte[] out = new byte[toks.length];
        for (int i = 0; i < toks.length; i++) {
            if (toks[i].equals("?")) {
                out[i] = 0x00;
            } else {
                out[i] = (byte) Integer.parseInt(toks[i], 16);
            }
        }
        return out;
    }

    // Ghidra's Memory.findBytes mask convention: a mask byte of 0x00 means
    // "don't care" (wildcard) at that position, 0xFF means "must match
    // exactly" - this is the inverse sense of "1 = wildcard" so build it
    // accordingly.
    private byte[] parseMask(String sigStr) {
        String[] toks = sigStr.trim().split("\\s+");
        byte[] mask = new byte[toks.length];
        for (int i = 0; i < toks.length; i++) {
            mask[i] = toks[i].equals("?") ? (byte) 0x00 : (byte) 0xFF;
        }
        return mask;
    }

    private List<Address> scanAllExecutable(byte[] pattern, byte[] mask) throws Exception {
        List<Address> results = new ArrayList<>();
        Memory mem = currentProgram.getMemory();
        for (MemoryBlock block : mem.getBlocks()) {
            if (!block.isInitialized() || !block.isExecute()) continue;
            Address start = block.getStart();
            Address end = block.getEnd();
            Address cursor = start;
            while (cursor != null && cursor.compareTo(end) <= 0) {
                Address hit = mem.findBytes(cursor, end, pattern, mask, true, monitor);
                if (hit == null) break;
                results.add(hit);
                try {
                    cursor = hit.add(4); // AArch64 instructions are 4-byte aligned
                } catch (Exception overflow) {
                    break;
                }
                if (results.size() > 50) {
                    println("scanAllExecutable: capping at 50 matches for this signature");
                    break;
                }
            }
        }
        return results;
    }
}
