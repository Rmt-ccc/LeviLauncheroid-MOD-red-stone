// Ghidra headless post-script.
//
// Follow-up to FindCallers.java's latest run: that script confirmed
// FUN_09053250 (the function containing the one known vtable+0x20
// live-Block-read call pattern) has exactly 2 direct "bl" callers in
// the whole binary, at 0x090549bc and 0x090649dc. Neither call site
// sits inside a Function Ghidra's analyzer (or FindCallers.java's old
// marker-based heuristic, built for a different target) could bound,
// so only raw disassembly windows around each call were dumped, not a
// full decompile.
//
// Both windows end the same way - immediately after the call to
// FUN_09053250, both write 1 to byte offset 0x1508 of the same base
// register (x19, the likely "this") and then call a second shared
// function at 0x09054f1c - strongly suggesting both call sites are
// either the same function (two branches of one bigger routine) or two
// closely related sibling functions with a shared calling convention.
//
// This script tries to pin down each call site's actual function entry
// point by walking backward from the call site looking for a standard
// AArch64 function-prologue shape (a stack-frame setup: "sub sp" and/or
// a "stp x29, x30, [sp, ...]" frame-pointer/link-register save, which
// AArch64 C++ codegen uses at the start of essentially every
// non-leaf function), then forces that address into a Function and
// decompiles it. This is the same class of technique as
// tryForceCreateFunction() in FindCallers.java, just driven by a
// generic prologue shape instead of a target-specific marker call, so
// it works for any as-yet-unidentified caller.

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.util.task.ConsoleTaskMonitor;

public class FindCallerPrologues extends GhidraScript {

    // The two orphan call sites FindCallers.java located, calling
    // FUN_09053250 directly via "bl".
    private static final long[] CALL_SITES = {
        0x090549bcL,
        0x090649dcL,
    };

    private static final int MAX_BACKWARD_INSNS = 2000;

    private PrintWriter out;

    private void emit(String line) {
        out.println(line);
        println(line);
    }

    @Override
    protected void run() throws Exception {
        out = new PrintWriter(new FileWriter("caller_prologues_output.txt"));
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        for (long callSiteOffset : CALL_SITES) {
            Address callSite = toAddr(callSiteOffset);
            emit("========== CALL SITE " + callSite + " ==========");

            Address entry = findPrologueBackward(callSite);
            if (entry == null) {
                emit("  No AArch64 prologue shape found within " + MAX_BACKWARD_INSNS
                        + " instructions backward from this call site.");
                emit("");
                out.flush();
                continue;
            }
            emit("  Candidate function entry (prologue found): " + entry
                    + " (" + callSite.subtract(entry) + " bytes before the call site)");

            Function fn = getFunctionAt(entry);
            if (fn == null) {
                try {
                    fn = createFunction(entry, null);
                } catch (Exception e) {
                    emit("  createFunction failed at " + entry + ": " + e.getMessage());
                }
            }
            if (fn == null) {
                emit("  Could not create a Function at " + entry + " - leaving as raw disassembly only.");
                emit("");
                out.flush();
                continue;
            }

            emit("  ---- decompiled " + fn.getName() + " @ " + fn.getEntryPoint() + " ----");
            DecompileResults res = decomp.decompileFunction(fn, 90, new ConsoleTaskMonitor());
            String decompiledText;
            if (res != null && res.decompileCompleted()) {
                decompiledText = res.getDecompiledFunction().getC();
            } else {
                decompiledText = "(decompile failed for function at " + entry + ")";
            }
            emit(decompiledText);
            emit("  ---- end " + fn.getName() + " ----");
            emit("");
            out.flush();
        }

        decomp.dispose();
        out.close();
        println("Done. Wrote caller_prologues_output.txt (also mirrored to stdout above)");
    }

    // Walks backward instruction-by-instruction from callSite looking
    // for a standard AArch64 prologue: a "stp x29, x30, [sp, #-N]!" (or
    // the non-pre-indexed "stp x29, x30, [sp, #N]" variant paired with
    // a preceding "sub sp, sp, #N") - the frame-pointer/link-register
    // save virtually every non-leaf AArch64 C++ function begins with.
    // Returns the address of that stp/sub instruction (treated as the
    // function entry), or null if nothing matching turns up in range.
    private Address findPrologueBackward(Address callSite) {
        List<Instruction> backward = new ArrayList<>();
        Instruction insn = currentProgram.getListing().getInstructionAt(callSite);
        if (insn == null) return null;

        Instruction walker = insn;
        for (int i = 0; i < MAX_BACKWARD_INSNS; i++) {
            walker = walker.getPrevious();
            if (walker == null) break;
            backward.add(walker);

            String mn = walker.getMnemonicString();
            if (mn == null) continue;

            // stp x29, x30, [sp, ...] - the frame-pointer/link-register
            // save pair that marks the very start of the prologue.
            if (mn.equalsIgnoreCase("stp")) {
                String rep = walker.toString().toLowerCase();
                if (rep.contains("x29") && rep.contains("x30") && rep.contains("sp")) {
                    // Prefer the earliest matching "sub sp, sp, #imm"
                    // immediately before this stp, if present (separate
                    // pre-prologue stack-frame allocation); otherwise
                    // the stp itself is the entry.
                    Instruction prev = walker.getPrevious();
                    if (prev != null && "sub".equalsIgnoreCase(prev.getMnemonicString())
                            && prev.toString().toLowerCase().contains("sp")) {
                        return prev.getAddress();
                    }
                    return walker.getAddress();
                }
            }

            // A bare, unconditional return in the instruction stream
            // before we've seen a prologue strongly suggests we've
            // walked past the end of the PREVIOUS function without
            // finding our own entry (i.e. our target function has no
            // standard frame, or sits right after another function
            // with no gap) - stop here rather than attributing an
            // unrelated function's body to our call site.
            if (mn.equalsIgnoreCase("ret")) {
                break;
            }
        }
        return null;
    }
}
