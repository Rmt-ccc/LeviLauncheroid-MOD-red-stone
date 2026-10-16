// Ghidra headless post-script.
//
// For each target string below: finds it in Defined Strings, finds every
// place in code that references it, and dumps the containing function's
// name, address, and decompiled C-like pseudocode to an output text file
// (state_refs_output.txt).

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
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.ConsoleTaskMonitor;

public class FindStateRefs extends GhidraScript {

    // Only the targets that still weren't usefully resolved after the
    // previous run (bite_counter and respawn_anchor_charge already gave
    // clean results from the raw-disassembly fallback - no need to spend
    // time on them again; honey_level/open_bit aren't defined strings at
    // all, so re-checking them is instant and harmless but left out here
    // to keep the run focused).
    private static final String[] TARGETS = {
        "composter_fill_level",
        "sculk_sensor_phase",
        "lever_direction",
        "redstone_signal",
    };

    // Every real function body in this binary starts with a call to this
    // fixed helper address (confirmed across multiple prior samples -
    // repeater/comparator/etc. decompiles all showed the stack-canary
    // setup pattern, and the raw-disassembly dumps from the last run show
    // "bl 0x0e656420" as the first instruction of every function that has
    // one). When Ghidra's auto-analysis missed a function (no Function
    // object at a reference site), we scan backward for the nearest one
    // of these calls and treat it as the function's entry point, then
    // force Ghidra to define a Function there so the decompiler can run.
    private static final long FUNC_PROLOGUE_MARKER_OFFSET = 0x0e656420L;

    // Helper that writes a line to BOTH the output file and the headless
    // stdout log (so results are readable straight from the Actions run
    // page / step log, with no file download or unzip needed).
    private PrintWriter out;

    private void emit(String line) {
        out.println(line);
        println(line); // GhidraScript.println -> headless stdout -> analyze.log
    }

    @Override
    protected void run() throws Exception {
        out = new PrintWriter(new FileWriter("state_refs_output.txt"));
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        // Cache decompiled output per function entry point so a function
        // referenced many times (e.g. from a 16-case switch, or from many
        // call sites sharing one function) is only decompiled and printed
        // ONCE instead of once per reference.
        Map<Address, String> decompCache = new LinkedHashMap<>();

        Address marker = toAddr(FUNC_PROLOGUE_MARKER_OFFSET);

        // The forced function creation below kept collapsing into a
        // trivial "thunk_FUN_08603160() { thunk_FUN_08603160(); }" stub
        // for every target. Root cause: whatever is at the marker address
        // (or what it thunks to) is flagged NO RETURN in this program -
        // likely a bad auto-analysis artifact from the broken exception-
        // handler tables we saw earlier. With the first instruction of a
        // forced function being a call to something marked no-return,
        // Ghidra's flow analysis assumes execution can't continue past
        // it, so the "function" it creates is just that one instruction -
        // which then LOOKS like / gets named as a thunk. Clearing the
        // no-return flag on the marker (and anything it thunks to) lets
        // flow analysis continue past the call into the real function
        // body, same as it must for all the OTHER functions that already
        // decompiled cleanly (their decompiler output just hides this
        // call as the elided stack-canary-style prologue).
        clearNoReturnChain(marker);

        for (String target : TARGETS) {
            emit("========== STRING: " + target + " ==========");
            List<Address> hits = findExactStringAddresses(target);
            if (hits.isEmpty()) {
                emit("  (not found as a defined string)");
                emit("");
                continue;
            }
            for (Address strAddr : hits) {
                emit("  string data at " + strAddr);
                ReferenceIterator refs = currentProgram.getReferenceManager()
                        .getReferencesTo(strAddr);

                // Group reference addresses by containing function first.
                Map<Function, List<Address>> byFunction = new LinkedHashMap<>();
                List<Address> noFunctionRefs = new ArrayList<>();
                boolean any = false;
                while (refs.hasNext()) {
                    any = true;
                    Reference ref = refs.next();
                    Address from = ref.getFromAddress();
                    Function fn = getFunctionContaining(from);
                    if (fn == null) {
                        // Try to recover a function boundary by locating the
                        // nearest preceding prologue-marker call and forcing
                        // Ghidra to define a Function starting there.
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
                // Still no Function object for these (no prologue marker
                // found within the search range either) - fall back to a
                // raw disassembly window around each address so there's at
                // least something to read by hand.
                for (Address from : noFunctionRefs) {
                    emit("    referenced from " + from
                            + "  (not inside a known function, no prologue marker found either"
                            + " - raw disassembly window below)");
                    try {
                        Address winStart = from.subtract(0x100);
                        Address winEnd = from.add(0x100);
                        AddressSet window = new AddressSet(winStart, winEnd);
                        Address a = winStart;
                        while (a != null && a.compareTo(winEnd) <= 0) {
                            try {
                                disassemble(a);
                            } catch (Exception ignore) {
                                // already code, or not a valid instruction start - skip
                            }
                            try {
                                a = a.add(4);
                            } catch (Exception overflow) {
                                break; // hit the end of the address space
                            }
                        }
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
                if (!any) {
                    emit("    (no references found to this string)");
                }
            }
            emit("");
            out.flush();
        }

        decomp.dispose();
        out.close();
        println("Done. Wrote state_refs_output.txt (also mirrored to stdout above)");
    }

    // Clears the "does not return" flag on whatever Function exists at
    // `addr`, following the thunk chain (a thunk may itself point at
    // another thunk) up to a safety limit. Also forces a Function to
    // exist at `addr` if none does yet, so there is something to clear.
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

    // Scans backward from `from` for the nearest "bl <marker>" instruction
    // (AArch64 instructions are fixed 4-byte width, so step by 4), treats
    // that instruction's address as a function entry point, and asks
    // Ghidra to define a Function there. Returns the resulting Function,
    // or null if no marker was found within the search range or function
    // creation failed.
    private Function tryForceCreateFunction(Address from, Address marker) {
        final int maxBackBytes = 0x4000;
        final int maxForwardDisasmBytes = 0x3000;
        try {
            Address searchStart = from.subtract(maxBackBytes);
            Address a = from;
            Address foundEntry = null;
            while (a.compareTo(searchStart) >= 0) {
                // Make sure this address is disassembled so we can inspect
                // it as an instruction; skip addresses that already are
                // (common once a neighboring reference has covered them).
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
                    break; // hit the start of the address space
                }
            }

            if (foundEntry == null) {
                return null;
            }

            // Disassemble forward from the recovered entry point so Ghidra
            // has enough code in the listing to compute the function body,
            // then define the function.
            Address fwdEnd = foundEntry.add(maxForwardDisasmBytes);
            Address d = foundEntry;
            while (d != null && d.compareTo(fwdEnd) <= 0) {
                if (currentProgram.getListing().getInstructionAt(d) == null) {
                    try {
                        disassemble(d);
                    } catch (Exception ignore) {
                        // fine - might be data or already covered
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

            // Safety net: if this STILL came back as a trivial thunk whose
            // body is only the single "bl marker" instruction (the bug we
            // saw before clearNoReturnChain() existed - or a recurrence of
            // it for some other reason), blow it away and rebuild the
            // function with an EXPLICIT body spanning everything we just
            // disassembled, bypassing Ghidra's flow-based body computation
            // (and its thunk auto-detection) entirely.
            if (fn != null && (fn.isThunk() || fn.getBody().getNumAddresses() <= 4)) {
                try {
                    currentProgram.getListing().removeFunction(foundEntry);
                } catch (Exception ignore) {
                    // ignore - may not have existed as a plain function
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
        DataIterator it = currentProgram.getListing().getDefinedData(true);
        while (it.hasNext()) {
            Data d = it.next();
            if (!d.hasStringValue()) continue;
            Object val = d.getValue();
            if (val == null) continue;
            String s = val.toString();
            if (s.equals(target)) {
                results.add(d.getAddress());
            }
        }
        return results;
    }
}
