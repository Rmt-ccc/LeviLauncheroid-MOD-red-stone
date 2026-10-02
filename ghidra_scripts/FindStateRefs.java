// Ghidra headless post-script.
//
// For each target string below: finds it in Defined Strings, finds every
// place in code that references it, and dumps the containing function's
// name, address, and decompiled C-like pseudocode to an output text file
// (state_refs_output.txt).

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.ConsoleTaskMonitor;

public class FindStateRefs extends GhidraScript {

    private static final String[] TARGETS = {
        "repeater_delay",
        "output_subtract_bit",
        "powered_bit",
        "toggle_bit",
        "fill_level",
        "composter_fill_level",
        "sculk_sensor_phase",
        "attached_bit",
        "disarmed_bit",
        "rail_data_bit",
        "triggered_bit",
        "orientation",
    };

    @Override
    protected void run() throws Exception {
        PrintWriter out = new PrintWriter(new FileWriter("state_refs_output.txt"));
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        for (String target : TARGETS) {
            out.println("========== STRING: " + target + " ==========");
            List<Address> hits = findExactStringAddresses(target);
            if (hits.isEmpty()) {
                out.println("  (not found as a defined string)");
                out.println();
                continue;
            }
            for (Address strAddr : hits) {
                out.println("  string data at " + strAddr);
                ReferenceIterator refs = currentProgram.getReferenceManager()
                        .getReferencesTo(strAddr);
                boolean any = false;
                while (refs.hasNext()) {
                    any = true;
                    Reference ref = refs.next();
                    Address from = ref.getFromAddress();
                    Function fn = getFunctionContaining(from);
                    out.println("    referenced from " + from
                            + (fn != null ? "  in function " + fn.getName()
                                    + " @ " + fn.getEntryPoint() : "  (not inside a known function)"));
                    if (fn != null) {
                        DecompileResults res = decomp.decompileFunction(fn, 60, new ConsoleTaskMonitor());
                        if (res != null && res.decompileCompleted()) {
                            out.println("    ---- decompiled " + fn.getName() + " ----");
                            out.println(res.getDecompiledFunction().getC());
                            out.println("    ---- end " + fn.getName() + " ----");
                        } else {
                            out.println("    (decompile failed for " + fn.getName() + ")");
                        }
                    }
                }
                if (!any) {
                    out.println("    (no references found to this string)");
                }
            }
            out.println();
            out.flush();
        }

        decomp.dispose();
        out.close();
        println("Done. Wrote state_refs_output.txt");
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
