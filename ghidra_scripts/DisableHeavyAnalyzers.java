// Ghidra headless PRE-script (runs after import, before auto-analysis).
// Disables memory-hungry analyzers we don't need for finding string
// cross-references and decompiling a handful of functions - in
// particular the GCC Exception Handler analyzer, which was causing
// OutOfMemoryError on this large binary by building huge LSDA/reference
// tables we never use.

import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

import java.util.List;

public class DisableHeavyAnalyzers extends GhidraScript {

    private static final String[] DISABLE_IF_NAME_CONTAINS = {
        "exception handler",
        "exception handling",
        // Observed eating 738 of a 900-second analysis budget on this
        // binary (per-analyzer timing report), starving out later,
        // more important analyzers (like ASCII Strings) before the
        // per-file analysis timeout hit. We don't need call-fixup
        // matching (library call-convention patching) for reading
        // aux-value branching logic out of a handful of functions.
        "call-fixup",
        "call fixup",
        // With Call-Fixup Installer gone, THESE three ate the rest of
        // the 900s budget instead (247 + 225 + 25 secs, per the timing
        // report) - still leaving no time for ASCII Strings (which our
        // whole approach depends on: findExactStringAddresses() needs
        // the target strings to already be defined as string data).
        // None of these three matter for our narrow goal: we only read
        // a handful of specific functions by hand via the decompiler
        // (not a full switch-statement recovery pass) and don't rely
        // on automatic non-return/shared-return-call detection.
        "non-returning functions - discovered",
        "decompiler switch analysis",
        "shared return calls",
    };

    @Override
    protected void run() throws Exception {
        Options analysisOptions = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        List<String> names = analysisOptions.getOptionNames();
        for (String name : names) {
            String lower = name.toLowerCase();
            for (String match : DISABLE_IF_NAME_CONTAINS) {
                if (lower.contains(match)) {
                    try {
                        analysisOptions.setBoolean(name, false);
                        println("Disabled analyzer option: " + name);
                    } catch (Exception e) {
                        println("Could not disable: " + name + " (" + e.getMessage() + ")");
                    }
                    break;
                }
            }
        }
    }
}
