// Ghidra headless PRE-script (runs after import, before auto-analysis).
//
// We went through several rounds of disabling one slow/broken analyzer
// at a time (GCC Exception Handlers, Call-Fixup Installer, Non-Returning
// Functions - Discovered, Decompiler Switch Analysis, Shared Return
// Calls, Basic Constant Reference Analyzer) only to have a DIFFERENT
// data-flow analyzer (Call Convention ID) become the new one that eats
// the entire per-file analysis timeout on this unusually large binary.
// This is whack-a-mole: on a binary this size, pretty much any analyzer
// that does real data-flow/constant-propagation work is going to take
// an enormous amount of time (or run into the same "VarnodeContext: out
// of address spaces" NEON/vector-register bug).
//
// So instead of a denylist, this is now an ALLOWLIST: disable every
// analyzer EXCEPT the handful we actually need. We only need enough to
// (a) disassemble code and recover function boundaries, and (b) let
// FindStateRefs.java's own manual ADRP+ADD/LDR scan find string
// references itself, without relying on Ghidra's reference/constant-
// propagation analyzers at all.
public class DisableHeavyAnalyzers extends ghidra.app.script.GhidraScript {

    private static final String[] KEEP_ENABLED_IF_NAME_CONTAINS = {
        "disassemble",                 // "Disassemble", "Disassemble Entry Points"
        "function start search",
        "create function",
        "ascii strings",
        "non-returning functions - known",
        "aarch64 elf plt thunks",
        "dwarf",                       // near-instant here anyway (DWARF not found)
    };

    @Override
    protected void run() throws Exception {
        ghidra.framework.options.Options analysisOptions =
                currentProgram.getOptions(ghidra.program.model.listing.Program.ANALYSIS_PROPERTIES);
        java.util.List<String> names = analysisOptions.getOptionNames();
        for (String name : names) {
            // Skip sub-options (e.g. "GCC Exception Handlers.Create Try
            // Catch Comments") - they're irrelevant once their parent
            // analyzer is disabled, and most aren't plain booleans
            // anyway so trying to flip them just adds log noise.
            if (name.contains(".")) {
                continue;
            }
            String lower = name.toLowerCase();
            boolean keep = false;
            for (String allow : KEEP_ENABLED_IF_NAME_CONTAINS) {
                if (lower.contains(allow)) {
                    keep = true;
                    break;
                }
            }
            if (keep) {
                println("Keeping analyzer enabled: " + name);
                continue;
            }
            try {
                analysisOptions.setBoolean(name, false);
                println("Disabled analyzer: " + name);
            } catch (Exception e) {
                // Not a plain boolean option (or already off) - harmless.
            }
        }
    }
}
