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
