// Ghidra headless post-script.
//
// FindFunctionPointerRefs.java tried two ways to find where
// FUN_11633944's address (0x11633944, the redstone_signal per-aux-value
// constructor found by FindStateRefs.java) is stored as data, so we can
// locate the property-descriptor table row it belongs to: an
// adrp+add/ldr/str code-reference index, and a raw 8-byte
// little-endian byte scan. Both came back with zero hits.
//
// That combination is the signature of an ELF relocation that Ghidra's
// loader has not fully applied. libminecraftpe.so is a position-
// independent shared library: a table entry that holds "the address of
// FUN_11633944" is almost never baked into the file as the literal
// final address. Instead the ELF carries an R_AARCH64_RELATIVE (or
// similar) relocation record - {location in a data section, addend},
// and it's the addend that equals 0x11633944 (minus the library's
// intended load bias, usually 0 for these record formats). The dynamic
// linker (or Ghidra's loader, if it fully processes DT_RELA) writes
// addend+base into that location at "load" time. If Ghidra's headless
// import only partially processed relocations (plausible on a huge
// binary under this project's constrained analysisTimeoutPerFile), the
// raw bytes at the table location would still show zero/placeholder
// data - invisible to both of the previous scripts' techniques, even
// though the relocation record pointing at our function is sitting
// right there in Ghidra's own Relocation Table.
//
// This script doesn't touch the raw memory bytes at all. It walks
// Ghidra's RelocationTable directly - the parsed-from-file list of
// relocation records - and reports every entry whose target/addend/
// resolved value equals 0x11633944, with the relocation's own address
// (i.e. where in memory the table row lives) and surrounding bytes.

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;

public class ScanRelocationsForTarget extends GhidraScript {

    private static final long TARGET = 0x11633944L;

    private PrintWriter out;

    private void emit(String line) {
        out.println(line);
        println(line);
    }

    @Override
    protected void run() throws Exception {
        out = new PrintWriter(new FileWriter("relocation_scan_output.txt"));

        RelocationTable relocTable = currentProgram.getRelocationTable();
        emit("Total relocation records in program: " + relocTable.getSize());
        emit("Scanning for any relocation whose addend/value/bytes encode target 0x"
                + Long.toHexString(TARGET) + " ...");
        emit("");

        int totalScanned = 0;
        int hits = 0;
        Iterator<Relocation> it = relocTable.getRelocations();
        while (it.hasNext()) {
            Relocation r = it.next();
            totalScanned++;

            boolean matched = false;
            StringBuilder why = new StringBuilder();

            long[] values = r.getValues();
            if (values != null) {
                for (long v : values) {
                    if (v == TARGET) {
                        matched = true;
                        why.append("values[]=0x").append(Long.toHexString(v)).append(" ");
                    }
                }
            }

            byte[] bytes = r.getBytes();
            if (bytes != null && bytes.length >= 8) {
                for (int off = 0; off + 8 <= bytes.length; off++) {
                    long v = 0;
                    for (int i = 0; i < 8; i++) {
                        v |= (((long) bytes[off + i]) & 0xFF) << (8 * i);
                    }
                    if (v == TARGET) {
                        matched = true;
                        why.append("bytes[").append(off).append(":+8]=0x")
                                .append(Long.toHexString(v)).append(" ");
                    }
                }
            }

            if (matched) {
                hits++;
                Address loc = r.getAddress();
                emit("HIT #" + hits + "  relocation at " + loc
                        + "  type=" + r.getType()
                        + "  status=" + r.getStatus()
                        + "  symbolName=" + r.getSymbolName()
                        + "  (" + why.toString().trim() + ")");
                dumpHexWindow(loc, 0x40);
                emit("");
            }
        }

        emit("Scanned " + totalScanned + " relocation record(s) total, " + hits + " matching 0x"
                + Long.toHexString(TARGET) + ".");

        if (hits == 0) {
            emit("");
            emit("No relocation record encodes the target address either. Combined with the earlier");
            emit("zero-hit code-reference scan and zero-hit raw-byte scan, this means: across every");
            emit("representation Ghidra's loader exposes (disassembled code, raw memory bytes, and");
            emit("the relocation table itself), nothing in this binary materializes 0x"
                    + Long.toHexString(TARGET) + " as data anywhere. The remaining explanations are:");
            emit("  (a) the real call site uses a different address-construction idiom this script");
            emit("      doesn't model yet (e.g. a 32-bit PC-relative delta table, not a 64-bit pointer");
            emit("      table - common for ARM64 \"relative vtables\"), or");
            emit("  (b) FUN_11633944's actual entry address, as Ghidra labeled it, is slightly off from");
            emit("      the address any table/relocation actually targets (e.g. table points a few bytes");
            emit("      earlier/later - a prologue variant Ghidra split differently), or");
            emit("  (c) this function is simply dead/unreachable code in the shipped binary (a build-time");
            emit("      artifact never actually invoked at runtime) and the real runtime read path for");
            emit("      redstone_signal goes through an entirely different, not-yet-found function.");
        }

        out.close();
        println("Done. Wrote relocation_scan_output.txt (also mirrored to stdout above)");
    }

    private void dumpHexWindow(Address center, int halfWidth) {
        try {
            Address start = center.subtract(halfWidth);
            Address end = center.add(halfWidth);
            Memory mem = currentProgram.getMemory();
            MemoryBlock blk = mem.getBlock(center);
            emit("    block: " + (blk == null ? "?" : blk.getName()));
            Address a = start;
            StringBuilder line = new StringBuilder();
            int col = 0;
            while (a != null && a.compareTo(end) <= 0) {
                byte b;
                try {
                    b = mem.getByte(a);
                } catch (Exception ex) {
                    b = 0;
                }
                line.append(String.format("%02x ", b));
                col++;
                if (col == 16) {
                    emit("    " + a.subtract(15) + ":  " + line);
                    line.setLength(0);
                    col = 0;
                }
                try {
                    a = a.add(1);
                } catch (Exception overflow) {
                    break;
                }
            }
            if (col > 0) {
                emit("    (tail):  " + line);
            }
        } catch (Exception ex) {
            emit("    (failed to dump hex window: " + ex.getMessage() + ")");
        }
    }
}
