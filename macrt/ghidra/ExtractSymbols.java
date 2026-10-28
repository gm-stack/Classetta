// Ghidra post-script: dump a program's already-defined symbols as JSON.
//
// Read-only -- it never touches the database, and analyzeHeadless is run
// with -noanalysis so nothing is re-analyzed either.  Run headless:
//
//   analyzeHeadless <projectDir> <projectName> -noanalysis -readOnly \
//       [-process <program> -noanalysis] \
//       -postScript ExtractSymbols.java <out.json> [jankA5Hex]
//
// Arguments:
//   out.json     where to write the JSON
//   jankA5Hex    optional; if given, the program's word at 0x904 must
//                equal it -- the jank dumps record their A5 there, so
//                this proves the program was made from these resources.
//
// Output: {"program": name, "a5": <0x904 word>,
//          "functions": [{"name","entry","body_end","signature"}, ...]}
//
// Bodies end where Ghidra says they end (inclusive max address), even
// when that overruns the routine's RTS into its neighbour; the tracer
// stops its own scans at the segment.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class ExtractSymbols extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("usage: ExtractSymbols.java <out.json> [jankA5Hex]");
        }
        Program program = currentProgram;
        long a5 = program.getMemory().getInt(program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(0x904)) & 0xFFFFFFFFL;
        if (args.length >= 2) {
            long want = Long.parseLong(args[1].replace("#", ""), 16);
            if (a5 != want) {
                println("EXTRACT-MISMATCH a5=" + Long.toHexString(a5) + " want=" + args[1]);
                return;
            }
        }

        StringBuilder json = new StringBuilder();
        json.append("{\"program\":").append(quote(program.getName()))
            .append(",\"a5\":").append(a5)
            .append(",\"functions\":[");
        FunctionIterator functions = program.getFunctionManager().getFunctions(true);
        int count = 0;
        while (functions.hasNext()) {
            Function f = functions.next();
            if (f.isExternal()) {
                continue;
            }
            Address entry = f.getEntryPoint();
            Address bodyEnd = f.getBody().getMaxAddress();
            if (count++ > 0) {
                json.append(',');
            }
            json.append("{\"name\":").append(quote(f.getName()))
                .append(",\"entry\":\"").append(entry.toString(false)).append('"')
                .append(",\"body_end\":\"")
                .append((bodyEnd == null ? entry : bodyEnd).toString(false)).append('"')
                .append(",\"signature\":").append(quote(prototype(f)))
                .append('}');
            if (monitor.isCancelled()) {
                break;
            }
        }
        json.append("]}");

        try (PrintWriter out = new PrintWriter(
                Files.newBufferedWriter(java.nio.file.Paths.get(args[0]),
                        StandardCharsets.UTF_8))) {
            out.print(json);
        }
        println("EXTRACT-DONE " + count + " functions");
    }

    // "ret name(type1 name1, type2 name2)": the shape macrt's signature
    // parser reads -- the parameter's name is its last word -- built
    // from the parts every Ghidra version carries.  Ghidra's pointer
    // type names ("char *") already carry the star on the type.
    private static String prototype(Function f) {
        StringBuilder b = new StringBuilder();
        b.append(f.getReturnType().getName());
        b.append(' ').append(f.getName()).append('(');
        Parameter[] params = f.getParameters();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) {
                b.append(", ");
            }
            b.append(params[i].getDataType().getName()).append(' ').append(params[i].getName());
        }
        return b.append(')').toString();
    }

    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n");  break;
                case '\r': b.append("\\r");  break;
                case '\t': b.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        return b.append('"').toString();
    }
}
