import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.File;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.nio.file.Files;
import java.util.*;

public class HexcoreMetrics extends GhidraScript {
    private static String esc(String value) { return value.replace("\\", "\\\\").replace("\"", "\\\""); }
    private static String sha256(File file) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file.toPath()));
        StringBuilder out = new StringBuilder(); for (byte value : digest) out.append(String.format("%02x", value)); return out.toString();
    }
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs(); if (args.length < 2) throw new IllegalArgumentException("output and focus CSV required");
        List<String> focus = Arrays.asList(args[1].split(",")); Map<String,List<String>> found = new TreeMap<>(); for (String name : focus) found.put(name, new ArrayList<>());
        int functions = 0, named = 0, calls = 0; FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext() && !monitor.isCancelled()) {
            Function function = iterator.next(); functions++; String name = function.getName(); if (!name.startsWith("FUN_")) named++;
            for (String expected : focus) if (name.equals(expected) || name.startsWith("_" + expected) || name.startsWith(expected + "@@")) found.get(expected).add(name);
            calls += function.getCalledFunctions(monitor).size();
        }
        StringBuilder json = new StringBuilder(); json.append("{\n  \"schemaVersion\": 1,\n  \"tool\": \"Ghidra\",\n  \"version\": \"12.1.2\",\n");
        File binary = new File(currentProgram.getExecutablePath()); json.append("  \"binaryPath\": \"").append(esc(binary.getAbsolutePath())).append("\",\n  \"binarySha256\": \"").append(sha256(binary)).append("\",\n");
        json.append("  \"functions\": ").append(functions).append(",\n  \"namedFunctions\": ").append(named).append(",\n  \"calledFunctionEdges\": ").append(calls).append(",\n  \"focus\": {");
        boolean first = true; for (Map.Entry<String,List<String>> entry : found.entrySet()) { if (!first) json.append(","); first=false; json.append("\n    \"").append(esc(entry.getKey())).append("\": ["); for (int i=0;i<entry.getValue().size();i++){if(i>0)json.append(", ");json.append("\"").append(esc(entry.getValue().get(i))).append("\"");} json.append("]"); }
        json.append("\n  }\n}\n"); try (FileWriter writer = new FileWriter(args[0])) { writer.write(json.toString()); }
    }
}
