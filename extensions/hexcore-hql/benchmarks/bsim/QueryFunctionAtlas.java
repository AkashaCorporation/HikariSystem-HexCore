/*
 * SPDX-License-Identifier: Apache-2.0
 * Headless BSim query exporter based on Ghidra's QueryFunction.java example.
 */
//@category BSim

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.protocol.QueryNearest;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.program.model.listing.Function;

public class QueryFunctionAtlas extends GhidraScript {
    private static String json(String value) {
        if (value == null) return "null";
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (currentProgram == null || args.length < 2) {
            throw new IllegalArgumentException("usage: QueryFunctionAtlas <database-url> <output-json> [threshold] [max]");
        }
        String databaseUrl = args[0];
        Path output = Path.of(args[1]);
        double threshold = args.length >= 3 ? Double.parseDouble(args[2]) : 0.0;
        int max = args.length >= 4 ? Integer.parseInt(args[3]) : 20;
        URL url = BSimClientFactory.deriveBSimURL(databaseUrl);
        List<String> queries = new ArrayList<>();
        try (FunctionDatabase database = BSimClientFactory.buildClient(url, false)) {
            if (!database.initialize()) throw new IllegalStateException(database.getLastError().message);
            Iterator<Function> functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function function = functions.next();
                if (!function.getName().startsWith("bench_")) continue;
                List<String> matches = new ArrayList<>();
                GenSignatures generator = new GenSignatures(false);
                try {
                    generator.setVectorFactory(database.getLSHVectorFactory());
                    generator.openProgram(currentProgram, null, null, null, null, null);
                    DescriptionManager manager = generator.getDescriptionManager();
                    generator.scanFunction(function);
                    QueryNearest query = new QueryNearest();
                    query.manage = manager;
                    query.max = max;
                    query.thresh = threshold;
                    query.signifthresh = 0.0;
                    ResponseNearest response = query.execute(database);
                    if (response == null) throw new IllegalStateException(database.getLastError().message);
                    for (SimilarityResult result : response.result) {
                        for (SimilarityNote note : result) {
                            FunctionDescription description = note.getFunctionDescription();
                            ExecutableRecord executable = description.getExecutableRecord();
                            matches.add("{" +
                                "\"executable\":" + json(executable.getNameExec()) + "," +
                                "\"function\":" + json(description.getFunctionName()) + "," +
                                "\"address\":" + json("0x" + Long.toUnsignedString(description.getAddress(), 16)) + "," +
                                "\"similarity\":" + Double.toString(note.getSimilarity()) + "," +
                                "\"significance\":" + Double.toString(note.getSignificance()) +
                            "}");
                        }
                    }
                } finally {
                    generator.dispose();
                }
                queries.add("{" +
                    "\"function\":" + json(function.getName()) + "," +
                    "\"address\":" + json(function.getEntryPoint().toString()) + "," +
                    "\"matches\":[" + String.join(",", matches) + "]" +
                "}");
            }
        }
        String result = "{" +
            "\"schemaVersion\":1," +
            "\"program\":" + json(currentProgram.getName()) + "," +
            "\"executableSha256\":" + json(currentProgram.getExecutableSHA256()) + "," +
            "\"database\":" + json(databaseUrl) + "," +
            "\"threshold\":" + Double.toString(threshold) + "," +
            "\"maxMatches\":" + Integer.toString(max) + "," +
            "\"queries\":[" + String.join(",", queries) + "]" +
        "}\n";
        Files.createDirectories(output.toAbsolutePath().getParent());
        Files.writeString(output, result, StandardCharsets.UTF_8);
        println("QueryFunctionAtlas wrote " + queries.size() + " queries to " + output);
    }
}
