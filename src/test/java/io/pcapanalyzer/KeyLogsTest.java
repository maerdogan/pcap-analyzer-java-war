package io.pcapanalyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Several key logs joined into one, as for the two TLS legs on both sides of a NetScaler. */
class KeyLogsTest {
    static Path resource(String name) throws Exception {
        return Path.of(KeyLogsTest.class.getResource("/" + name).toURI());
    }

    @Test
    void joinKeepsEveryKeyOnce(@TempDir Path tmp) throws Exception {
        Path a = tmp.resolve("a.log"), b = tmp.resolve("b.log"), out = tmp.resolve("out.log");
        Files.writeString(a, "# leg one\nCLIENT_RANDOM 01 aa\nCLIENT_RANDOM 02 bb\n");
        Files.writeString(b, "CLIENT_RANDOM 02 bb\n\nCLIENT_TRAFFIC_SECRET_0 03 cc\n");
        assertEquals(3, KeyLogs.join(List.of(a, b), out));
        assertEquals(List.of("# leg one", "CLIENT_RANDOM 01 aa", "CLIENT_RANDOM 02 bb", "CLIENT_TRAFFIC_SECRET_0 03 cc"), Files.readAllLines(out));
    }

    @Test
    void otherFilesAreNotKeyLogs(@TempDir Path tmp) throws Exception {
        Path text = tmp.resolve("notes.txt");
        Files.writeString(text, "hello\n");
        assertFalse(KeyLogs.looksLikeKeyLog(text));
        assertTrue(KeyLogs.looksLikeKeyLog(resource("https_tls13.keylog")));
    }

    @Test
    void joinedKeyLogStillDecrypts(@TempDir Path tmp) throws Exception {
        String binary = System.getenv().getOrDefault("PCAP_ANALYZER_TSHARK", "tshark");
        assumeTrue(Tools.available(binary), "tshark is not installed");
        Path joined = tmp.resolve("joined.log");
        KeyLogs.join(List.of(resource("https_h2.keylog"), resource("https_tls13.keylog")), joined);
        for (String capture : List.of("https_tls13.pcap", "https_h2.pcap")) {
            Map<String, Object> r = Analysis.run(new TShark(binary), resource(capture), joined, null, 120);
            assertTrue(((List<?>) r.get("transactions")).size() > 0, capture + " was not decrypted with the joined key log");
        }
    }
}
