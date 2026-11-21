package io.pcapanalyzer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Captures are recognised by their first bytes: pcap, pcapng and NetScaler traces. */
class CaptureFormatTest {
    @Test
    void pcapAndPcapngAreCaptures() throws Exception {
        assertTrue(AppServlet.looksLikeCapture(Path.of(getClass().getResource("/h2c-control.pcap").toURI())));
    }

    @Test
    void netscalerTracesAreCaptures(@TempDir Path tmp) throws Exception {
        for (String version : new String[] {"V10", "V20", "V30", "V35"}) {
            byte[] head = new byte[300];
            byte[] sig = ("NetScaler " + version + " Performance Data").getBytes(StandardCharsets.ISO_8859_1);
            System.arraycopy(sig, 0, head, 24, sig.length); // the text sits inside the first record
            Path f = tmp.resolve("trace-" + version + ".cap");
            Files.write(f, head);
            assertTrue(AppServlet.looksLikeCapture(f), version);
        }
    }

    @Test
    void otherFilesAreNot(@TempDir Path tmp) throws Exception {
        Path f = tmp.resolve("notes.txt");
        Files.writeString(f, "NetScaler notes, not a trace\n");
        assertFalse(AppServlet.looksLikeCapture(f));
    }
}
