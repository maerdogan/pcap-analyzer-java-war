package io.pcapanalyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** HTTP/2 control frames between a gateway and its backend: flow control waits, refused streams and GOAWAY.
 *  The capture comes from tools/gen_h2_control.py. Needs tshark, from PATH or PCAP_ANALYZER_TSHARK. */
class Http2ControlTest {
    static Map<String, Object> result;

    @BeforeAll
    static void analyze() throws Exception {
        String binary = System.getenv().getOrDefault("PCAP_ANALYZER_TSHARK", "tshark");
        assumeTrue(Tools.available(binary), "tshark is not installed");
        Path capture = Path.of(Http2ControlTest.class.getResource("/h2c-control.pcap").toURI());
        result = Analysis.run(new TShark(binary), capture, null, 120);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> detail(String key) {
        return (Map<String, Object>) ((Map<String, Object>) result.get("issue_detail")).get(key);
    }

    @SuppressWarnings("unchecked")
    static List<String> details(String key) {
        return ((List<Map<String, Object>>) detail(key).get("details")).stream().map(m -> String.valueOf(m.get("detail"))).collect(Collectors.toList());
    }

    @SuppressWarnings("unchecked")
    static Map<String, Number> counts() {
        return ((List<Map<String, Object>>) result.get("issues")).stream().collect(Collectors.toMap(m -> (String) m.get("key"), m -> (Number) m.get("count")));
    }

    @Test
    void flowControlWaitIsFound() {
        assertTrue(counts().containsKey("h2_flow_stall"), "no flow control wait in " + counts());
        List<String> waits = details("h2_flow_stall");
        String conn = waits.stream().filter(d -> d.startsWith("connection: ")).findFirst().orElseThrow(() -> new AssertionError(String.valueOf(waits)));
        int ms = Integer.parseInt(conn.substring("connection: ".length(), conn.length() - " ms".length()));
        assertTrue(ms >= 195 && ms <= 215, "the wait was " + ms + " ms, expected about 200");
    }

    @Test
    void refusedStreamIsReported() {
        assertEquals(1, counts().get("h2_reset").intValue());
        assertEquals(List.of("stream 3: REFUSED_STREAM"), details("h2_reset"));
    }

    @Test
    void goawayIsReported() {
        assertEquals(1, counts().get("h2_goaway").intValue());
        assertEquals(List.of("NO_ERROR"), details("h2_goaway"));
    }

    @Test
    void errorCodesHaveNames() {
        assertEquals("ENHANCE_YOUR_CALM", Builder.h2Error(11L));
        assertEquals("0x1f", Builder.h2Error(31L));
    }
}
