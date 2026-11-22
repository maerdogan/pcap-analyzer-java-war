package io.pcapanalyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** PROXY protocol v2 and v1 headers in front of HTTP on a gateway port. The capture comes from tools/gen_proxy.py. */
class ProxyProtocolTest {
    static Map<String, Object> result;

    @BeforeAll
    static void analyze() throws Exception {
        String binary = System.getenv().getOrDefault("PCAP_ANALYZER_TSHARK", "tshark");
        assumeTrue(Tools.available(binary), "tshark is not installed");
        result = Analysis.run(new TShark(binary), Path.of(ProxyProtocolTest.class.getResource("/proxy.pcap").toURI()), null, 120);
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> rows(String key) {
        return (List<Map<String, Object>>) result.get(key);
    }

    @Test
    void connectionsNameTheClientBeforeTheProxy() {
        Map<String, Object> v2 = rows("connections").get(0), v1 = rows("connections").get(1);
        assertEquals("v2", v2.get("proxy_version"));
        assertEquals("203.0.113.7:40000", v2.get("proxy_client"));
        assertEquals("198.51.100.10:443", v2.get("proxy_server"));
        assertEquals("v1", v1.get("proxy_version"));
        assertEquals("[2001:db8::7]:40001", v1.get("proxy_client"));
    }

    @Test
    void requestsBehindTheHeaderAreStillRead() {
        List<Map<String, Object>> txns = rows("transactions");
        assertEquals(2, txns.size());
        assertEquals("203.0.113.7:40000", txns.get(0).get("proxy_client"));
        assertEquals(200, ((Number) txns.get(0).get("status")).intValue());
    }
}
