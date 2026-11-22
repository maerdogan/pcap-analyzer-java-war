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
        assertEquals(3, txns.size());
        assertEquals("203.0.113.7:40000", txns.get(0).get("proxy_client"));
        assertEquals(200, ((Number) txns.get(0).get("status")).intValue());
    }

    @Test
    void originalClientComesFromTheHeaderOrTheProxyHeader() {
        List<Map<String, Object>> txns = rows("transactions");
        assertEquals("203.0.113.7:40000", txns.get(0).get("original_client"));
        assertEquals("PROXY v2", txns.get(0).get("original_client_from"));
        assertEquals("198.51.100.5", txns.get(2).get("original_client"));
        assertEquals("x-forwarded-for", txns.get(2).get("original_client_from"));
    }

    @Test
    void clientAddressReadsListsAndForwarded() {
        assertEquals("198.51.100.5", Builder.clientAddress("x-forwarded-for", "198.51.100.5, 10.0.0.1"));
        assertEquals("[2001:db8::1]:4711", Builder.clientAddress("forwarded", "for=\"[2001:db8::1]:4711\";proto=https, for=10.0.0.1"));
        assertEquals("192.0.2.60", Builder.clientAddress("forwarded", "proto=http;for=192.0.2.60;by=203.0.113.43"));
        assertEquals(null, Builder.clientAddress("forwarded", "for=unknown"));
    }
}
