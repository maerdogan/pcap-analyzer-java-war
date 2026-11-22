package io.pcapanalyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Two TLS 1.2 connections where the server asks for a client certificate: one client sends it, one does not.
 *  The server sends a leaf and an intermediate. The capture comes from tools/gen_mtls.py. */
class MutualTlsTest {
    static Map<String, Object> result;

    @BeforeAll
    static void analyze() throws Exception {
        String binary = System.getenv().getOrDefault("PCAP_ANALYZER_TSHARK", "tshark");
        assumeTrue(Tools.available(binary), "tshark is not installed");
        Path capture = Path.of(MutualTlsTest.class.getResource("/mtls.pcap").toURI());
        result = Analysis.run(new TShark(binary), capture, null, 120);
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> conns() {
        return (List<Map<String, Object>>) result.get("connections");
    }

    @Test
    void chainAndClientCertificateArePerConnection() {
        Map<String, Object> sent = conns().get(0), missing = conns().get(1);
        assertEquals(2, sent.get("tls_chain"));
        assertEquals(true, sent.get("tls_client_cert_requested"));
        assertEquals("netscaler.example.test", sent.get("tls_client_name"));
        assertEquals(0, missing.get("tls_client_certs"));
    }

    @Test
    void missingClientCertificateIsAnIssue() {
        Http2ControlTest.result = result;
        assertEquals(1, Http2ControlTest.counts().get("tls_no_client_cert").intValue());
        assertEquals(List.of("gw.example.test"), Http2ControlTest.details("tls_no_client_cert"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void summaryCountsMutualTls() {
        Map<String, Object> tls = (Map<String, Object>) result.get("tls");
        assertEquals(2L, tls.get("client_cert_requested"));
        assertEquals(1L, tls.get("client_cert_sent"));
    }
}
