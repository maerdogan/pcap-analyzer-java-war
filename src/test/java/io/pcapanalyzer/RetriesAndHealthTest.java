package io.pcapanalyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RetriesAndHealthTest {
    static Map<String, Object> t(int id, String rid, double start, double end, Integer status) {
        Map<String, Object> m = new HashMap<>();
        m.put("id", id); m.put("request_id", rid); m.put("req_start", start); m.put("req_end", start); m.put("resp_end", end); m.put("status", status);
        return m;
    }

    @Test
    void aFailedAttemptFollowedByTheSameIdIsARetry() {
        Map<String, Object> first = t(1, "abc", 0, 1, 503), second = t(2, "abc", 1.1, 1.2, 200);
        Map<String, Object> legA = t(3, "xyz", 0, 1, 502), legB = t(4, "xyz", 0.1, 0.9, 502);  // two legs of one proxy, overlapping
        Map<String, Object> ok1 = t(5, "ok", 0, 1, 200), ok2 = t(6, "ok", 2, 3, 200);
        Analysis.markRetries(List.of(first, second, legA, legB, ok1, ok2));
        assertEquals(1, second.get("retry_of"));
        assertEquals(2, second.get("attempt"));
        assertNull(legB.get("retry_of"));
        assertNull(ok2.get("retry_of"));
    }

    @Test
    void healthChecksByPathAndAgent() {
        assertTrue(Builder.healthCheck("/healthz", null));
        assertTrue(Builder.healthCheck("/orders/actuator/health?x=1", null));
        assertTrue(Builder.healthCheck("/", "NetScaler-Monitor/1.0"));
        assertTrue(Builder.healthCheck("/ready", "kube-probe/1.30"));
        assertFalse(Builder.healthCheck("/api/order/status", null));
        assertFalse(Builder.healthCheck("/api/orders", "Mozilla/5.0"));
    }
}
