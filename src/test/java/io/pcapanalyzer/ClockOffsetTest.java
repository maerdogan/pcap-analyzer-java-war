package io.pcapanalyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The same requests at a NetScaler (A) and at a gateway (B) whose clock is 2 s ahead and drifts 100 ppm. Each way takes 5 ms. */
class ClockOffsetTest {
    static Map<String, Object> row(String id, double reqStart, double respStart, double total) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id); m.put("request_id", "r" + id.substring(1)); m.put("method", "GET"); m.put("uri", "/x"); m.put("url_template", "/x"); m.put("status", 200);
        m.put("req_start", reqStart); m.put("resp_start", respStart); m.put("total", total); m.put("service", 0.01);
        return m;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> points(Double given) {
        List<Map<String, Object>> a = new ArrayList<>(), b = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            double t = 1000 + i * 3.0, off = 2.0 + 100e-6 * (t - 1000);
            double bReq = t + 0.005 + off, bResp = bReq + 0.010, aResp = bResp - off + 0.005;
            a.add(row("a" + i, t, aResp, aResp - t)); b.add(row("b" + i, bReq, bResp, 0.010));
        }
        return Compare.twoPoint(Map.of("transactions", a), Map.of("transactions", b), given);
    }

    @Test
    @SuppressWarnings("unchecked")
    void offsetAndDriftAreEstimated() {
        Map<String, Object> p = points(null);
        assertEquals(100, Analysis.d(p.get("clock_drift_ppm")), 1);
        for (Map<String, Object> r : (List<Map<String, Object>>) p.get("rows")) {
            assertEquals(0.005, Analysis.d(r.get("forward")), 0.0005);
            assertEquals(0.005, Analysis.d(r.get("back")), 0.0005);
        }
    }

    @Test
    void givenOffsetReplacesTheEstimate() {
        Map<String, Object> p = points(1.5);
        assertEquals(1.5, Analysis.d(p.get("clock_skew")), 1e-9);
        assertEquals(true, p.get("clock_given"));
    }
}
