package io.pcapanalyzer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The two legs of a NetScaler proxy, linked by the PCB numbers of an nstrace. tshark cannot write an nstrace, so the rows are made here. */
class NetScalerLegsTest {
    static Map<String, Object> conn(int stream, Long pcb, Long linked) {
        Map<String, Object> m = new HashMap<>();
        m.put("stream", stream); m.put("ns_pcb", pcb); m.put("ns_linked_pcb", linked);
        return m;
    }

    @Test
    void legsArePairedFromEitherSide() {
        Map<String, Object> client = conn(0, 0x100L, 0x200L), server = conn(1, 0x200L, null), other = conn(2, 0x300L, 0x999L), plain = conn(3, null, null);
        Analysis.linkNetScalerLegs(List.of(client, server, other, plain));
        assertEquals(1, client.get("ns_peer"));
        assertEquals(0, server.get("ns_peer"));
        assertNull(other.get("ns_peer"));
        assertNull(plain.get("ns_peer"));
    }
}
