package io.pcapanalyzer;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Map;
import org.junit.jupiter.api.Test;

/** The LDAP address takes any port, or none: ldaps:// then uses 636 and ldap:// 389. */
class LdapTest {
    static String check(String url) { return Ldap.problem(Map.of("url", url, "user_filter", "(uid={0})")); }

    @Test
    void anyPortOrNone() {
        for (String ok : new String[] {"ldaps://dc.example.com", "ldaps://dc.example.com:3269", "ldap://10.0.0.5:10389/", "ldaps://[2001:db8::1]:636"}) assertNull(check(ok), ok);
        for (String bad : new String[] {"ldaps://dc:0", "ldaps://dc:65536", "dc.example.com", "ldaps://a b", "http://dc.example.com"}) assertNotNull(check(bad), bad);
    }
}
