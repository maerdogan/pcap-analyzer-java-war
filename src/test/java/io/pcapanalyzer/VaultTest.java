package io.pcapanalyzer;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

/** The vault in a work folder of its own (PCAP_ANALYZER_WORKDIR must point at an empty folder). The tests run in order, like a life of an install. */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class VaultTest {
    static Path wd;
    static final String ADMIN = "Admin-Password-1", MASTER = "Q7#mZ2!pL9x$Rt4w";
    static byte[] big;

    @BeforeAll
    static void folder() throws Exception {
        String v = System.getenv("PCAP_ANALYZER_WORKDIR");
        assumeTrue(v != null && v.contains("vault-test"), "set PCAP_ANALYZER_WORKDIR to an empty vault-test folder");
        wd = Path.of(v);
        Files.createDirectories(wd.resolve("0123456789abcdef"));
        Files.writeString(wd.resolve("0123456789abcdef/meta.json"), "{\"id\":\"0123456789abcdef\"}");
        Files.writeString(wd.resolve("audit.log"), "{\"event\":\"upload\"}\n");
        big = new byte[3 * (1 << 20) + 12345];
        new Random(1).nextBytes(big);
        Files.write(wd.resolve("0123456789abcdef/capture.bin"), big);
    }

    @Test @Order(1)
    void masterKeyRules() {
        assertNotNull(Vault.masterProblem("short#"));
        assertNotNull(Vault.masterProblem("abcdefgh12345678"));
        assertNull(Vault.masterProblem(MASTER));
    }

    @Test @Order(2)
    void setUpEncryptsWhatIsThere() throws Exception {
        Vault.setUp(ADMIN, MASTER);
        assertTrue(Vault.encrypted(wd.resolve("0123456789abcdef/meta.json")));
        assertTrue(Vault.encrypted(wd.resolve("0123456789abcdef/capture.bin")));
        assertFalse(Files.exists(wd.resolve("audit.log")));
        assertTrue(Files.exists(Records.auditFile()));
        assertFalse(Files.readString(Records.auditFile()).contains("upload"), "the activity log must not be readable");
        assertEquals("{\"id\":\"0123456789abcdef\"}", Vault.readText(wd.resolve("0123456789abcdef/meta.json")));
        try (InputStream in = Vault.in(wd.resolve("0123456789abcdef/capture.bin"))) { assertArrayEquals(big, in.readAllBytes()); }
    }

    @Test @Order(3)
    void restartNeedsTheAdminPassword() throws Exception {
        Vault.lock();
        assertThrows(Vault.LockedException.class, () -> Vault.readText(wd.resolve("0123456789abcdef/meta.json")));
        // writing needs only the public key, so it works while locked
        Vault.writeText(wd.resolve("0123456789abcdef/notes.json"), "{\"note\":\"x\"}");
        assertFalse(Vault.unlock("wrong password"));
        assertTrue(Vault.unlock(ADMIN));
        assertEquals(MASTER, Vault.masterKey());
        assertEquals("{\"note\":\"x\"}", Vault.readText(wd.resolve("0123456789abcdef/notes.json")));
    }

    @Test @Order(4)
    void changedFilesAreFound() throws Exception {
        Vault.clearAlerts();
        Path f = wd.resolve("0123456789abcdef/capture.bin");
        byte[] raw = Files.readAllBytes(f);
        raw[raw.length / 2] ^= 1;
        Files.write(f, raw);
        assertFalse(Vault.verify(f));
        Path cut = wd.resolve("0123456789abcdef/meta.json");
        byte[] m = Files.readAllBytes(cut);
        Files.write(cut, java.util.Arrays.copyOf(m, m.length - 20));
        assertFalse(Vault.verify(cut));
        Files.writeString(wd.resolve("0123456789abcdef/result.json"), "{}");
        assertThrows(java.io.IOException.class, () -> Vault.readText(wd.resolve("0123456789abcdef/result.json")));
        assertEquals(3, Vault.alerts().size(), String.valueOf(Vault.alerts()));
    }

    @Test @Order(5)
    void newAdminPasswordAndMasterKey() throws Exception {
        Vault.changeAdminPassword(ADMIN, "Second-Password-2");
        Vault.changeMaster("N3w&Key*2026abcd");
        Vault.lock();
        assertFalse(Vault.unlock(ADMIN));
        assertTrue(Vault.unlock("Second-Password-2"));
        assertEquals("N3w&Key*2026abcd", Vault.masterKey());
        assertEquals("{\"note\":\"x\"}", Vault.readText(wd.resolve("0123456789abcdef/notes.json")));
    }

    @Test @Order(6)
    void usersAndGroupsAreEncrypted() throws Exception {
        Users.addGroup("neta", "Ağ ekibi");
        Users.add("ali", "Ali Yılmaz", "S1", "neta", Users.Role.VIEWER, "User-Password-1", false);
        String raw = new String(Files.readAllBytes(wd.resolve("users.json")), StandardCharsets.ISO_8859_1);
        assertFalse(raw.contains("ali") || raw.contains("neta"));
        Users.Current u = Users.verify("ali", "User-Password-1");
        assertNotNull(u);
        assertTrue(u.mustChange(), "a new local user must change the password");
        Users.setOwnPassword("ali", "User-Password-2");
        assertFalse(Users.verify("ali", "User-Password-2").mustChange());
        assertEquals("Ali Yılmaz", Users.list().get(0).get("full_name"));
    }

    @Test @Order(7)
    void ldapFilterIsEscaped() {
        assertEquals("a\\2a\\28b\\29\\5c", Ldap.escape("a*(b)\\"));
    }
}
