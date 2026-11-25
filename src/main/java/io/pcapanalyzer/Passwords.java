package io.pcapanalyzer;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;

/** The setup admin's password, kept as a salted hash in password.json. PCAP_ANALYZER_ADMIN_PASSWORD is read once, at the first start, and moved there;
 *  without it the first sign-in is admin / admin and a new password must be chosen at once. */
public final class Passwords {
    public static final int MIN_LENGTH = 12;
    private static final int ITERATIONS = 210_000;
    private static final SecureRandom RANDOM = new SecureRandom();

    private Passwords() {}

    static byte[] hash(String password, byte[] salt) {
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, 256)).getEncoded();
        } catch (Exception e) { throw new IllegalStateException(e); }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> stored() {
        try {
            Object o = Json.parse(Files.readString(Settings.workdir().resolve("password.json"), StandardCharsets.UTF_8));
            return o instanceof Map ? (Map<String, Object>) o : null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /** Sign-in is always possible: with no password saved and none in the environment, the first sign-in is admin / admin. */
    public static boolean configured() { return true; }

    /** True while the setup admin still has the first-run password admin / admin and must choose a new one before anything else. */
    public static boolean mustChange() { return !Vault.isSetUp() && stored() == null && Settings.adminPassword().isEmpty(); }

    public static boolean matches(String candidate) {
        // once the vault exists, the admin password is what opens it; there is no other copy
        if (Vault.isSetUp()) return Vault.unlock(candidate);
        Map<String, Object> s = stored();
        if (s == null) {
            String env = Settings.adminPassword();
            if (env.isEmpty()) return MessageDigest.isEqual(candidate.getBytes(StandardCharsets.UTF_8), "admin".getBytes(StandardCharsets.UTF_8));
            return MessageDigest.isEqual(candidate.getBytes(StandardCharsets.UTF_8), env.getBytes(StandardCharsets.UTF_8));
        }
        return MessageDigest.isEqual(hash(candidate, HexFormat.of().parseHex((String) s.get("salt"))), HexFormat.of().parseHex((String) s.get("hash")));
    }

    /** Moves PCAP_ANALYZER_ADMIN_PASSWORD into password.json as a hash, once, so the plain password can be removed from the server settings.
     *  Returns true when it moved it. From then on the variable is ignored. */
    public static boolean adoptEnvironment() throws IOException {
        if (Vault.isSetUp() || stored() != null || Settings.adminPassword().isEmpty()) return false;
        save(Settings.adminPassword());
        return true;
    }

    public static void save(String password) throws IOException {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        Map<String, Object> m = new java.util.LinkedHashMap<>();
        m.put("salt", HexFormat.of().formatHex(salt)); m.put("hash", HexFormat.of().formatHex(hash(password, salt)));
        Files.createDirectories(Settings.workdir());
        Path tmp = Settings.workdir().resolve("password.json.tmp");
        Files.writeString(tmp, Json.write(m), StandardCharsets.UTF_8);
        try { Files.setPosixFilePermissions(tmp, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")); } catch (UnsupportedOperationException ignored) { }
        Files.move(tmp, Settings.workdir().resolve("password.json"), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }
}
