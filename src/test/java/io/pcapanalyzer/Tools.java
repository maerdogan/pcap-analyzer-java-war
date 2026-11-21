package io.pcapanalyzer;

/** Helpers shared by the tests. */
final class Tools {
    private Tools() {}

    /** True when the program starts, so tests that need tshark are skipped where it is missing. */
    static boolean available(String binary) {
        try {
            return new ProcessBuilder(binary, "--version").redirectErrorStream(true).start().waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
}
