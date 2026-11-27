package io.pcapanalyzer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;

/**
 * AI help for reading an analysis, through the OpenCode command line tool.
 *
 * The models are the ones OpenCode lists (`opencode models`), so every provider the server's OpenCode is signed in to
 * (`opencode auth login`) shows up. The person picks one; the analysis, already masked of secrets, is written as a
 * compact JSON file in an empty temporary folder, `opencode run --model PROVIDER/MODEL --file context.json PROMPT`
 * reads it, and the answer is saved with the analysis. OpenCode runs with edit, shell and web tools denied: it
 * can only read the file it is given and answer.
 *
 * Off unless PCAP_ANALYZER_OPENCODE is set (a path, or "opencode" to use the PATH).
 */
public final class Ai {
    private Ai() {}

    private static final Pattern MODEL = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,150}");
    private static final Pattern ANSI = Pattern.compile("\\u001B\\[[0-9;?]*[ -/]*[@-~]");
    private static final int KEEP_RUNS = 10, MAX_CONTEXT_CHARS = 60_000;

    // ---- settings

    /** The opencode program, or null when the feature is off. */
    public static String binary() {
        String v = System.getProperty("pcap.opencode", System.getenv("PCAP_ANALYZER_OPENCODE"));   // the property is for tests
        return v == null || v.isBlank() ? null : v.strip();
    }

    public static boolean enabled() { return binary() != null; }

    static long timeoutSeconds() {
        try { return Math.max(30, Long.parseLong(System.getenv("PCAP_ANALYZER_OPENCODE_TIMEOUT_S"))); } catch (RuntimeException e) { return 600; }
    }

    /** Optional: only these models (comma separated, exact PROVIDER/MODEL, or PROVIDER/* for a whole provider) may be used. */
    static List<String> allowList() {
        String v = System.getenv("PCAP_ANALYZER_OPENCODE_MODELS");
        if (v == null || v.isBlank()) return List.of();
        List<String> out = new ArrayList<>();
        for (String s : v.split(",")) if (!s.isBlank()) out.add(s.strip());
        return out;
    }

    static boolean allowed(String model) {
        List<String> allow = allowList();
        if (allow.isEmpty()) return true;
        for (String a : allow) {
            if (a.equals(model)) return true;
            if (a.endsWith("/*") && model.startsWith(a.substring(0, a.length() - 1))) return true;
        }
        return false;
    }

    // ---- models

    /** The models OpenCode offers, as PROVIDER/MODEL, or the reason there are none. */
    public record Models(List<String> list, String error) {}

    private static volatile Models cached;
    private static volatile long cachedAt;

    /** The models the admin allows, from the ones OpenCode lists. Nothing until the admin has chosen. */
    public static Models models(boolean refresh) {
        Models all = allModels(refresh);
        if (all.error() != null) return all;
        Set<String> chosen = chosen();
        return new Models(all.list().stream().filter(chosen::contains).toList(), null);
    }

    static Path chosenFile() { return Settings.workdir().resolve("ai-models.json"); }

    /** What the admin allows, as PROVIDER/MODEL. */
    public static Set<String> chosen() {
        Set<String> out = new TreeSet<>();
        if (Vault.readJson(chosenFile()) instanceof List<?> l) for (Object o : l) out.add(String.valueOf(o));
        return out;
    }

    public static void choose(Collection<String> models) throws IOException {
        Set<String> ok = new TreeSet<>();
        for (String m : models) if (m != null && MODEL.matcher(m).matches() && m.contains("/")) ok.add(m);
        Vault.writeText(chosenFile(), Json.write(new ArrayList<>(ok)));
    }

    /** Every model OpenCode lists (within PCAP_ANALYZER_OPENCODE_MODELS), for the admin to choose from. Asks at most once in five minutes unless refresh is true. */
    public static synchronized Models allModels(boolean refresh) {
        if (!enabled()) return new Models(List.of(), "off");
        long now = System.currentTimeMillis();
        if (!refresh && cached != null && cached.error() == null && now - cachedAt < 300_000) return cached;
        Models m;
        try {
            Run r = exec(List.of(binary(), "models"), null, 60, null, p -> { });
            if (r.exit != 0) m = new Models(List.of(), r.output.isBlank() ? "opencode exited with " + r.exit : tail(r.output, 400));
            else m = new Models(parseModels(r.output), null);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            m = new Models(List.of(), "Cannot run " + binary() + ": " + e.getMessage());
        }
        if (m.error() == null) m = new Models(m.list().stream().filter(Ai::allowed).toList(), null);
        cached = m;
        cachedAt = now;
        return m;
    }

    /** One model per line, PROVIDER/MODEL. Anything else (logs, headings) is ignored. */
    static List<String> parseModels(String output) {
        Set<String> out = new TreeSet<>();
        for (String line : ANSI.matcher(output).replaceAll("").split("\\R")) {
            String s = line.strip();
            if (s.contains("/") && MODEL.matcher(s).matches()) out.add(s);
        }
        return new ArrayList<>(out);
    }

    /** The models grouped by provider, in order. */
    public static Map<String, List<String>> byProvider(List<String> models) {
        Map<String, List<String>> out = new TreeMap<>();
        for (String m : models) out.computeIfAbsent(m.substring(0, m.indexOf('/')), k -> new ArrayList<>()).add(m);
        return out;
    }

    // ---- what the model is told

    static final Map<String, String> LANGUAGE_NAMES = Map.of("tr", "Turkish", "en", "English", "de", "German", "es", "Spanish");

    /** The question that is asked when the person writes none. */
    static String defaultQuestion() {
        return "Find out why HTTP requests in this capture are slow or failing. Name the phase where the time goes (connection setup, "
                + "network delay, server time, transfer, or packet loss), the hosts, URLs and connections involved, and what to check or change next.";
    }

    static String prompt(String question, String lang) {
        return "You are a network and web performance engineer. The attached file context.json is the result of a packet capture analysis "
                + "(times are in seconds; sizes in bytes; secrets were masked). Use only what is in the file; say so when the data cannot answer something, "
                + "and do not invent hosts, numbers or packets. Start with a short verdict, then the evidence with the exact values, then the next steps. "
                + "Answer in " + LANGUAGE_NAMES.getOrDefault(lang, "English") + ".\n\nQuestion: " + question;
    }

    private static final String[] SECTIONS = {"summary", "http", "tcp", "kinds", "capture_points", "budget", "quality", "warnings", "statuses"};

    /** A compact copy of an analysis: the totals in full, the long lists cut to their first rows. */
    @SuppressWarnings("unchecked")
    static String context(String filename, Map<String, Object> result) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("capture", filename);
        for (String k : SECTIONS) if (result.get(k) != null) out.put(k, result.get(k));
        out.put("issues", result.get("issues"));
        if (result.get("issue_detail") != null) out.put("issue_detail", result.get("issue_detail"));
        int[] sizes = {200, 100, 50, 30, 15, 8};
        // cut the lists harder until the text fits
        for (int n : sizes) {
            out.put("slowest_requests", cut(result.get("slow"), n));
            out.put("urls", cut(result.get("urls"), n));
            out.put("connections", cut(result.get("connections"), n));
            out.put("hosts", cut(result.get("hosts"), n));
            out.put("servers", cut(result.get("backends"), n));
            out.put("tls", cut(result.get("tls"), n));
            String text = Json.write(out);
            if (text.length() <= MAX_CONTEXT_CHARS || n == sizes[sizes.length - 1]) {
                if (text.length() > MAX_CONTEXT_CHARS * 2) {
                    out.remove("issue_detail");
                    text = Json.write(out);
                }
                return text;
            }
        }
        return Json.write(out);
    }

    /** The same JSON with line breaks and indents, for reading. */
    public static String pretty(String json) {
        StringBuilder sb = new StringBuilder(json.length() * 2);
        int depth = 0;
        boolean str = false, esc = false;
        for (int i = 0; i < json.length(); i++) {
            char ch = json.charAt(i);
            if (str) { sb.append(ch); if (esc) esc = false; else if (ch == '\\') esc = true; else if (ch == '"') str = false; continue; }
            switch (ch) {
                case '"' -> { str = true; sb.append(ch); }
                case '{', '[' -> {
                    char close = ch == '{' ? '}' : ']';
                    if (i + 1 < json.length() && json.charAt(i + 1) == close) { sb.append(ch).append(close); i++; }
                    else { sb.append(ch).append('\n').append("  ".repeat(++depth)); }
                }
                case '}', ']' -> sb.append('\n').append("  ".repeat(Math.max(0, --depth))).append(ch);
                case ',' -> sb.append(",\n").append("  ".repeat(depth));
                case ':' -> sb.append(": ");
                default -> sb.append(ch);
            }
        }
        return sb.toString();
    }

    private static Object cut(Object list, int n) {
        return list instanceof List<?> l && l.size() > n ? new ArrayList<>(l.subList(0, n)) : list;
    }

    /** What a run would send, as {prompt, context}, so the person can read it before asking. */
    public static String[] preview(String filename, Map<String, Object> result, String question, String lang) {
        String q = question == null || question.isBlank() ? defaultQuestion() : question.strip();
        if (q.length() > 2000) q = q.substring(0, 2000);
        return new String[] {prompt(q, lang), context(filename, result)};
    }

    // ---- runs

    /** One question to one model, as it is saved with the analysis. */
    public static final class Job {
        public final String id = Settings.randomHex(6), model, question, user, prompt, context;
        public final long started = System.currentTimeMillis();
        public volatile long finished;
        public volatile String state = "running", answer = "", error = "";
        volatile Process process;
        volatile boolean cancelled;
        Job(String model, String question, String user, String prompt, String context) { this.model = model; this.question = question; this.user = user; this.prompt = prompt; this.context = context; }

        Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id); m.put("model", model); m.put("question", question); m.put("user", user);
            m.put("state", state); m.put("started", started / 1000.0); m.put("finished", finished / 1000.0);
            m.put("prompt", prompt); m.put("context", context); m.put("answer", answer); m.put("error", error);
            return m;
        }
    }

    private static final Map<String, Job> RUNNING = new ConcurrentHashMap<>();   // analysis id -> its run
    private static final ExecutorService POOL = Executors.newFixedThreadPool(2, r -> { Thread t = new Thread(r, "pcap-ai"); t.setDaemon(true); return t; });
    private static final Object FILE_LOCK = new Object();

    static Path file(String id) { return Settings.workdir().resolve(id).resolve("ai.json"); }

    /** The run in progress for an analysis, or null. */
    public static Job running(String id) { Job j = RUNNING.get(id); return j != null && j.state.equals("running") ? j : null; }

    /** The latest run, running or saved, or null. */
    public static Job latest(String id) { return RUNNING.get(id); }

    /** Saved runs, newest first. */
    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> history(String id) {
        Object o = Vault.readJson(file(id));
        List<Map<String, Object>> out = new ArrayList<>();
        if (o instanceof List<?> l) for (Object x : l) if (x instanceof Map<?, ?> m) out.add((Map<String, Object>) m);
        return out;
    }

    public static class Refused extends Exception { Refused(String m) { super(m); } }

    /**
     * Starts a run in the background and returns it at once. One run at a time per analysis.
     * @param filename name of the capture, for the model's context
     */
    public static Job start(String id, String filename, Map<String, Object> result, String model, String question, String lang, String user) throws Refused {
        if (!enabled()) throw new Refused("The AI help is off. Set PCAP_ANALYZER_OPENCODE on the server.");
        if (model == null || !MODEL.matcher(model).matches() || !model.contains("/")) throw new Refused("Choose a model.");
        Models listed = models(false);
        if (listed.error() != null) throw new Refused(listed.error());
        if (!listed.list().contains(model)) throw new Refused("This model is not offered by OpenCode.");
        String q = question == null || question.isBlank() ? defaultQuestion() : question.strip();
        if (q.length() > 2000) q = q.substring(0, 2000);
        String context = context(filename, result), prompt = prompt(q, lang);
        Job job = new Job(model, q, user == null ? "" : user, prompt, context);
        if (RUNNING.compute(id, (k, old) -> old != null && old.state.equals("running") ? old : job) != job) throw new Refused("An AI analysis of this capture is already running.");
        POOL.submit(() -> {
            try {
                if (job.cancelled) throw new IOException("Stopped.");
                String text = ask(model, prompt, context, p -> { job.process = p; if (job.cancelled) kill(p); });
                if (!job.cancelled) { job.answer = text; job.state = "done"; }
            } catch (Exception e) {
                if (!job.cancelled) { job.error = String.valueOf(e.getMessage()); job.state = "failed"; }
                if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            } finally {
                if (job.cancelled) { job.state = "cancelled"; job.error = ""; }
                job.finished = System.currentTimeMillis();
                try { save(id, job); } catch (IOException ignored) { }
            }
        });
        return job;
    }

    private static void kill(Process p) { p.descendants().forEach(ProcessHandle::destroyForcibly); p.destroyForcibly(); }

    /** Stops the run in progress for an analysis: OpenCode and anything it started are killed. False when nothing was running. */
    public static boolean cancel(String id) {
        Job j = running(id);
        if (j == null) return false;
        j.cancelled = true;
        j.state = "cancelled";
        Process p = j.process;
        if (p != null) kill(p);
        return true;
    }

    private static void save(String id, Job job) throws IOException {
        if (!Files.isDirectory(file(id).getParent())) return;   // the analysis was deleted meanwhile
        synchronized (FILE_LOCK) {
            List<Map<String, Object>> all = history(id);
            all.add(0, job.toMap());
            Vault.writeText(file(id), Json.write(all.size() > KEEP_RUNS ? new ArrayList<>(all.subList(0, KEEP_RUNS)) : all));
        }
    }

    /** OpenCode may only read the file it is given: no edits, no shell, no web. */
    static final String LOCKED_DOWN = "{\"permission\":{\"edit\":\"deny\",\"bash\":\"deny\",\"webfetch\":\"deny\"}}";

    /** Runs opencode in an empty temporary folder that holds only context.json, and returns the answer. */
    static String ask(String model, String prompt, String context) throws IOException, InterruptedException { return ask(model, prompt, context, p -> { }); }

    static String ask(String model, String prompt, String context, java.util.function.Consumer<Process> onStart) throws IOException, InterruptedException {
        Path tmp = Files.createTempDirectory("pcap-ai-");
        try {
            Files.writeString(tmp.resolve("context.json"), context, StandardCharsets.UTF_8);
            List<String> cmd = new ArrayList<>(List.of(binary(), "run", "--model", model, "--file", "context.json", "--", prompt));
            Run r = exec(cmd, tmp, timeoutSeconds(), Map.of("OPENCODE_CONFIG_CONTENT", LOCKED_DOWN), onStart);
            String text = r.output.strip();
            if (r.timedOut) throw new IOException("OpenCode did not answer within " + timeoutSeconds() + " seconds.");
            if (r.exit != 0) throw new IOException("OpenCode exited with " + r.exit + (text.isEmpty() ? "" : ": " + tail(text, 600)));
            if (text.isEmpty()) throw new IOException("OpenCode returned no answer.");
            return text;
        } finally {
            try (var walk = Files.walk(tmp)) { walk.sorted(Comparator.reverseOrder()).forEach(p -> p.toFile().delete()); } catch (IOException ignored) { }
        }
    }

    // ---- process

    record Run(int exit, String output, boolean timedOut) {}

    /** Runs a program without a shell, standard input closed, output (both streams) read in full, stopped after the limit. */
    static Run exec(List<String> cmd, Path cwd, long seconds, Map<String, String> env, java.util.function.Consumer<Process> onStart) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(cmd).redirectErrorStream(true);
        if (cwd != null) pb.directory(cwd.toFile());
        pb.environment().put("NO_COLOR", "1");
        pb.environment().put("CI", "1");
        if (env != null) pb.environment().putAll(env);
        Process p = pb.start();
        p.getOutputStream().close();
        onStart.accept(p);
        StringBuilder sb = new StringBuilder();
        Thread reader = new Thread(() -> {
            try (var in = p.getInputStream()) {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) if (sb.length() < 2_000_000) synchronized (sb) { sb.append(new String(buf, 0, n, StandardCharsets.UTF_8)); }
            } catch (IOException ignored) { }
        }, "pcap-ai-out");
        reader.setDaemon(true);
        reader.start();
        boolean done = p.waitFor(seconds, TimeUnit.SECONDS);
        if (!done) { p.descendants().forEach(ProcessHandle::destroyForcibly); p.destroyForcibly(); p.waitFor(5, TimeUnit.SECONDS); }
        reader.join(5000);
        String out;
        synchronized (sb) { out = ANSI.matcher(sb).replaceAll(""); }
        return new Run(done ? p.exitValue() : -1, out, !done);
    }

    private static String tail(String s, int n) {
        s = s.strip();
        return s.length() > n ? "…" + s.substring(s.length() - n) : s;
    }
}
