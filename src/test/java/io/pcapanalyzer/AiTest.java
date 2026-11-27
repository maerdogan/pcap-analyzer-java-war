package io.pcapanalyzer;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/** The OpenCode help, with a small shell script standing in for opencode. */
class AiTest {
    @TempDir Path tmp;

    /** A fake opencode: lists two providers; `run` answers with the model and the first lines of context.json, or fails for model bad/x. */
    private void fake() throws Exception {
        Path bin = tmp.resolve("opencode");
        Files.writeString(bin, """
            #!/bin/sh
            if [ "$1" = "models" ]; then printf 'anthropic/claude-x\\nopenai/gpt-y\\nslow/z\\nbad/x\\nnot a model line\\n'; exit 0; fi
            [ "$1" = "run" ] || exit 9
            model="$3"
            [ "$model" = "slow/z" ] && { sleep 30; echo late; exit 0; }
            [ "$model" = "bad/x" ] && { echo boom >&2; exit 3; }
            echo "model=$model perm=$OPENCODE_CONFIG_CONTENT"
            echo "files=$(ls)"
            head -c 60 context.json
            """);
        Files.setPosixFilePermissions(bin, PosixFilePermissions.fromString("rwxr-xr-x"));
        System.setProperty("pcap.opencode", bin.toString());
    }

    @AfterEach void off() { System.clearProperty("pcap.opencode"); }

    @Test void parsesOnlyModelLines() {
        assertEquals(List.of("a/b", "openai/gpt-5.1"), Ai.parseModels("\u001B[0mopenai/gpt-5.1\nINFO starting\n  a/b  \n\nnot a model\n"));
    }

    @Test void providersAreGrouped() {
        assertEquals(List.of("anthropic", "openai"), new ArrayList<>(Ai.byProvider(List.of("openai/g", "anthropic/c", "anthropic/d")).keySet()));
    }

    @Test void offWithoutTheProgram() {
        assertFalse(Ai.enabled());
        assertEquals("off", Ai.models(true).error());
    }

    @Test void listsModelsFromOpencode() throws Exception {
        fake();
        Ai.Models m = Ai.allModels(true);
        assertNull(m.error());
        assertEquals(List.of("anthropic/claude-x", "bad/x", "openai/gpt-y", "slow/z"), m.list());
    }

    @Test void answersFromAModelWithOnlyTheContextFile() throws Exception {
        fake();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("summary", Map.of("requests", 3));
        result.put("issues", List.of());
        Path wd = tmp.resolve("data");
        Files.createDirectories(wd.resolve("0123456789abcdef"));
        String text = Ai.ask("anthropic/claude-x", Ai.prompt("why?", "tr"), Ai.context("a.pcap", result));
        assertTrue(text.contains("model=anthropic/claude-x"), text);
        assertTrue(text.contains("\"deny\""), "tools are denied: " + text);
        assertTrue(text.contains("files=context.json"), "only the context file is there: " + text);
        assertTrue(text.contains("\"capture\""), text);
    }

    @Test void failureAndUnknownModelAreReported() throws Exception {
        fake();
        var e = assertThrows(java.io.IOException.class, () -> Ai.ask("bad/x", "p", "{}"));
        assertTrue(e.getMessage().contains("exited with 3") && e.getMessage().contains("boom"), e.getMessage());
        Ai.allModels(true);
        assertThrows(Ai.Refused.class, () -> Ai.start("0123456789abcdef", "a.pcap", Map.of(), "nobody/none", "", "en", "t"));
        assertThrows(Ai.Refused.class, () -> Ai.start("0123456789abcdef", "a.pcap", Map.of(), "no-slash", "", "en", "t"));
    }

    @Test void contextShrinksBigLists() {
        List<Object> rows = new ArrayList<>();
        for (int i = 0; i < 5000; i++) rows.add(Map.of("url", "/path/" + i + "/".repeat(40), "n", i));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("urls", rows); result.put("issues", List.of());
        String text = Ai.context("big.pcap", result);
        assertTrue(text.length() < 200_000, "length " + text.length());
        assertTrue(text.contains("/path/0/"));
    }

    @Test void pageListsModelsGroupedAndEscapes() throws Exception {
        fake();
        var c = new Pages.Ctx("/app", "tr", "tok", "/", "0123456789abcdef", null);
        String html = Pages.aiPage(c, new LinkedHashMap<>(Map.of("id", "0123456789abcdef", "filename", "<x>.pcap")), Ai.allModels(true), "openai/gpt-y", true);
        assertTrue(html.contains("<optgroup label=\"anthropic\">") && html.contains("<option value=\"openai/gpt-y\" selected>gpt-y</option>"), html);
        assertTrue(html.contains("Yapay zekâ ile analiz et") && html.contains("&lt;x&gt;.pcap") && !html.contains("<x>"), html);
        assertTrue(Pages.capnav(c, "0123456789abcdef", "ai", 0).contains("/ai\""));
    }

    @Test void usersSeeOnlyWhatTheAdminChose() throws Exception {
        fake();
        String old = System.getProperty("user.dir");
        System.setProperty("user.dir", tmp.toString());
        try {
            Files.createDirectories(Settings.workdir());
            assertEquals(List.of(), Ai.models(true).list(), "nothing is offered until the admin chooses");
            Ai.choose(List.of("openai/gpt-y", "../etc/passwd", "nobody/none"));
            assertEquals(List.of("openai/gpt-y"), Ai.models(false).list(), "only chosen models OpenCode really lists");
            assertEquals(List.of("anthropic/claude-x", "bad/x", "openai/gpt-y", "slow/z"), Ai.allModels(false).list());
            assertThrows(Ai.Refused.class, () -> Ai.start("0123456789abcdef", "a.pcap", Map.of(), "anthropic/claude-x", "", "en", "t"));
        } finally { System.setProperty("user.dir", old); }
    }

    @Test void whatIsSentCanBeShown() throws Exception {
        String[] pv = Ai.preview("a.pcap", Map.of("issues", List.of(), "summary", Map.of("n", 1)), "why slow?", "en");
        assertTrue(pv[0].contains("Question: why slow?") && pv[0].contains("English"));
        assertTrue(Ai.pretty(pv[1]).contains("\n  \"capture\": \"a.pcap\""), Ai.pretty(pv[1]));
        var c = new Pages.Ctx("/app", "en", "tok", "/", "x", null);
        String html = Pages.sentFragment(c, "<b>", pv[1]);
        assertTrue(html.contains("&lt;b&gt;") && html.contains("context.json"));
    }

    @Test void aRunCanBeStopped() throws Exception {
        fake();
        String old = System.getProperty("user.dir");
        System.setProperty("user.dir", tmp.toString());
        try {
            String id = "0123456789abcdef";
            Files.createDirectories(Settings.workdir().resolve(id));
            Ai.choose(List.of("slow/z"));
            Ai.models(true);
            assertFalse(Ai.cancel(id), "nothing runs yet");
            long t0 = System.currentTimeMillis();
            Ai.Job job = Ai.start(id, "a.pcap", Map.of("issues", List.of()), "slow/z", "", "en", "t");
            Thread.sleep(700);
            assertNotNull(Ai.running(id));
            assertThrows(Ai.Refused.class, () -> Ai.start(id, "a.pcap", Map.of(), "slow/z", "", "en", "t"), "one run at a time");
            assertTrue(Ai.cancel(id));
            assertEquals("cancelled", job.state);
            for (int i = 0; i < 50 && Ai.history(id).isEmpty(); i++) Thread.sleep(100);
            assertTrue(System.currentTimeMillis() - t0 < 15_000, "stopped without waiting for the model");
            assertEquals("cancelled", Ai.history(id).get(0).get("state"));
            assertNull(Ai.running(id));
        } finally { System.setProperty("user.dir", old); }
    }
}
