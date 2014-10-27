package ru.wiseman.jmpt.integration;

import org.junit.Test;
import ru.wiseman.jmpt.key.SecretKey;
import ru.wiseman.jmpt.key.TMCGSecretKey;

import static junit.framework.TestCase.assertTrue;

public class KeyIntegration {
    @Test
    public void testKeys() throws Exception {
        SecretKey sec = new TMCGSecretKey("Alice", "alice@gaos.org", 1024L);
//        SecretKey sec3 = new TMCGSecretKey("Carol", "carol@gaos.org", 1024L, false);
        assertTrue(sec.check());

    }

    @Test
    public void testKeys2() throws Exception {
        SecretKey sec = new TMCGSecretKey("Alice", "alice@gaos.org", 1024L);
//        SecretKey sec3 = new TMCGSecretKey("Carol", "carol@gaos.org", 1024L, false);
        assertTrue(sec.check());

    }
}
