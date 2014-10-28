package ru.wiseman.jmpt.integration;

import org.junit.Test;
import ru.wiseman.jmpt.key.PublicKey;
import ru.wiseman.jmpt.key.SecretKey;
import ru.wiseman.jmpt.key.TMCGPublicKey;
import ru.wiseman.jmpt.key.TMCGSecretKey;

import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertTrue;

public class KeyIntegrationTest {
    @Test
    public void tmcgKeys() throws Exception {
        SecretKey secretKey = new TMCGSecretKey("Alice", "alice@gaos.org", 1024L);
        PublicKey publicKey = new TMCGPublicKey(secretKey);

        assertNotNull(secretKey);
        assertTrue(secretKey.check());

        assertNotNull(publicKey);
        assertTrue(publicKey.check());
    }
}
