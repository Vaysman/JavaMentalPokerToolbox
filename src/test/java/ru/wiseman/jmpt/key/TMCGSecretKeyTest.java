package ru.wiseman.jmpt.key;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.*;

public class TMCGSecretKeyTest {
    @Test
    public void testSign() throws Exception {

    }

    @Test
    public void testDecrypt() throws Exception {

    }

    @Test
    public void testImportKey() throws Exception {

    }

    @Test
    public void testVerify() throws Exception {

    }

    @Test
    public void testFingerprint() throws Exception {

    }

    @Test
    public void testEncrypt() throws Exception {

    }

    @Test
    public void check_properSecretKey_returnsTrue() throws Exception {
        TMCGPublicKey publicKey = mock(TMCGPublicKey.class);
        TMCGSecretKey privateKey = spy(new TMCGSecretKey("Alice", "alice@gaos.org", 1024));
        doReturn(publicKey).when(privateKey).makePublicKey(privateKey);
        when(publicKey.check()).thenReturn(true);

        boolean check = privateKey.check();

        assertTrue(check);
    }

    @Test
    public void check_improperSecretKey_returnsFalse() throws Exception {
        TMCGPublicKey publicKey = mock(TMCGPublicKey.class);
        TMCGSecretKey privateKey = spy(new TMCGSecretKey("Alice", "alice@gaos.org", 1024));
        doReturn(publicKey).when(privateKey).makePublicKey(privateKey);
        when(publicKey.check()).thenReturn(false);

        boolean check = privateKey.check();

        assertFalse(check);
    }
}
