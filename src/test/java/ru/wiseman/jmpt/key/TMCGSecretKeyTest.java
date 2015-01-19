package ru.wiseman.jmpt.key;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;

import static org.junit.Assert.*;
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
//        TMCGPublicKey publicKey = mock(TMCGPublicKey.class);
//        TMCGSecretKey privateKey = spy(new TMCGSecretKey("Alice", "alice@gaos.org", 1024));
//        doReturn(publicKey).when(privateKey).makePublicKey(privateKey);
//        when(publicKey.check()).thenReturn(true);
//
//        boolean check = privateKey.check();
//
//        assertTrue(check);
    }

    @Test
    public void check_improperSecretKey_returnsFalse() throws Exception {
//        TMCGPublicKey publicKey = mock(TMCGPublicKey.class);
//        TMCGSecretKey privateKey = spy(new TMCGSecretKey("Alice", "alice@gaos.org", 1024));
//        doReturn(publicKey).when(privateKey).makePublicKey(privateKey);
//        when(publicKey.check()).thenReturn(false);
//
//        boolean check = privateKey.check();
//
//        assertFalse(check);
    }

    @Test
    public void mpz_sprime3mod4() throws Exception {
        TMCGSecretKey key = new TMCGSecretKey();
        System.out.println(key.mpz_sprime3mod4(500, 0));
    }

    @Test
    public void hFunction() throws Exception{
        byte[] expected = {110, -24, -77, 73, 38, 74, 99, 76, -124, 8, -17, 39, -38, 65, 83, -99, 31, 87, 127, 56};
        String text = "The Magic Words are Squeamish Ossifrage";

        assertArrayEquals(expected, Utils.h(text));
    }

    @Test
    public void hFunction2() throws Exception{
        byte[] expected = {-32, 27, -125, -110, -9, 47, -49, 56, 39, 17, -8, -41, 104, 93, 118, -30, 10, -65, 10, 98};
        String text = "The Magic Words are Squeamish OssifragelibTMCG0The Magic Words are Squeamish Ossifrage";

        assertArrayEquals(expected, Utils.h(text));
    }

    @Test
    public void gFunction() throws Exception{
        byte[] expected = {-80, -51, -58, -93, -36, -80, -51, -58, -93, -36, -80, -51};
        String text = "The Magic Words are Squeamish Ossifrage";

        assertArrayEquals(expected, Utils.g(text));
    }

    @Test
    public void mpz_import() throws Exception{
        byte[] data =  {-80, -96, -3, 26, -40};
        String expected = "9oi3w7vc";

        assertEquals(expected, Utils.mpzImport(data).toString(36));
    }

    @Test
    public void mpz_import2() throws Exception{
        byte[] data =  { -80, -96 };
        String expected = "yw0";
        BigInteger b = new BigInteger(expected, 36);

        assertEquals(expected, Utils.mpzImport(data).toString(36));
    }
}

