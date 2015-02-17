package ru.wiseman.jmpt.key;

import org.junit.Test;

import java.math.BigInteger;

import static org.junit.Assert.*;

public class UtilsTest {

    @Test
    public void mpz_qrmn_p() throws Exception {
        // some different cases randomly selected
        assertTrue(Utils.mpz_qrmn_p(BigInteger.ONE, BigInteger.valueOf(3), BigInteger.valueOf(7), null));
        assertFalse(Utils.mpz_qrmn_p(BigInteger.valueOf(9), BigInteger.valueOf(3), BigInteger.valueOf(7), null));
        assertFalse(Utils.mpz_qrmn_p(BigInteger.valueOf(30), BigInteger.valueOf(3), BigInteger.valueOf(7), null));
        assertTrue(Utils.mpz_qrmn_p(BigInteger.valueOf(16), BigInteger.valueOf(3), BigInteger.valueOf(7), null));
        assertTrue(Utils.mpz_qrmn_p(BigInteger.valueOf(4), BigInteger.valueOf(3), BigInteger.valueOf(7), null));
        assertTrue(Utils.mpz_qrmn_p(BigInteger.valueOf(16), BigInteger.valueOf(5), BigInteger.valueOf(11), null));
        assertFalse(Utils.mpz_qrmn_p(BigInteger.valueOf(5), BigInteger.valueOf(5), BigInteger.valueOf(11), null));
        assertFalse(Utils.mpz_qrmn_p(BigInteger.valueOf(37), BigInteger.valueOf(5), BigInteger.valueOf(11), null));
    }

    @Test
    public void mpz_sprime3mod4() throws Exception {
        int anyInt = 0;
        int size = 6;
        BigInteger actual = Utils.mpz_sprime3mod4(size, anyInt);

        assertEquals(size, actual.bitLength());
        assertEquals(3, actual.mod(BigInteger.valueOf(4)).intValue());
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
    public void gFunction2() throws Exception{
        byte[] expected = { 78, -112, 102, 22, -52, 78, -112, 102, 22, -52, 78, -112, 102, 22, -52, 78, -112, 102, 22, -52, 78, -112, 102, 22, -52, 78, -112, 102, 22, -52, 78, -112, 102, 22, -52, 78, -112, 102, 22, -52, 78 };
        String text = "cyhr9jnjp5f8iq30b34rwmvnpu2st75hk89ek9j80lqhh1xmxo68cz3r9e3f4yhp^5";

        assertArrayEquals(expected, Utils.g(text, 41));
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

        assertEquals(expected, Utils.mpzImport(data).toString(36));
    }

    @Test
    public void mpz_import3() throws Exception{
        byte[] data =  { 78, -112, 102, 22, -52, 78, -112, 102, 22, -52, 78, -112, 102, 22, -52, 78, -112, 102, 22, -52, 78, -112, 102, 22, -52, 78, -112, 102, 22, -52, 78, -112, 102, 22, -52, 78, -112, 102, 22, -52, 78 };
        String expected = "1i7i88x8cuggcjrwuqb3cg16t5g35bjqjdj92ew1g6dq4a2vicjg13kgk3uuhlce";

        assertEquals(expected, Utils.mpzImport(data).toString(36));
    }

    @Test
    public void gcdExt() throws Exception{
        BigInteger expectedGcd = BigInteger.valueOf(6);
        BigInteger a = BigInteger.valueOf(12);
        BigInteger b = BigInteger.valueOf(30);

        BigInteger[] bezout = Utils.gcdExt(a, b);
        assertEquals(expectedGcd, bezout[0]);
        assertEquals(expectedGcd, bezout[1].multiply(a).add(bezout[2].multiply(b)));
    }

    @Test
    public void gcdEx2() throws Exception{
        BigInteger expectedGcd = BigInteger.ONE;
        BigInteger a = BigInteger.valueOf(991);
        BigInteger b = BigInteger.valueOf(981);

        BigInteger[] bezout = Utils.gcdExt(a, b);
        assertEquals(expectedGcd, bezout[0]);
        assertEquals(expectedGcd, bezout[0]);
        assertEquals(expectedGcd, bezout[1].multiply(a).add(bezout[2].multiply(b)));
    }

    @Test
    public void mpz_sqrtmp_r() throws  Exception {
        BigInteger actual = Utils.mpz_sqrtmp_r(BigInteger.valueOf(2), BigInteger.valueOf(7));
        BigInteger expected = BigInteger.valueOf(4);
        assertEquals(expected, actual);

        actual = Utils.mpz_sqrtmp_r(BigInteger.valueOf(4), BigInteger.valueOf(11));
        expected = BigInteger.valueOf(9);
        assertEquals(expected, actual);

        actual = Utils.mpz_sqrtmp_r(BigInteger.ZERO, BigInteger.valueOf(11));
        expected = BigInteger.ZERO;
        assertEquals(expected, actual);


    }
}
