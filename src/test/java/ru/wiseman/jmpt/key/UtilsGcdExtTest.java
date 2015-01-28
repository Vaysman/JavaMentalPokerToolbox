package ru.wiseman.jmpt.key;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class UtilsGcdExtTest {

    @Parameterized.Parameters(name = "{index}: gcdExt({0}, {1}) = [{2}, x, y]")

    public static Collection<Object[]> gcdData() {
        return Arrays.asList(new Object[][]{
                { BigInteger.TEN, BigInteger.ZERO, BigInteger.TEN },
                { BigInteger.ZERO, BigInteger.TEN, BigInteger.TEN },
                { BigInteger.valueOf(12), BigInteger.valueOf(30), BigInteger.valueOf(6) },
                { BigInteger.valueOf(991), BigInteger.valueOf(981), BigInteger.ONE }
        });
    }

    @Parameterized.Parameter(value = 0)
    public BigInteger a;
    @Parameterized.Parameter(value = 1)
    public BigInteger b;
    @Parameterized.Parameter(value = 2)
    public BigInteger expectedGcd;

    @Test
    public void gcdExt() throws Exception {
        BigInteger[] bezout = Utils.gcdExt(a, b);
        assertEquals(expectedGcd, bezout[0]);
        assertEquals(expectedGcd, a.multiply(bezout[1]).add(b.multiply(bezout[2])));
    }
}