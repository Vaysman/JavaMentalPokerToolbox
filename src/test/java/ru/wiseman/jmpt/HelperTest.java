package ru.wiseman.jmpt;

import org.junit.Test;

import java.math.BigInteger;

public class HelperTest {
    @Test
    public void testOut() throws Exception {
        BigInteger n = BigInteger.valueOf(37);
        System.out.println("**" + n.divide(BigInteger.valueOf(5)) + "**");
        System.out.println("**" + BigInteger.valueOf(7).remainder(BigInteger.valueOf(4)) + "**");
    }


}
