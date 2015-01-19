package ru.wiseman.jmpt;

import org.junit.Test;

import java.math.BigInteger;

public class HelperTest {
    @Test
    public void testOut() throws Exception {
        BigInteger n = BigInteger.valueOf(37);
        System.out.println("**" + n.toString(36) + "**");
    }


}
