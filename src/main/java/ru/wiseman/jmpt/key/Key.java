package ru.wiseman.jmpt.key;

import java.math.BigInteger;

public interface Key {
    BigInteger BIG_INTEGER_2 = BigInteger.valueOf(2);
    BigInteger BIG_INTEGER_5 = BigInteger.valueOf(5);
    BigInteger BIG_INTEGER_8 = BigInteger.valueOf(8);

    String getName();

    String getEmail();

    String getType();

    BigInteger getModulus();

    BigInteger getY();

    boolean check();

    String encrypt(String clearText);

    String fingerprint();

    boolean verify(String string, String signature);

    String keyId();

    String keyId(int size);
}
