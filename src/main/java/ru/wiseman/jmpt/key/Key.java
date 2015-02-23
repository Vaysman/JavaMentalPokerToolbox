package ru.wiseman.jmpt.key;

import java.math.BigInteger;

public interface Key {
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
}
