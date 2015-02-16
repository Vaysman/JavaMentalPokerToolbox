package ru.wiseman.jmpt.key;

import java.math.BigInteger;

public interface Key {
    public boolean check();

    public String encrypt(String clearText);

    public String fingerprint();

    public BigInteger getPublicModulus();

    public BigInteger getPublicNqr();

    public boolean verify(String string, String signature);
}
