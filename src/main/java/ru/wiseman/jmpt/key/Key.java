package ru.wiseman.jmpt.key;

public interface Key {
    boolean check();

    String encrypt(String clearText);

    String fingerprint();

    boolean verify(String string, String signature);

    String keyId();
}
