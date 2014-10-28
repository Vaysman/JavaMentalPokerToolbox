package ru.wiseman.jmpt.key;

public interface SecretKey extends Key {
    byte[] decrypt(byte[] encryptedText);

    String sign(String toSign);
}
