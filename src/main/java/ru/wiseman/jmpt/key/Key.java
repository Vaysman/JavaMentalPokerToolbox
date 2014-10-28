package ru.wiseman.jmpt.key;

public interface Key {
    public boolean check();

    public byte[] encrypt(byte[] clearText);

    public String fingerprint();
    public boolean verify(String string, String signature);
}
