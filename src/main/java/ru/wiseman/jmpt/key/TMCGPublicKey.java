package ru.wiseman.jmpt.key;

public class TMCGPublicKey implements PublicKey {
    public TMCGPublicKey(SecretKey secretKey) {
    }

    @Override
    public boolean check() {
        return true;
    }

    @Override
    public byte[] encrypt(byte[] clearText) {
        return new byte[0];
    }

    @Override
    public String fingerprint() {
        return null;
    }

    @Override
    public boolean verify(String string, String signature) {
        return false;
    }

    public static TMCGPublicKey importKey(String key) {
        return new TMCGPublicKey(null);
    }
}
