package ru.wiseman.jmpt.key;

public class TMCGSecretKey implements SecretKey {
    public  TMCGSecretKey(String name, String email, int keySize) {
    }

    public TMCGSecretKey(String name, String email, int keySize, boolean appendNizkProf) {

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

    public static TMCGSecretKey importKey(String key) {
        return new TMCGSecretKey(null, null, 1024);
    }

    @Override
    public byte[] decrypt(byte[] encryptedText) {
        return new byte[0];
    }

    @Override
    public String sign(String toSign) {
        return null;
    }
}
