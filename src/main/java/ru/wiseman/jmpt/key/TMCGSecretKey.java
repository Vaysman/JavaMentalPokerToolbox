package ru.wiseman.jmpt.key;

import java.math.BigInteger;

public class TMCGSecretKey implements SecretKey {
    public TMCGSecretKey(String name, String email, int keySize) {
    }

    public TMCGSecretKey(String name, String email, int keySize, boolean appendNizkProf) {

    }

    public static TMCGSecretKey importKey(String key) {
        return new TMCGSecretKey(null, null, 1024);
    }

    @Override
    public boolean check() {
        TMCGPublicKey publicKey = makePublicKey(this);
        return publicKey.check();
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
    public BigInteger getPublicModulus() {
        return null;
    }

    @Override
    public BigInteger getPublicNqr() {
        return null;
    }

    @Override
    public boolean verify(String string, String signature) {
        return false;
    }

    @Override
    public byte[] decrypt(byte[] encryptedText) {
        return new byte[0];
    }

    @Override
    public String sign(String toSign) {
        return null;
    }

    TMCGPublicKey makePublicKey(TMCGSecretKey secretKey) {
        return new TMCGPublicKey(secretKey);
    }
}
