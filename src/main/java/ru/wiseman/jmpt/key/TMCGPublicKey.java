package ru.wiseman.jmpt.key;

public class TMCGPublicKey implements PublicKey {
    public TMCGPublicKey(SecretKey secretKey) {
    }

    @Override
    public boolean check() {
        return true;
    }
}
