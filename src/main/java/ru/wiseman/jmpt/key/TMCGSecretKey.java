package ru.wiseman.jmpt.key;

/**
 * @author Mikhail Vaysman
 */
public class TMCGSecretKey implements SecretKey {
    public TMCGSecretKey(String name, String email, long keySize) {
    }

    public TMCGSecretKey(String name, String email, long keySize, boolean unknown) {

    }

    @Override
    public boolean check() {
        return true;
    }
}
