package ru.wiseman.jmpt.key;

public interface PublicKeyRing {
    void add(PublicKey playerPublicKey);

    int size();

    void clear();
}
