package ru.wiseman.jmpt.key;

import java.math.BigInteger;

public interface PublicKeyRing {
    void add(PublicKey playerPublicKey);

    PublicKey getKeyForPlayer(int index);

    BigInteger getModulusForPlayer(int index);

    int size();

    void clear();
}
