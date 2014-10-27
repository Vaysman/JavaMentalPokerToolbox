package ru.wiseman.jmpt.key;

import java.util.ArrayList;
import java.util.List;

public class PublicKeyRingImpl implements PublicKeyRing {
    private List<PublicKey> keys;

    public PublicKeyRingImpl() {
        keys = new ArrayList<PublicKey>();
    }

    @Override
    public void add(PublicKey playerPublicKey) {
        keys.add(playerPublicKey);
    }

    @Override
    public int size() {
        return keys.size();
    }

    @Override
    public void clear() {
        keys.clear();
    }
}
