package ru.wiseman.jmpt.card;

import ru.wiseman.jmpt.Consts;
import ru.wiseman.jmpt.ImportException;
import ru.wiseman.jmpt.key.PublicKey;
import ru.wiseman.jmpt.key.PublicKeyRing;
import ru.wiseman.jmpt.key.Utils;

import java.math.BigInteger;

public class TMCGCard implements Card {
    private int bits;
    private int players;
    private BigInteger[][] z;
    private final int maxCardType;

    public TMCGCard() {
        this(0, 0);
    }

    public TMCGCard(int players, int bits) {
        this.players = players;
        this.bits = bits;
        allocate();
        // TMCG_MaxCardType = 2^{TMCG_TypeBits}
        maxCardType = 1 << bits;
    }

    public TMCGCard(int players, int bits, int type, PublicKeyRing ring) {
        this(players, bits);

        assert type < maxCardType;
        assert ring.size() == players;

        for (int w = 0; w < bits; w++) {
            BigInteger z = BigInteger.ONE;
            if((type & 1) > 0) {
                z = ring.getKeyForPlayer(0).getY();
            }
            type >>= 1;
            this.z[0][w] = z;
        }

        for (int k = 1; k < players; k++) {
            for (int w = 0; w < bits; w++) {
                this.z[0][w] =  BigInteger.ONE;
            }
        }
    }



    public int getBitsCount() {
        return bits;
    }

    public int getPlayersCount() {
        return players;
    }

    public void importCard(String s) {
        String tokens[] = s.split("\\|");

        // check magic
        if (!tokens[0].equals("crd")) {
            throw new ImportException("Wrong magic");
        }

        // card description
        int players = Integer.parseInt(tokens[1]);
        int bits = Integer.parseInt(tokens[2]);

        if (players < 2 && bits < 1) {
            throw new ImportException("Wrong card description players: " + players + ", bits: " + bits);
        }

        resize(players, bits);
        int tokenIndex = 3;
        for (int i = 0; i < players; i++) {
            for (int j = 0; j < bits; j++) {
                z[i][j] = new BigInteger(tokens[tokenIndex], Consts.TMCG_MPZ_IO_BASE);
                tokenIndex++;
            }
        }
    }

    public TMCGCard mask(TMCGCardSecret cs, PublicKeyRing ring, boolean timingAttackProtection) {
        assert ring.size() == players;
        assert cs.getPlayersCount() == players;
        assert cs.getBitsCount() == bits;

        TMCGCard masked = new TMCGCard(players, bits);

        for (int k = 0; k < players; k++) {
            for (int w = 0; w < bits; w++) {
                PublicKey key = ring.getKeyForPlayer(k);
                masked.z[k][w] = Utils.maskValue(z[k][w], cs.r[k][w], key.getY(), key.getModulus(), cs.b[k][w], timingAttackProtection);
            }
        }
        return masked;
    }

    public void resize(int players, int bits) {
        this.players = players;
        this.bits = bits;
        allocate();
    }

    public void setZ(int player, int bit, BigInteger val) {
        z[player][bit] = val;
    }

    @Override
    public String toString() {
        StringBuilder card = new StringBuilder("crd|");
        card.append(players).append("|");
        card.append(bits).append("|");
        for (BigInteger[] bits : z) {
            for (BigInteger bit : bits) {
                card.append(bit.toString(Consts.TMCG_MPZ_IO_BASE)).append("|");
            }
        }
        return card.toString();
    }

    private void allocate() {
        z = new BigInteger[players][bits];
    }
}
