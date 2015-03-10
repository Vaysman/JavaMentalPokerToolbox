package ru.wiseman.jmpt.card;

import ru.wiseman.jmpt.Consts;
import ru.wiseman.jmpt.ImportException;
import ru.wiseman.jmpt.key.PublicKeyRing;
import ru.wiseman.jmpt.key.Utils;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class TMCGCardSecret implements CardSecret {
    private boolean[][] b;
    private int bits;
    private int players;
    private BigInteger[][] r;
    private Random random = new SecureRandom();

    private TMCGCardSecret() {
        this(0, 0);
    }

    private TMCGCardSecret(int players, int bits) {
        this.players = players;
        this.bits = bits;
        allocate();
    }

    public TMCGCardSecret(int players, int bits, PublicKeyRing ring, int index) {
        this(players, bits);

        assert ring.size() == players;

        TMCGCardSecret cs = new TMCGCardSecret(players, bits);

        for (int k = 0; k < players; k++) {
            BigInteger m = ring.getModulusForPlayer(k);

            for (int w = 0; w < bits; w++) {
                // choose uniformly at random a number r \in Z^*_m
                BigInteger r;

                do {
                    r = Utils.mpz_srandomm(m);
                } while (!r.gcd(m).equals(BigInteger.ONE));
                cs.setRandom(k, w, r);

                // choose uniformly at random a bit b \in {0, 1}
                // or set it initially to zero in the index-th row
                boolean bit = randomBit();
                if (k == index) {
                    bit = false;
                }

                cs.setBit(k, w, bit);
            }
        }

        // XOR b_{ij} with i \neq index (keep type of this card)
        for (int k = 0; k < players; k++) {
            if (k == index) {
                continue;
            }
            for (int w = 0; w < bits; w++) {
                if (cs.getBit(index, w)) {
                    if (cs.getBit(k, w)) {
                        cs.setBit(index, w, false);
                    } else {
                        cs.setBit(index, w, true);
                    }
                } else {
                    if (cs.getBit(k, w)) {
                        cs.setBit(index, w, true);
                    } else {
                        cs.setBit(index, w, false);
                    }
                }
            }
        }
    }

    public boolean getBit(int player, int bit) {
        return b[player][bit];
    }

    public int getBitsCount() {
        return bits;
    }

    @Override
    public int getPlayersCount() {
        return players;
    }

    public BigInteger getRandom(int player, int bit) {
        return r[player][bit];
    }

    public void importCard(String s) {
        String tokens[] = s.split("\\|");

        // check magic
        if (!tokens[0].equals("crs")) {
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
                r[i][j] = new BigInteger(tokens[tokenIndex], Consts.TMCG_MPZ_IO_BASE);
                tokenIndex++;
                b[i][j] = tokens[tokenIndex].startsWith("1");
                tokenIndex++;
            }
        }
    }

    public void resize(int players, int bits) {
        this.players = players;
        this.bits = bits;
        allocate();
    }

    public void setBit(int player, int bit, boolean val) {
        b[player][bit] = val;
    }

    public void setRandom(int player, int bit, BigInteger val) {
        r[player][bit] = val;
    }

    @Override
    public String toString() {
        StringBuilder card = new StringBuilder("crs|");
        card.append(players).append("|");
        card.append(bits).append("|");
        for (int i = 0; i < players; i++) {
            for (int j = 0; j < bits; j++) {
                card.append(r[i][j].toString(Consts.TMCG_MPZ_IO_BASE)).append("|");
                card.append(b[i][j] ? 1 : 0).append("|");
            }
        }

        return card.toString();
    }

    private void allocate() {
        r = new BigInteger[players][bits];
        b = new boolean[players][bits];
    }

    private boolean randomBit() {
        return random.nextBoolean();
    }
}
