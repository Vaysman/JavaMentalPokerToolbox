package ru.wiseman.jmpt.card;

import ru.wiseman.jmpt.ImportException;
import ru.wiseman.jmpt.SchindelhauerTMCG;

import java.math.BigInteger;

public class TMCGCard implements Card {
    private int bits;
    private int players;
    private BigInteger[][] z;

    public TMCGCard() {
        this(0, 0);
    }

    public TMCGCard(int players, int bits) {
        this.players = players;
        this.bits = bits;
        allocate();
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
                z[i][j] = new BigInteger(tokens[tokenIndex], SchindelhauerTMCG.TMCG_MPZ_IO_BASE);
                tokenIndex++;
            }
        }
    }

    public void resize(int players, int bits) {
        this.players = players;
        this.bits = bits;
        allocate();
    }

    @Override
    public String toString() {
        StringBuilder card = new StringBuilder("crd|");
        card.append(players).append("|");
        card.append(bits).append("|");
        for (BigInteger[] bits : z) {
            for (BigInteger bit : bits) {
                card.append(bit.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE)).append("|");
            }
        }
        return card.toString();
    }

    private void allocate() {
        z = new BigInteger[players][bits];
    }
}
