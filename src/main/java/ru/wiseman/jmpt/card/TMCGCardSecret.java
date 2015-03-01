package ru.wiseman.jmpt.card;

import ru.wiseman.jmpt.ImportException;
import ru.wiseman.jmpt.SchindelhauerTMCG;

import java.math.BigInteger;

public class TMCGCardSecret implements CardSecret {
    private int bits;
    private int players;
    private BigInteger[][] r, b;

    public TMCGCardSecret() {
        this(0, 0);
    }

    public TMCGCardSecret(int players, int bits) {
        this.players = players;
        this.bits = bits;
        allocate();
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
                r[i][j] = new BigInteger(tokens[tokenIndex], SchindelhauerTMCG.TMCG_MPZ_IO_BASE);
                tokenIndex++;
                b[i][j] = new BigInteger(tokens[tokenIndex], SchindelhauerTMCG.TMCG_MPZ_IO_BASE);
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
        StringBuilder card = new StringBuilder("crs|");
        card.append(players).append("|");
        card.append(bits).append("|");
        for (int i = 0; i < players; i++) {
            for (int j = 0; j < bits; j++) {
                card.append(r[i][j].toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE)).append("|");
                card.append(b[i][j].toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE)).append("|");
            }
        }

        return card.toString();
    }

    private void allocate() {
        r = new BigInteger[players][bits];
        b = new BigInteger[players][bits];
    }
}
