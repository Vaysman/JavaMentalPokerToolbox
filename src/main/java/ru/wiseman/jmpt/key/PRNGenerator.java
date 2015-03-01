package ru.wiseman.jmpt.key;

import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;
import ru.wiseman.jmpt.SchindelhauerTMCG;

import java.math.BigInteger;

public class PRNGenerator {
    private final BigInteger m;
    private final int mnsize;
    private StringBuilder seed;

    public PRNGenerator(BigInteger m, BigInteger y) {
        this.m = m;
        mnsize = m.bitLength() / 8;
        seed = new StringBuilder();
        seed.append(m.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE))
                .append("^")
                .append(y.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE));
    }

    public BigInteger nextCoprime() {
        BigInteger random;
        // common random number \in Z^*_m (build from hash function g)
        do {
            random = generateNumberUpdateSeed();
        } while (!random.gcd(m).equals(BigInteger.ONE));
        return random;
    }

    public BigInteger nextNQR() {
        BigInteger random;
        // common random number foo \in Z^\circ_m (build from hash function g)
        do {
            random = generateNumberUpdateSeed();
        } while (IntegerFunctions.jacobi(random, m) != 1);
        return random;
    }

    private BigInteger generateNumberUpdateSeed() {
        BigInteger random;
        String input = seed.toString();
        byte[] mn = Utils.g(input, mnsize);
        random = Utils.mpzImport(mn);
        random = random.mod(m);
        seed.append(random.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE));
        return random;
    }
}
