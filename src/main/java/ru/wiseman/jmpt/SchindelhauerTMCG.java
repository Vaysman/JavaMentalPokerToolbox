package ru.wiseman.jmpt;

import ru.wiseman.jmpt.card.*;
import ru.wiseman.jmpt.key.PublicKeyRing;
import ru.wiseman.jmpt.key.TMCGPublicKey;
import ru.wiseman.jmpt.key.TMCGSecretKey;
import ru.wiseman.jmpt.key.Utils;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.Random;

public class SchindelhauerTMCG {
    private int bits;
    private int maxCardType;
    private BigInteger messageSpace[];
    private int players;
    private Random random;
    private int ret;
    private int securityLevel;

    public SchindelhauerTMCG(int numberOfProofs, int numberOfPlayer, int numberOfBitsForEncodingCard) {
        random = new SecureRandom();
        securityLevel = numberOfProofs;
        players = numberOfPlayer;
        bits = numberOfBitsForEncodingCard;
        // TMCG_MaxCardType = 2^{TMCG_TypeBits}
        maxCardType = 1 << bits;

        // initialize the message space for the VTMF scheme
        messageSpace = new BigInteger[maxCardType];
    }

    public TMCGCardSecret TMCG_CreateCardSecret(final PublicKeyRing ring, int index) {
        assert ring.size() == players;

        TMCGCardSecret cs = new TMCGCardSecret(players, bits);

        for (int k = 0; k < players; k++) {
            for (int w = 0; w < bits; w++) {
                // choose uniformly at random a number r \in Z^*_m
                BigInteger m = ring.getModulusForPlayer(k);
                BigInteger r;

                do {
                    r = Utils.mpz_srandomm(m);
                } while (!r.gcd(m).equals(BigInteger.ONE));
                cs.setRandom(k, w, r);

                // choose uniformly at random a bit b \in {0, 1}
                // or set it initially to zero in the index-th row
                BigInteger bit = randomBit();
                if (k == index) {
                    bit = BigInteger.ZERO;
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
                // we can use == because BigInteger immutable
                if (cs.getBit(index, w) == BigInteger.ONE) {
                    if (cs.getBit(k, w) == BigInteger.ONE) {
                        cs.setBit(index, w, BigInteger.ZERO);
                    } else {
                        cs.setBit(index, w, BigInteger.ONE);
                    }
                } else {
                    if (cs.getBit(k, w) == BigInteger.ONE) {
                        cs.setBit(index, w, BigInteger.ONE);
                    } else {
                        cs.setBit(index, w, BigInteger.ZERO);
                    }
                }
            }
        }
        return cs;
    }

    public void TMCG_CreateCardSecret(VTMFCardSecret cs, BarnettSmartVTMF_dlog vtmf) {
        throw new NotImplementedException();
    }

    public void TMCG_CreateOpenCard(TMCGCard c, final PublicKeyRing ring, int type) {
        throw new NotImplementedException();
    }

    public void TMCG_CreateOpenCard(VTMFCard c, BarnettSmartVTMF_dlog vtmf, int type) {
        throw new NotImplementedException();
    }

    public void TMCG_CreatePrivateCard(TMCGCard c, TMCGCardSecret cs, final PublicKeyRing ring,
                                       int index, int type) {
        throw new NotImplementedException();
    }

    public void TMCG_CreatePrivateCard(VTMFCard c, VTMFCardSecret cs, BarnettSmartVTMF_dlog vtmf,
                                       int type) {
        throw new NotImplementedException();
    }

    int TMCG_CreateStackSecret(TMCGStackSecret<TMCGCardSecret> ss, boolean cyclic,
                               final PublicKeyRing ring, int index, int size) {
        throw new NotImplementedException();
    }

    int TMCG_CreateStackSecret(TMCGStackSecret<VTMFCardSecret> ss, boolean cyclic, int size,
                               BarnettSmartVTMF_dlog vtmf) {
        throw new NotImplementedException();
    }

    public void TMCG_MaskCard(final TMCGCard c, TMCGCard cc, final TMCGCardSecret cs,
                              final PublicKeyRing ring, boolean TimingAttackProtection) {
        throw new NotImplementedException();
    }

    public void TMCG_MaskCard(final TMCGCard c, TMCGCard cc, final TMCGCardSecret cs,
                              final PublicKeyRing ring) {
        TMCG_MaskCard(c, cc, cs, ring, true);
    }

    public void TMCG_MaskCard(final VTMFCard c, VTMFCard cc, final VTMFCardSecret cs,
                              BarnettSmartVTMF_dlog vtmf, boolean TimingAttackProtection) {
        throw new NotImplementedException();
    }

    public void TMCG_MaskCard(final VTMFCard c, VTMFCard cc, final VTMFCardSecret cs,
                              BarnettSmartVTMF_dlog vtmf) {
        TMCG_MaskCard(c, cc, cs, vtmf, true);
    }

    public void TMCG_MixStack(final TMCGStack<TMCGCard> s, TMCGStack<TMCGCard> s2,
                              final TMCGStackSecret<TMCGCardSecret> ss,
                              final PublicKeyRing ring, boolean TimingAttackProtection) {
        throw new NotImplementedException();
    }

    public void TMCG_MixStack(final TMCGStack<TMCGCard> s, TMCGStack<TMCGCard> s2,
                              final TMCGStackSecret<TMCGCardSecret> ss,
                              final PublicKeyRing ring) {
        TMCG_MixStack(s, s2, ss, ring, true);
    }

    public void TMCG_MixStack(final TMCGStack<VTMFCard> s, TMCGStack<VTMFCard> s2,
                              final TMCGStackSecret<VTMFCardSecret> ss,
                              BarnettSmartVTMF_dlog vtmf, boolean TimingAttackProtection) {
        throw new NotImplementedException();
    }

    public void TMCG_MixStack(final TMCGStack<VTMFCard> s, TMCGStack<VTMFCard> s2,
                              final TMCGStackSecret<VTMFCardSecret> ss,
                              BarnettSmartVTMF_dlog vtmf) {
        TMCG_MixStack(s, s2, ss, vtmf, true);
    }

    public void TMCG_ProveCardSecret(final TMCGCard c, final TMCGSecretKey key, int index,
                                     InputStream in, OutputStream out) {
        throw new NotImplementedException();
    }

    public void TMCG_ProveCardSecret(final VTMFCard c, BarnettSmartVTMF_dlog vtmf,
                                     InputStream in, OutputStream out) {
        throw new NotImplementedException();
    }

    public void TMCG_ProveMaskCard(final TMCGCard c, final TMCGCard cc, final TMCGCardSecret cs,
                                   final PublicKeyRing ring, InputStream in, OutputStream out) {
        throw new NotImplementedException();
    }

    public void TMCG_ProveMaskCard(final VTMFCard c, final VTMFCard cc, final VTMFCardSecret cs,
                                   BarnettSmartVTMF_dlog vtmf, InputStream in, OutputStream out) {
        throw new NotImplementedException();
    }

    public void TMCG_ProveStackEquality(final TMCGStack<TMCGCard> s, final TMCGStack<TMCGCard> s2,
                                        final TMCGStackSecret<TMCGCardSecret> ss, boolean cyclic,
                                        final PublicKeyRing ring, int index,
                                        InputStream in, OutputStream out) {
        throw new NotImplementedException();
    }

    public void TMCG_ProveStackEquality(final TMCGStack<VTMFCard> s, final TMCGStack<VTMFCard> s2,
                                        final TMCGStackSecret<VTMFCardSecret> ss, boolean cyclic,
                                        BarnettSmartVTMF_dlog vtmf, InputStream in, OutputStream out) {
        throw new NotImplementedException();
    }

    public void TMCG_ProveStackEquality_Groth(final TMCGStack<VTMFCard> s, final TMCGStack<VTMFCard> s2,
                                              final TMCGStackSecret<VTMFCardSecret> ss,
                                              BarnettSmartVTMF_dlog vtmf, GrothVSSHE vsshe,
                                              InputStream in, OutputStream out) {
        throw new NotImplementedException();
    }

    public void TMCG_SelfCardSecret(final TMCGCard c, TMCGCardSecret cs, final TMCGSecretKey key,
                                    int index) {
        throw new NotImplementedException();
    }

    public void TMCG_SelfCardSecret(final VTMFCard c, BarnettSmartVTMF_dlog vtmf) {
        throw new NotImplementedException();
    }

    int TMCG_TypeOfCard(final TMCGCardSecret cs) {
        throw new NotImplementedException();
    }

    int TMCG_TypeOfCard(final VTMFCard c, BarnettSmartVTMF_dlog vtmf) {
        throw new NotImplementedException();
    }

    boolean TMCG_VerifyCardSecret(final TMCGCard c, TMCGCardSecret cs, final TMCGPublicKey key,
                                  int index, InputStream in, OutputStream out) {
        throw new NotImplementedException();
    }

    boolean TMCG_VerifyCardSecret(final VTMFCard c, BarnettSmartVTMF_dlog vtmf,
                                  InputStream in, OutputStream out) {
        throw new NotImplementedException();
    }

    boolean TMCG_VerifyMaskCard(final TMCGCard c, final TMCGCard cc, final PublicKeyRing ring,
                                InputStream in, OutputStream out) {
        throw new NotImplementedException();
    }

    boolean TMCG_VerifyMaskCard(final VTMFCard c, final VTMFCard cc, BarnettSmartVTMF_dlog vtmf,
                                InputStream in, OutputStream out) {
        throw new NotImplementedException();
    }

    boolean TMCG_VerifyStackEquality(final TMCGStack<TMCGCard> s, final TMCGStack<TMCGCard> s2,
                                     boolean cyclic, final PublicKeyRing ring,
                                     InputStream in, OutputStream out) {
        throw new NotImplementedException();
    }

    boolean TMCG_VerifyStackEquality(final TMCGStack<VTMFCard> s, final TMCGStack<VTMFCard> s2,
                                     boolean cyclic, BarnettSmartVTMF_dlog vtmf,
                                     InputStream in, OutputStream out) {
        throw new NotImplementedException();
    }

    boolean TMCG_VerifyStackEquality_Groth(final TMCGStack<VTMFCard> s, final TMCGStack<VTMFCard> s2,
                                           BarnettSmartVTMF_dlog vtmf, GrothVSSHE vsshe,
                                           InputStream in, OutputStream out) {
        throw new NotImplementedException();
    }

    private void proveQuadraticResidue(TMCGSecretKey key, BigInteger t, InputStream in, OutputStream out) {
        List<BigInteger> rr, ss;
        BigInteger foo, bar, lej, t_sqrt;
        int security_desire = 0;
/*
            std::vector<mpz_ptr> rr, ss;
	mpz_t foo, bar, lej, t_sqrt;
	unsigned long int security_desire = 0;
	in >> security_desire, in.ignore(1, '\n');

	mpz_init(foo), mpz_init(bar), mpz_init(lej), mpz_init(t_sqrt);

	// compute mpz_sqrtmn (modular square root) of t
	assert(mpz_qrmn_p(t, key.p, key.q, key.m));
	mpz_sqrtmn_fast(t_sqrt, t, key.p, key.q, key.m,
		key.gcdext_up, key.gcdext_vq, key.pa1d4, key.qa1d4);

	// phase (P2)
	for (unsigned long int i = 0; i < security_desire; i++)
	{
		mpz_ptr r = new mpz_t(), s = new mpz_t();
		mpz_init(r), mpz_init(s);

		// choose uniformly at random a number $r \in Z^*_m$
		do
		{
			mpz_srandomm(r, key.m);
			mpz_gcd(lej, r, key.m);
		}
		while (mpz_cmp_ui(lej, 1L) || !mpz_cmp_ui(r, 1L));

		// compute $s := t_sqrt \cdot r_i^{-1} \bmod m$
		ret = mpz_invert(s, r, key.m);
		assert(ret);
		mpz_mul(s, s, t_sqrt);
		mpz_mod(s, s, key.m);
		assert(mpz_cmp_ui(s, 1L));

		// compute $R_i = r_i^2 \bmod m,\; S_i = s_i^2 \bmod m$
		mpz_mul(foo, r, r);
		mpz_mod(foo, foo, key.m);
		mpz_mul(bar, s, s);
		mpz_mod(bar, bar, key.m);

		// check the congruence $R_i \cdot S_i \equiv t \pmod{m}$
		#ifndef NDEBUG
			mpz_mul(lej, foo, bar);
			mpz_mod(lej, lej, key.m);
			assert(mpz_congruent_p(t, lej, key.m));
		#endif

		// store $r_i$, $s_i$ and send $R_i$, $S_i$ to the verifier
		rr.push_back(r), ss.push_back(s);
		out << foo << std::endl, out << bar << std::endl;
	}

	// phase (P4)
	for (unsigned long int i = 0; i < security_desire; i++)
	{
		// receive R/S-question from the verifier
		in >> foo;

		// send proof to the verifier
		if (mpz_get_ui(foo) & 1L)
			out << rr[i] << std::endl;
		else
			out << ss[i] << std::endl;
	}

	mpz_clear(foo), mpz_clear(bar), mpz_clear(lej), mpz_clear(t_sqrt);
	for (std::vector<mpz_ptr>::iterator ri = rr.begin(); ri != rr.end(); ri++)
		mpz_clear(*ri), delete *ri;
	for (std::vector<mpz_ptr>::iterator si = ss.begin(); si != ss.end(); si++)
		mpz_clear(*si), delete *si;

         */

    }

    private BigInteger randomBit() {
        return random.nextBoolean() ? BigInteger.ONE : BigInteger.ZERO;
    }

    public class BarnettSmartVTMF_dlog {
    }

    public class GrothVSSHE {
    }

}
