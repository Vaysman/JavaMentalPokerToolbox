package ru.wiseman.jmpt.key;

import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;
import ru.wiseman.jmpt.SchindelhauerTMCG;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class TMCGSecretKey implements SecretKey {
    public static final BigInteger BIG_INTEGER_8 = BigInteger.valueOf(8);
    public static final BigInteger BIG_INTEGER_2 = BigInteger.valueOf(2);
    private String name;
    private String email;
    private String type;
    private String nizk;
    private String sig;
    private BigInteger m;
    private BigInteger y;
    private BigInteger p;
    private BigInteger q;
    // non-persistent members
    private BigInteger y1;
    private BigInteger m1pq;
    private BigInteger gcdext_up;
    private BigInteger gcdext_vq;
    private BigInteger pa1d4;
    private BigInteger qa1d4;
    private int ret;
    private Random random;


    public TMCGSecretKey(String name, String email, int keySize, boolean appendNizkProf) {
        this();
        this.name = name;
        this.email = email;

        generate(keySize, appendNizkProf);
    }

    public TMCGSecretKey() {
        random = new SecureRandom();
    }

    private void generate(int keySize, boolean appendNizkProf) {
        BigInteger foo, bar;
        int size = (keySize / 2) + 1;

        String type = "TMCG/RABIN_" + keySize + (appendNizkProf ? "_NIZK" : "");
        do {
            // choose a random safe prime p, but with fixed size (n/2 + 1) bit
            p = Utils.mpz_sprime3mod4(size, SchindelhauerTMCG.TMCG_MR_ITERATIONS);
            assert !p.mod(BIG_INTEGER_8).equals(BigInteger.ONE);

            // choose a random safe prime q, but with fixed size (n/2 + 1) bit
            // and p \not\equiv q (mod 8)
            foo = BIG_INTEGER_8;
            do {
                q = Utils.mpz_sprime3mod4(size, SchindelhauerTMCG.TMCG_MR_ITERATIONS);
            } while (p.mod(foo).equals(q));
            assert !q.mod(BIG_INTEGER_8).equals(BigInteger.ONE);
            assert(!p.mod(foo).equals(q));

            // compute modulus: m = p \cdot q
            m = p.multiply(q);

            // compute upper bound for SAEP, i.e. 2^{n+1} + 2^n
            foo = BigInteger.ONE;
            foo = foo.multiply(BIG_INTEGER_2.pow(keySize));
            bar = foo.multiply(BIG_INTEGER_2);
            bar = foo.add(bar);
        } while (m.bitLength() < keySize + 1 || m.compareTo(bar) >= 0);

        // choose a small $y \in NQR^\circ_m$ for fast TMCG encoding
        y = BigInteger.ONE;
        do {
            y = y.add(BigInteger.ONE);
        } while (IntegerFunctions.jacobi(y, m) != 1 || mpz_qrmn_p(y, p, q, m));

        // pre-compute non-persistent values
        precompute();

        // Rosario Gennaro, Daniele Micciancio, Tal Rabin:
        // 'An Efficient Non-Interactive Statistical Zero-Knowledge
        // Proof System for Quasi-Safe Prime Products',
        // 5th ACM Conference on Computer and Communication Security, CCS 1998

        // STAGE1/2: m = p^i * q^j, p and q prime
        // STAGE3: y \in NQR^\circ_m
//        std::ostringstream nizk2, input;
        String input = m.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) + "^" + y.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE);
        String nizk2 = "nzk^" + SchindelhauerTMCG.TMCG_KEY_NIZK_STAGE1 + "^";
//        input << m << "^" << y, nizk2 << "nzk^";
        int mnsize = m.bitLength() / 8;
//        char *mn = new char[mnsize];
        // STAGE1: m Square Free
        // soundness error probability \le d^{-TMCG_KEY_NIZK_STAGE1}
//        nizk2 << TMCG_KEY_NIZK_STAGE1 << "^";
        for(int stage1 =0 ; stage1 < SchindelhauerTMCG.TMCG_KEY_NIZK_STAGE1 && appendNizkProf ; stage1++) {
            // common random number foo \in Z^*_m (build from hash function g)
            do {
                byte[] mn = Utils.g(input);
                byte[] foo_data = new byte[mnsize];
                System.arraycopy(mn, 0, foo_data, 0, mnsize);
                foo = Utils.mpzImport(foo_data);
                foo = foo.mod(m);
                bar = foo.gcd(m);
                input = input + foo.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE);
            } while (bar.compareTo(BigInteger.ONE) != 0);

            // compute bar = foo^{m^{-1} mod \phi(m)} mod m
            bar = foo.modPow(m1pq, m);
            // update NIZK-proof stream
            nizk2 = nizk2 + bar.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) + "^";
        }

        // STAGE2: m Prime Power Product
        // soundness error probability \le 2^{-TMCG_KEY_NIZK_STAGE2}
        nizk2 = nizk2 + SchindelhauerTMCG.TMCG_KEY_NIZK_STAGE2 + "^";
        for (int stage2 = 0; (stage2 < SchindelhauerTMCG.TMCG_KEY_NIZK_STAGE2) && appendNizkProf; stage2++) {
            // common random number foo \in Z^*_m (build from hash function g)
            do {
                byte[] mn = Utils.g(input);
                byte[] foo_data = new byte[mnsize];
                System.arraycopy(mn, 0, foo_data, 0, mnsize);
                foo = Utils.mpzImport(foo_data);
                foo = foo.mod(m);
                bar = foo.gcd(m);
                input = input + foo.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE);
            } while (bar.compareTo(BigInteger.ONE) != 0);

            // compute square root of +-foo or +-2foo mod m
            if(Utils.mpz_qrmn_p(foo, p, q, m)) {
                bar = Utils.sqrtModR(foo, p, q, m);
            }
            nizk2  = nizk2 + bar.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) + "^";
        }
/*

	// STAGE2: m Prime Power Product
	// soundness error probability \le 2^{-TMCG_KEY_NIZK_STAGE2}
	nizk2 << TMCG_KEY_NIZK_STAGE2 << "^";
	for (size_t stage2 = 0; (stage2 < TMCG_KEY_NIZK_STAGE2) && nizk_key; stage2++)
	{
		// common random number foo \in Z^*_m (build from hash function g)
		do
		{
			g(mn, mnsize, (input.str()).c_str(), (input.str()).length());
			mpz_import(foo, 1, -1, mnsize, 1, 0, mn);
			mpz_mod(foo, foo, m);
			mpz_gcd(bar, foo, m);
			input << foo;
		}
		while (mpz_cmp_ui(bar, 1L));

		// compute square root of +-foo or +-2foo mod m
		if (mpz_qrmn_p(foo, p, q, m))
			mpz_sqrtmn_r(bar, foo, p, q, m);
		else
		{
			mpz_neg(foo, foo);
			if (mpz_qrmn_p(foo, p, q, m))
				mpz_sqrtmn_r(bar, foo, p, q, m);
			else
			{
				mpz_mul_2exp(foo, foo, 1L);
				if (mpz_qrmn_p(foo, p, q, m))
					mpz_sqrtmn_r(bar, foo, p, q, m);
				else
				{
					mpz_neg(foo, foo);
					if (mpz_qrmn_p(foo, p, q, m))
						mpz_sqrtmn_r(bar, foo, p, q, m);
					else
						mpz_set_ui(bar, 0L);
				}
			}
		}

		// update NIZK-proof stream
		nizk2 << bar << "^";
	}

	// STAGE3: y \in NQR^\circ_m
	// soundness error probability \le 2^{-TMCG_KEY_NIZK_STAGE3}
	nizk2 << TMCG_KEY_NIZK_STAGE3 << "^";
	for (size_t stage3 = 0; (stage3 < TMCG_KEY_NIZK_STAGE3) && nizk_key; stage3++)
	{
		// common random number foo \in Z^\circ_m (build from hash function g)
		do
		{
			g(mn, mnsize, (input.str()).c_str(), (input.str()).length());
			mpz_import(foo, 1, -1, mnsize, 1, 0, mn);
			mpz_mod(foo, foo, m);
			input << foo;
		}
		while (mpz_jacobi(foo, m) != 1);

		// compute square root
		if (!mpz_qrmn_p(foo, p, q, m))
		{
			mpz_mul(foo, foo, y);
			mpz_mod(foo, foo, m);
		}
		mpz_sqrtmn_r(bar, foo, p, q, m);

		// update NIZK-proof stream
		nizk2 << bar << "^";
	}

	nizk = nizk2.str();
	delete [] mn;
	mpz_clear(foo), mpz_clear(bar);

	// compute self-signature
	std::ostringstream data, repl;
	data << name << "|" << email << "|" << type << "|" <<
		m << "|" << y << "|" << nizk << "|";
	sig = sign(data.str());
	repl << "ID" << TMCG_KEYID_SIZE << "^";
	sig.replace(sig.find(repl.str()),
		(repl.str()).length() + TMCG_KEYID_SIZE, keyid());

         */
    }

    private void precompute() {

    }

    // quadratic residiosity mod n, with n = p * q
    private boolean mpz_qrmn_p(BigInteger y, BigInteger p, BigInteger q, BigInteger m) {
        return IntegerFunctions.jacobi(y, p) == 1 && IntegerFunctions.jacobi(y, q) == 1;
    }

    public static TMCGSecretKey importKey(String key) {
        return null;
    }

    @Override
    public boolean check() {
        TMCGPublicKey publicKey = makePublicKey(this);
        return publicKey.check();
    }

    @Override
    public byte[] encrypt(byte[] clearText) {
        return new byte[0];
    }

    @Override
    public String fingerprint() {
        return null;
    }

    @Override
    public BigInteger getPublicModulus() {
        return null;
    }

    @Override
    public BigInteger getPublicNqr() {
        return null;
    }

    @Override
    public boolean verify(String string, String signature) {
        return false;
    }

    @Override
    public byte[] decrypt(byte[] encryptedText) {
        return new byte[0];
    }

    @Override
    public String sign(String toSign) {
        return null;
    }

    TMCGPublicKey makePublicKey(TMCGSecretKey secretKey) {
        return new TMCGPublicKey(secretKey);
    }
}
