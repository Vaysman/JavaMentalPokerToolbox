package ru.wiseman.jmpt.key;

import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;
import ru.wiseman.jmpt.SchindelhauerTMCG;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.StringTokenizer;

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
    private BigInteger m1pq;
    private BigInteger gcdext_up;
    private BigInteger gcdext_vq;
    private BigInteger pa1d4;
    private BigInteger qa1d4;
    private Random random;

    public TMCGSecretKey(String name, String email, int keySize, boolean appendNizkProf) {
        this();
        this.name = name;
        this.email = email;

        generate(keySize, appendNizkProf);
    }

    public TMCGSecretKey(String name, String email, int keySize, boolean appendNizkProf, BigInteger p, BigInteger q) {
        this();
        this.name = name;
        this.email = email;
        this.q = q;
        this.p = p;
        generate(keySize, appendNizkProf, true);
    }

    public TMCGSecretKey() {
        random = new SecureRandom();
    }

    public static TMCGSecretKey importKey(String key) {
        TMCGSecretKey secretKey = new TMCGSecretKey();
        StringTokenizer st = new StringTokenizer(key, "|", false);

        // check magic
        if (!(st.hasMoreElements() && st.nextToken().equals("sec"))) {
            throw new ImportKeyException("Wrong magic");
        }

        // name
        if (!(st.hasMoreTokens() && (secretKey.name = st.nextToken()) != null)) {
            throw new ImportKeyException("Can't read name");
        }

        // email
        if (!(st.hasMoreTokens() && (secretKey.email = st.nextToken()) != null)) {
            throw new ImportKeyException("Can't read email");
        }

        // type
        if (!(st.hasMoreTokens() && (secretKey.type = st.nextToken()) != null)) {
            throw new ImportKeyException("Can't read type");
        }

        // m
        if (!(st.hasMoreTokens() && (secretKey.m = new BigInteger(st.nextToken(), SchindelhauerTMCG.TMCG_MPZ_IO_BASE)) != null)) {
            throw new ImportKeyException("Can't read modulus");
        }

        // y
        if (!(st.hasMoreTokens() && (secretKey.y = new BigInteger(st.nextToken(), SchindelhauerTMCG.TMCG_MPZ_IO_BASE)) != null)) {
            throw new ImportKeyException("Can't read y");
        }

        // p
        if (!(st.hasMoreTokens() && (secretKey.p = new BigInteger(st.nextToken(), SchindelhauerTMCG.TMCG_MPZ_IO_BASE)) != null)) {
            throw new ImportKeyException("Can't read p");
        }

        // q
        if (!(st.hasMoreTokens() && (secretKey.q = new BigInteger(st.nextToken(), SchindelhauerTMCG.TMCG_MPZ_IO_BASE)) != null)) {
            throw new ImportKeyException("Can't read q");
        }

        // NIZK
        if (!(st.hasMoreTokens() && (secretKey.nizk = st.nextToken()) != null)) {
            throw new ImportKeyException("Can't read nzik");
        }

        // sig
        if (!(st.hasMoreTokens() && (secretKey.sig = st.nextToken("\n").substring(1)) != null)) {
            throw new ImportKeyException("Can't read signature");
        }

        // pre-compute non-persistent values
        secretKey.precompute();

        return secretKey;
    }

    @Override
    public String keyId(int size) {
        return makePublicKey(this).keyId(size);
    }

    @Override
    public boolean check() {
        return makePublicKey(this).check();
    }

    @Override
    public String encrypt(String clearText) {
        return makePublicKey(this).encrypt(clearText);
    }

    @Override
    public String fingerprint() {
        return makePublicKey(this).fingerprint();
    }

    @Override
    public boolean verify(String data, String signature) {
        return makePublicKey(this).verify(data, signature);
    }

    @Override
    public String keyId() {
        return keyId(SchindelhauerTMCG.TMCG_KEYID_SIZE);
    }

    @Override
    public byte[] decrypt(byte[] encryptedText) {
        return decrypt(new String(encryptedText));
    }

    public byte[] decrypt(String s) {
        BigInteger vdata, vroot[];
        int rabin_s2 = 2 * SchindelhauerTMCG.TMCG_SAEP_S0;
        int rabin_s1 = (m.bitLength() / 8) - rabin_s2;

        assert rabin_s2 < m.bitLength() / 16;
        assert rabin_s2 < rabin_s1;
        assert SchindelhauerTMCG.TMCG_SAEP_S0 < m.bitLength() / 32;

        byte[] r = new byte[rabin_s1];
        byte[] mt = new byte[rabin_s2];
        byte[] g12;

        StringTokenizer st = new StringTokenizer(s, "|", false);

        // check magic
        if (!(st.hasMoreElements() && st.nextToken().equals("enc"))) {
            throw new DecryptException("Wrong magic");
        }

        // check keyID
        String kid = null;
        if (!(st.hasMoreTokens() && (kid = st.nextToken()).equals(keyId()))) {
            throw new DecryptException("Wrong key id. Expected " + keyId() + ", found " + kid);
        }

        // vdata
        if (!(st.hasMoreTokens() && (vdata = new BigInteger(st.nextToken(), SchindelhauerTMCG.TMCG_MPZ_IO_BASE)) != null)) {
            throw new DecryptException("Wrong encrypted data");
        }

        // decrypt value, i.e., compute the modular square roots
        if (!Utils.mpz_qrmn_p(vdata, p, q, m)) {
            throw new DecryptException("Wrong encrypted data");
        }
        vroot = Utils.mpz_sqrtmn_fast_all(vdata, p, q, m, gcdext_up, gcdext_vq, pa1d4, qa1d4);
        for (int i = 0; i < 4; i++) {
            if (vroot[i].bitLength() / 8 <= (rabin_s1 + rabin_s2)) {
                ByteArrayInputStream buff = new ByteArrayInputStream(vroot[i].toByteArray());
                // skip sign byte
                if (buff.read() != 0) {
                    buff.reset();
                }
                buff.read(mt, 0, rabin_s2);
                buff.read(r, 0, rabin_s1);
                g12 = Utils.g(r, rabin_s2);
                for (int j = 0; j < rabin_s2; j++) {
                    mt[j] ^= g12[j];
                }
                if (isAllMatch(Arrays.copyOfRange(mt, SchindelhauerTMCG.TMCG_SAEP_S0, SchindelhauerTMCG.TMCG_SAEP_S0 * 2), (byte) 0)) {
                    return Arrays.copyOf(mt, SchindelhauerTMCG.TMCG_SAEP_S0);
                }
            }
        }
        throw new DecryptException("Can't decrypt");
    }

    @Override
    public String sign(String toSign) {
        final int mdsize = 20;
        final int mnsize = m.bitLength() / 8;
        BigInteger foo, foo_sqrt[];
        byte[] data = toSign.getBytes();

        assert m.bitLength() % 8 > 0;
        assert mnsize > mdsize + SchindelhauerTMCG.TMCG_PRAB_K0;

        // WARNING: This is only a probabilistic algorithm (Rabin's signature scheme),
        // however, it should work with only a few iterations. Additionally the scheme
        // PRab from [Bellare, Rogaway: The Exact Security of Digital Signatures]
        // was implemented to increase the security.
        do {
            byte[] r = new byte[SchindelhauerTMCG.TMCG_PRAB_K0];
            random.nextBytes(r);
            ByteArrayOutputStream buff = new ByteArrayOutputStream();
            try {
                buff.write(data);
                buff.write(r);
                byte[] w = Utils.h(buff.toByteArray());
                byte[] g12 = Utils.g(w, mnsize - mdsize);
                for (int i = 0; i < SchindelhauerTMCG.TMCG_PRAB_K0; i++) {
                    r[i] ^= g12[i];
                }
                buff.reset();
                buff.write(w);
                buff.write(r);
                for (int i = 0; i < mnsize - mdsize - SchindelhauerTMCG.TMCG_PRAB_K0; i++) {
                    buff.write(g12[SchindelhauerTMCG.TMCG_PRAB_K0 + i]);
                }
                foo = Utils.mpzImport(buff.toByteArray());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }


        } while (!Utils.mpz_qrmn_p(foo, p, q, m));
        foo_sqrt = Utils.mpz_sqrtmn_fast_all(foo, p, q, m, gcdext_up, gcdext_vq, pa1d4, qa1d4);
        StringBuilder sign = new StringBuilder();
        sign.append("sig|").
                append(keyId()).append("|").
                append(foo_sqrt[random.nextInt(4)].toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE)).append("|");
        return sign.toString();
    }

    @Override
    public String toString() {
        return "sec|" + name + "|" + email + "|" + type + "|" + m.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) +
                "|" + y.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) + "|" + p.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) +
                "|" + q.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) + "|" + nizk +
                "|" + sig;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getEmail() {
        return email;
    }

    @Override
    public String getType() {
        return type;
    }

    public String getNizk() {
        return nizk;
    }

    public String getSig() {
        return sig;
    }

    @Override
    public BigInteger getModulus() {
        return m;
    }

    @Override
    public BigInteger getY() {
        return y;
    }

    private void generate(int keySize, boolean appendNizkProf) {
        generate(keySize, appendNizkProf, false);
    }

    private void generate(int keySize, boolean appendNizkProf, boolean precomp) {
        BigInteger foo, bar;
        final int size = (keySize / 2) + 1;

        type = "TMCG/RABIN_" + keySize + (appendNizkProf ? "_NIZK" : "");
        if (!precomp) {
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
                assert (!p.mod(foo).equals(q));

                // compute modulus: m = p \cdot q
                m = p.multiply(q);

                // compute upper bound for SAEP, i.e. 2^{n+1} + 2^n
                foo = BigInteger.ONE;
                foo = foo.multiply(BIG_INTEGER_2.pow(keySize));
                bar = foo.multiply(BIG_INTEGER_2);
                bar = foo.add(bar);
            } while (m.bitLength() < keySize + 1 || m.compareTo(bar) >= 0);
        } else {
            m = p.multiply(q);
        }
        // choose a small $y \in NQR^\circ_m$ for fast TMCG encoding
        y = BigInteger.ONE;
        do {
            y = y.add(BigInteger.ONE);
        } while (IntegerFunctions.jacobi(y, m) != 1 || Utils.mpz_qrmn_p(y, p, q, m));

        // pre-compute non-persistent values
        precompute();

        // Rosario Gennaro, Daniele Micciancio, Tal Rabin:
        // 'An Efficient Non-Interactive Statistical Zero-Knowledge
        // Proof System for Quasi-Safe Prime Products',
        // 5th ACM Conference on Computer and Communication Security, CCS 1998

        // STAGE1/2: m = p^i * q^j, p and q prime
        // STAGE3: y \in NQR^\circ_m
        String input = m.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) + "^" + y.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE);
        String nizk2 = "nzk^" + SchindelhauerTMCG.TMCG_KEY_NIZK_STAGE1 + "^";
        final int mnsize = m.bitLength() / 8;

        // STAGE1: m Square Free
        // soundness error probability \le d^{-TMCG_KEY_NIZK_STAGE1}
        for (int stage1 = 0; stage1 < SchindelhauerTMCG.TMCG_KEY_NIZK_STAGE1 && appendNizkProf; stage1++) {
            // common random number foo \in Z^*_m (build from hash function g)
            do {
                byte[] mn = Utils.g(input, mnsize);
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
                byte[] mn = Utils.g(input, mnsize);
                byte[] foo_data = new byte[mnsize];
                System.arraycopy(mn, 0, foo_data, 0, mnsize);
                foo = Utils.mpzImport(foo_data);
                foo = foo.mod(m);
                bar = foo.gcd(m);
                input = input + foo.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE);
            } while (bar.compareTo(BigInteger.ONE) != 0);

            // compute square root of +-foo or +-2foo mod m
            if (Utils.mpz_qrmn_p(foo, p, q, m)) {
                bar = Utils.mpz_sqrtmn_r(foo, p, q);
            } else {
                foo = foo.negate();
                if (Utils.mpz_qrmn_p(foo, p, q, m)) {
                    bar = Utils.mpz_sqrtmn_r(foo, p, q);
                } else {
                    foo = foo.shiftLeft(1);
                    if (Utils.mpz_qrmn_p(foo, p, q, m)) {
                        bar = Utils.mpz_sqrtmn_r(foo, p, q);
                    } else {
                        foo = foo.negate();
                        if (Utils.mpz_qrmn_p(foo, p, q, m)) {
                            bar = Utils.mpz_sqrtmn_r(foo, p, q);
                        } else {
                            bar = BigInteger.ZERO;
                        }
                    }
                }
            }
            // update NIZK-proof stream
            nizk2 = nizk2 + bar.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) + "^";
        }

        // STAGE3: y \in NQR^\circ_m
        // soundness error probability \le 2^{-TMCG_KEY_NIZK_STAGE3}
        nizk2 = nizk2 + SchindelhauerTMCG.TMCG_KEY_NIZK_STAGE3 + "^";
        for (int stage3 = 0; (stage3 < SchindelhauerTMCG.TMCG_KEY_NIZK_STAGE2) && appendNizkProf; stage3++) {
            // common random number foo \in Z^\circ_m (build from hash function g)
            do {
                byte[] mn = Utils.g(input, mnsize);
                byte[] foo_data = new byte[mnsize];
                System.arraycopy(mn, 0, foo_data, 0, mnsize);
                foo = Utils.mpzImport(foo_data);
                foo = foo.mod(m);
                input = input + foo.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE);
            } while (IntegerFunctions.jacobi(foo, m) != 1);
            // compute square root
            if (!Utils.mpz_qrmn_p(foo, p, q, m)) {
                foo = foo.multiply(y).mod(m);
            }
            bar = Utils.mpz_sqrtmn_r(foo, p, q);
            nizk2 = nizk2 + bar.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) + "^";
        }

        nizk = nizk2.toString();
        // compute self-signature
        String data;
        String repl;
        data = name + "|" + email + "|" + type + "|" + m.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) + "|" +
                y.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) + "|" + nizk + "|";
        sig = sign(data);

        repl = "ID" + SchindelhauerTMCG.TMCG_KEYID_SIZE + "^";
        int index = sig.indexOf(repl);
        int replsize = repl.length() + SchindelhauerTMCG.TMCG_KEYID_SIZE;
        // FIXME make it work
        sig = sig.substring(0, index) + keyId() + sig.substring(index + replsize, sig.length());
    }

    private boolean isAllMatch(final byte[] a, final byte value) {
        for (byte e : a) {
            if (e != value) {
                return false;
            }
        }

        return true;
    }

    private TMCGPublicKey makePublicKey(TMCGSecretKey secretKey) {
        return new TMCGPublicKey(secretKey);
    }

    // pre-compute non-persistent values
    private void precompute() {
        BigInteger foo;

        foo = m.subtract(p).subtract(q).add(BigInteger.ONE);
        m1pq = m.modInverse(foo);
        BigInteger[] gcdext = IntegerFunctions.extgcd(p, q);
        assert gcdext[0].equals(BigInteger.ONE);
        gcdext_up = gcdext[1].multiply(p);
        gcdext_vq = gcdext[2].multiply(q);
        pa1d4 = p.add(BigInteger.ONE).shiftRight(2);
        qa1d4 = q.add(BigInteger.ONE).shiftRight(2);
    }
}
