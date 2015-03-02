package ru.wiseman.jmpt.key;

import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;
import ru.wiseman.jmpt.Consts;
import ru.wiseman.jmpt.ImportException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.StringTokenizer;

public class TMCGSecretKey implements SecretKey {
    private String email;
    private BigInteger gcdext_up;
    private BigInteger gcdext_vq;
    private BigInteger m;
    // non-persistent members
    private BigInteger m1pq;
    private String name;
    private String nizk;
    private BigInteger p;
    private BigInteger pa1d4;
    private volatile TMCGPublicKey publicKey;
    private BigInteger q;
    private BigInteger qa1d4;
    private Random random;
    private String sig;
    private String type;
    private BigInteger y;

    public TMCGSecretKey(String name, String email, int keySize, boolean appendNizkProf, TMCGPublicKey publicKey) {
        this();
        this.name = name;
        this.email = email;
        this.publicKey = publicKey;

        generate(keySize, appendNizkProf);
    }

    public TMCGSecretKey() {
        random = new SecureRandom();
    }

    public TMCGSecretKey(String name, String email, int keySize) {
        this(name, email, keySize, false, null);
    }

    public TMCGSecretKey(String name, String email, int keySize, boolean appendNizkProf) {
        this(name, email, keySize, appendNizkProf, null);
    }

    public static TMCGSecretKey importKey(String key) {
        TMCGSecretKey secretKey = new TMCGSecretKey();
        String tokens[] = key.split("\\|");
        String errorMessage = "Unknown error";

        try {
            // check magic
            errorMessage = "Wrong magic";
            if (!tokens[0].equals("sec")) {
                throw new ImportException(errorMessage);
            }

            // name
            errorMessage = "Can't read name";
            secretKey.name = tokens[1];

            // email
            errorMessage = "Can't read email";
            secretKey.email = tokens[2];

            // type
            errorMessage = "Can't read type";
            secretKey.type = tokens[3];

            try {
                // m
                errorMessage = "Can't read modulus";
                secretKey.m = new BigInteger(tokens[4], Consts.TMCG_MPZ_IO_BASE);

                // y
                errorMessage = "Can't read y";
                secretKey.y = new BigInteger(tokens[5], Consts.TMCG_MPZ_IO_BASE);

                // p
                errorMessage = "Can't read p";
                secretKey.p = new BigInteger(tokens[6], Consts.TMCG_MPZ_IO_BASE);

                // q
                errorMessage = "Can't read q";
                secretKey.q = new BigInteger(tokens[7], Consts.TMCG_MPZ_IO_BASE);
            } catch (NumberFormatException ex) {
                throw new ImportException(errorMessage, ex);
            }

            // NIZK
            errorMessage = "Can't read nizk";
            if ((secretKey.nizk = tokens[8]).isEmpty()) {
                throw new ImportException("NIZK proof can't be empty");
            }

            // sig
            errorMessage = "Can't read signature";
            secretKey.sig = String.join("|", Arrays.copyOfRange(tokens, 9, tokens.length)) + "|";
            if (secretKey.sig.length() < 10) {
                throw new ImportException("Signature can't be empty");
            }
        } catch (NoSuchElementException ex) {
            throw new ImportException(errorMessage, ex);
        }

        // pre-compute non-persistent values
        secretKey.precompute();

        return secretKey;
    }

    @Override
    public boolean check() {
        return getPublicKey().check();
    }

    @Override
    public byte[] decrypt(byte[] encryptedText) {
        return decrypt(new String(encryptedText));
    }

    public byte[] decrypt(String s) {
        BigInteger vdata, vroot[];
        int rabin_s2 = 2 * Consts.TMCG_SAEP_S0;
        int rabin_s1 = (m.bitLength() / 8) - rabin_s2;

        assert rabin_s2 < m.bitLength() / 16;
        assert rabin_s2 < rabin_s1;
        assert Consts.TMCG_SAEP_S0 < m.bitLength() / 32;

        byte[] r = new byte[rabin_s1];
        byte[] mt = new byte[rabin_s2];
        byte[] g12;

        // FIXME replace StringTokenizer
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
        if (!(st.hasMoreTokens() && (vdata = new BigInteger(st.nextToken(), Consts.TMCG_MPZ_IO_BASE)) != null)) {
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
                Utils.skipSignByte(buff);
                if (buff.read(mt, 0, rabin_s2) < rabin_s2) {
                    throw new DecryptException("Not enough byte for message");
                }
                if (buff.read(r, 0, rabin_s1) < rabin_s1) {
                    throw new DecryptException("Not enough byte for gamma");
                }
                g12 = Utils.g(r, rabin_s2);
                for (int j = 0; j < rabin_s2; j++) {
                    mt[j] ^= g12[j];
                }
                if (isAllMatch(Arrays.copyOfRange(mt, Consts.TMCG_SAEP_S0, Consts.TMCG_SAEP_S0 * 2), (byte) 0)) {
                    return Arrays.copyOf(mt, Consts.TMCG_SAEP_S0);
                }
            }
        }
        throw new DecryptException("Can't decrypt");
    }

    @Override
    public String encrypt(String clearText) {
        return getPublicKey().encrypt(clearText);
    }

    @Override
    public String fingerprint() {
        return getPublicKey().fingerprint();
    }

    @Override
    public String getEmail() {
        return email;
    }

    @Override
    public BigInteger getModulus() {
        return m;
    }

    @Override
    public String getName() {
        return name;
    }

    public String getNizk() {
        return nizk;
    }

    public String getSig() {
        return sig;
    }

    @Override
    public String getType() {
        return type;
    }

    @Override
    public BigInteger getY() {
        return y;
    }

    @Override
    public String keyId(int size) {
        return getPublicKey().keyId(size);
    }

    @Override
    public String keyId() {
        return keyId(Consts.TMCG_KEYID_SIZE);
    }

    @Override
    public String sign(String toSign) {
        final int mnsize = m.bitLength() / 8;
        BigInteger foo, foo_sqrt[];
        byte[] data = toSign.getBytes();

        assert m.bitLength() % 8 > 0;
        assert mnsize > Consts.RMD160_HASH_SIZE + Consts.TMCG_PRAB_K0;

        // WARNING: This is only a probabilistic algorithm (Rabin's signature scheme),
        // however, it should work with only a few iterations. Additionally the scheme
        // PRab from [Bellare, Rogaway: The Exact Security of Digital Signatures]
        // was implemented to increase the security.
        do {
            byte[] r = new byte[Consts.TMCG_PRAB_K0];
            random.nextBytes(r);
            ByteArrayOutputStream buff = new ByteArrayOutputStream();
            try {
                buff.write(data);
                buff.write(r);
                byte[] w = Utils.h(buff.toByteArray());
                byte[] g12 = Utils.g(w, mnsize - Consts.RMD160_HASH_SIZE);
                for (int i = 0; i < Consts.TMCG_PRAB_K0; i++) {
                    r[i] ^= g12[i];
                }
                buff.reset();
                buff.write(w);
                buff.write(r);
                for (int i = 0; i < mnsize - Consts.RMD160_HASH_SIZE - Consts.TMCG_PRAB_K0; i++) {
                    buff.write(g12[Consts.TMCG_PRAB_K0 + i]);
                }
                foo = Utils.mpzImport(buff.toByteArray());
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }


        } while (!Utils.mpz_qrmn_p(foo, p, q, m));
        foo_sqrt = Utils.mpz_sqrtmn_fast_all(foo, p, q, m, gcdext_up, gcdext_vq, pa1d4, qa1d4);
        return "sig|" +
                keyId() + "|" +
                foo_sqrt[random.nextInt(4)].toString(Consts.TMCG_MPZ_IO_BASE) + "|";
    }

    @Override
    public String toString() {
        return "sec|" + name + "|" + email + "|" + type + "|" + m.toString(Consts.TMCG_MPZ_IO_BASE) +
                "|" + y.toString(Consts.TMCG_MPZ_IO_BASE) + "|" + p.toString(Consts.TMCG_MPZ_IO_BASE) +
                "|" + q.toString(Consts.TMCG_MPZ_IO_BASE) + "|" + nizk +
                "|" + sig;
    }

    @Override
    public boolean verify(String data, String signature) {
        return getPublicKey().verify(data, signature);
    }

    private void generate(int keySize, boolean appendNizkProf) {
        BigInteger foo, bar;
        final int size = (keySize / 2) + 1;

        type = "TMCG/RABIN_" + keySize + (appendNizkProf ? "_NIZK" : "");
        do {
            // choose a random safe prime p, but with fixed size (n/2 + 1) bit
            p = Utils.mpz_sprime3mod4(size, Consts.TMCG_MR_ITERATIONS);
            assert !p.mod(BIG_INTEGER_8).equals(BigInteger.ONE);

            // choose a random safe prime q, but with fixed size (n/2 + 1) bit
            // and p \not\equiv q (mod 8)
            foo = BIG_INTEGER_8;
            do {
                q = Utils.mpz_sprime3mod4(size, Consts.TMCG_MR_ITERATIONS);
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
        StringBuilder nizk2 = new StringBuilder("nzk^" + Consts.TMCG_KEY_NIZK_STAGE1 + "^");
        PRNGenerator generator = new PRNGenerator(m, y);

        // STAGE1: m Square Free
        // soundness error probability \le d^{-TMCG_KEY_NIZK_STAGE1}
        for (int stage1 = 0; stage1 < Consts.TMCG_KEY_NIZK_STAGE1 && appendNizkProf; stage1++) {
            foo = generator.nextCoprime();
            // compute bar = foo^{m^{-1} mod \phi(m)} mod m
            bar = foo.modPow(m1pq, m);
            // update NIZK-proof stream
            nizk2.append(bar.toString(Consts.TMCG_MPZ_IO_BASE)).append("^");
        }

        // STAGE2: m Prime Power Product
        // soundness error probability \le 2^{-TMCG_KEY_NIZK_STAGE2}
        nizk2.append(Consts.TMCG_KEY_NIZK_STAGE2 + "^");
        for (int stage2 = 0; (stage2 < Consts.TMCG_KEY_NIZK_STAGE2) && appendNizkProf; stage2++) {
            foo = generator.nextCoprime();

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
                            // FIXME: this is a rare but a bad case
                            bar = BigInteger.ZERO;
                        }
                    }
                }
            }
            // update NIZK-proof stream
            nizk2.append(bar.toString(Consts.TMCG_MPZ_IO_BASE)).append("^");
        }

        // STAGE3: y \in NQR^\circ_m
        // soundness error probability \le 2^{-TMCG_KEY_NIZK_STAGE3}
        nizk2.append(Consts.TMCG_KEY_NIZK_STAGE3 + "^");
        for (int stage3 = 0; (stage3 < Consts.TMCG_KEY_NIZK_STAGE2) && appendNizkProf; stage3++) {
            // common random number foo \in Z^\circ_m (build from hash function g)
            foo = generator.nextNQR();
            // compute square root
            if (!Utils.mpz_qrmn_p(foo, p, q, m)) {
                foo = foo.multiply(y).mod(m);
            }
            bar = Utils.mpz_sqrtmn_r(foo, p, q);
            nizk2.append(bar.toString(Consts.TMCG_MPZ_IO_BASE)).append("^");
        }

        nizk = nizk2.toString();
        // compute self-signature
        String data;
        String repl;
        data = name + "|" + email + "|" + type + "|" + m.toString(Consts.TMCG_MPZ_IO_BASE) + "|" +
                y.toString(Consts.TMCG_MPZ_IO_BASE) + "|" + nizk + "|";
        sig = sign(data);
        // FIXME: signature change update public key
        publicKey.setSignature(sig);

        repl = "ID" + Consts.TMCG_KEYID_SIZE + "^";
        int index = sig.indexOf(repl);
        int replsize = repl.length() + Consts.TMCG_KEYID_SIZE;
        sig = sig.substring(0, index) + keyId() + sig.substring(index + replsize, sig.length());
        // FIXME: signature change update public key
        publicKey.setSignature(sig);
    }

    private TMCGPublicKey getPublicKey() {
        TMCGPublicKey localPublicKey = publicKey;
        if (localPublicKey == null) {
            synchronized (TMCGSecretKey.class) {
                localPublicKey = publicKey;
                if (localPublicKey == null) {
                    publicKey = localPublicKey = new TMCGPublicKey(this);
                }
            }
        }

        return localPublicKey;
    }

    private boolean isAllMatch(final byte[] a, final byte value) {
        for (byte e : a) {
            if (e != value) {
                return false;
            }
        }

        return true;
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
