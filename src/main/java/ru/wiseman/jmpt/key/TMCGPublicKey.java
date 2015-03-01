package ru.wiseman.jmpt.key;

import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;
import ru.wiseman.jmpt.SchindelhauerTMCG;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.StringTokenizer;

public class TMCGPublicKey implements PublicKey {
    private BigInteger m;
    private BigInteger y;
    private String name;
    private String email;
    private String type;
    private String nizk;
    private String sig;
    private Random random;

    public TMCGPublicKey(TMCGSecretKey secretKey) {
        this();
        name = secretKey.getName();
        email = secretKey.getEmail();
        type = secretKey.getType();
        nizk = secretKey.getNizk();
        sig = secretKey.getSig();
        m = secretKey.getModulus();
        y = secretKey.getY();
    }

    public TMCGPublicKey() {
        random = new SecureRandom();
    }

    public static TMCGPublicKey importKey(String key) {
        TMCGPublicKey publicKey = new TMCGPublicKey();
        StringTokenizer st = new StringTokenizer(key, "|", false);

        // check magic
        if (!(st.hasMoreElements() && st.nextToken().equals("pub"))) {
            throw new ImportKeyException("Wrong magic");
        }

        // name
        if (!(st.hasMoreTokens() && (publicKey.name = st.nextToken()) != null)) {
            throw new ImportKeyException("Can't read name");
        }

        // email
        if (!(st.hasMoreTokens() && (publicKey.email = st.nextToken()) != null)) {
            throw new ImportKeyException("Can't read email");
        }

        // type
        if (!(st.hasMoreTokens() && (publicKey.type = st.nextToken()) != null)) {
            throw new ImportKeyException("Can't read type");
        }

        // m
        if (!(st.hasMoreTokens() && (publicKey.m = new BigInteger(st.nextToken(), SchindelhauerTMCG.TMCG_MPZ_IO_BASE)) != null)) {
            throw new ImportKeyException("Can't read modulus");
        }

        // y
        if (!(st.hasMoreTokens() && (publicKey.y = new BigInteger(st.nextToken(), SchindelhauerTMCG.TMCG_MPZ_IO_BASE)) != null)) {
            throw new ImportKeyException("Can't read y");
        }

        // NIZK
        if (!(st.hasMoreTokens() && (publicKey.nizk = st.nextToken()) != null)) {
            throw new ImportKeyException("Can't read nzik");
        }

        // sig
        if (!(st.hasMoreTokens() && (publicKey.sig = st.nextToken("\n").substring(1)) != null)) {
            throw new ImportKeyException("Can't read signature");
        }

        return publicKey;
    }

    public String selfId() {
        // maybe a self signature
        if (sig == null || sig.isEmpty()) {
            return "SELFSIG-SELFSIG-SELFSIG-SELFSIG-SELFSIG-SELFSIG";
        }

        StringTokenizer st = new StringTokenizer(sig, "|", false);

        // check magic
        if (!(st.hasMoreTokens() && st.nextToken().equals("sig"))) {
            return "ERROR";
        }

        // skip the keyID
        if (!(st.hasMoreTokens() && st.nextToken() != null)) {
            return "ERROR";
        }

        // get the sigID
        if (st.hasMoreTokens()) {
            return st.nextToken();
        }

        return "ERROR";
    }

    @Override
    public String keyId() {
        return keyId(SchindelhauerTMCG.TMCG_KEYID_SIZE);
    }

    @Override
    public String keyId(int size) {
        String selfId = selfId();

        if (selfId.equals("ERROR")) {
            return selfId;
        }

        int idBeginIndex = selfId.length() - Math.min(size, selfId.length());
        return "ID" + size + "^" + selfId.substring(idBeginIndex);
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

    @Override
    public BigInteger getModulus() {
        return m;
    }

    @Override
    public BigInteger getY() {
        return y;
    }

    @Override
    public boolean check() {
        BigInteger foo, bar;
        String s = nizk;
        int stage1_size = 0, stage2_size = 0, stage3_size = 0;
        int mnsize = m.bitLength() / 8;

        // sanity check, whether y \in Z^\circ
        if (IntegerFunctions.jacobi(y, m) != 1) {
            return false;
        }

        // sanity check, whether m \in ODD (odd numbers)
        if (!m.testBit(0)) {
            return false;
        }

        // sanity check, whether m \not\in P (prime)
        // (here is a very small probability of false-negative behaviour,
        // FIXME: give a short witness in public key)
        if (m.isProbablePrime(500)) {
            return false;
        }

        // check self-signature
        String data = name + "|" + email + "|" + type + "|" +
                m.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) + "|" +
                y.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) + "|" + nizk + "|";

        if (!verify(data, sig)) {
            return false;
        }

        // check, whether m \not\in FP (fermat primes: m = 2^k + 1)
        foo = m.subtract(BigInteger.ONE);

        // FIXME: is m correct here? (not foo)
        int k = foo.bitLength();
        bar = BIG_INTEGER_2.pow(k);
        if (foo.equals(bar)) {
            // check, whether k is power of two
            foo = BigInteger.valueOf(k);
            int l = foo.bitLength();
            bar = BIG_INTEGER_2.pow(l);
            if (foo.equals(bar)) {
                // check, whether m is not equal to 5L
                if (m.equals(BIG_INTEGER_5)) {
                    return false;
                }
                // check, whether 5^{2^(k/2)} \equiv -1 (mod m) [Pepin's prime test]
                foo = BIG_INTEGER_2.pow(k / 2).mod(m);
                foo = BIG_INTEGER_5.modPow(foo, m);
                bar = BigInteger.ONE.negate();
                if (Utils.isCoungruent(foo, bar, m)) {
                    return false;
                }
            }
        }

        // abort, if non-NIZK key
        if (!type.contains("NIZK")) {
            return true;
        }

        StringTokenizer st = new StringTokenizer(s, "^", false);

        try {
            // check magic of NIZK
            if (!st.nextToken().equals("nzk")) {
                return false;
            }

            // initialize NIZK proof input
            PRNGenerator generator = new PRNGenerator(m, y);

            // get security parameter of STAGE1
            if ((stage1_size = Integer.parseInt(st.nextToken())) < SchindelhauerTMCG.TMCG_KEY_NIZK_STAGE1) {
                return false;
            }

            // STAGE1: m is Square Free
            for (int i = 0; i < stage1_size; i++) {
                foo = generator.nextCoprime();

                // read NIZK proof
                if ((bar = new BigInteger(st.nextToken(), SchindelhauerTMCG.TMCG_MPZ_IO_BASE)) == null) {
                    return false;
                }

                // check, whether bar^m mod m is equal to foo
                bar = bar.modPow(m, m);
                if (!bar.equals(foo)) {
                    return false;
                }
            }

            // get security parameter of STAGE2
            // check security constraint of STAGE2
            if ((stage2_size = Integer.parseInt(st.nextToken())) < SchindelhauerTMCG.TMCG_KEY_NIZK_STAGE2) {
                return false;
            }

            // STAGE2: m is Prime Power Product
            for (int i = 0; i < stage2_size; i++) {
                foo = generator.nextCoprime();

                // read NIZK proof
                if ((bar = new BigInteger(st.nextToken(), SchindelhauerTMCG.TMCG_MPZ_IO_BASE)) == null) {
                    return false;
                }

                // check, whether bar^2 \equiv +-foo or \equiv +-2foo (mod m)
                bar = bar.pow(2).mod(m);
                // FIXME: this is a rare but a bad case
                if(!bar.equals(BigInteger.ZERO)) {
                    if (Utils.isNotCoungruent(bar, foo, m)) {
                        foo = foo.negate();
                        if (Utils.isNotCoungruent(bar, foo, m)) {
                            foo = foo.shiftLeft(1);
                            if (Utils.isNotCoungruent(bar, foo, m)) {
                                foo = foo.negate();
                                if (Utils.isNotCoungruent(bar, foo, m))
                                    return false;
                            }
                        }
                    }
                }
            }

            // get security parameter of STAGE3
            // check security constraint of STAGE3
            if ((stage3_size = Integer.parseInt(st.nextToken())) < SchindelhauerTMCG.TMCG_KEY_NIZK_STAGE3) {
                return false;
            }

            // STAGE3: y \in NQR^\circ_m
            for (int i = 0; i < stage3_size; i++) {
                foo = generator.nextNQR();

                // read NIZK proof
                if ((bar = new BigInteger(st.nextToken(), SchindelhauerTMCG.TMCG_MPZ_IO_BASE)) == null) {
                    return false;
                }

                // check congruence [Goldwasser-Micali NIZK proof for NQR]
                bar = bar.pow(2).mod(m);
                if (Utils.isNotCoungruent(bar, foo, m)) {
                    foo = foo.multiply(y).mod(m);
                    if (Utils.isNotCoungruent(bar, foo, m)) {
                        return false;
                    }
                }
            }
        } catch (NoSuchElementException ex) {
            return false;
        }

        // finish
        return true;
    }

    @Override
    public String encrypt(String value) {
        BigInteger vdata;

        int rabin_s2 = 2 * SchindelhauerTMCG.TMCG_SAEP_S0;
        int rabin_s1 = (m.bitLength() / 8) - rabin_s2;

        assert (rabin_s2 < (m.bitLength() / 16));
        assert (rabin_s2 < rabin_s1);
        assert (SchindelhauerTMCG.TMCG_SAEP_S0 < (m.bitLength() / 32));

        byte[] r = new byte[rabin_s1];
        random.nextBytes(r);

        byte[] mt = new byte[rabin_s2];
        int length = Math.min(value.getBytes().length, SchindelhauerTMCG.TMCG_SAEP_S0);
        System.arraycopy(value.getBytes(), 0, mt, 0, length);
        byte[] g12 = Utils.g(r, rabin_s2);
        for (int i = 0; i < rabin_s2; i++) {
            mt[i] ^= g12[i];
        }

        ByteArrayOutputStream buff = new ByteArrayOutputStream();
        try {
            buff.write(mt);
            buff.write(r);
        } catch (IOException e) {
            throw new EncryptingException();
        }
        vdata = Utils.mpzImport(buff.toByteArray());
        vdata = vdata.pow(2).mod(m);
        return "enc|" + keyId() + "|" + vdata.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) + "|";
    }

    @Override
    public String fingerprint() {
        int hash_size = SchindelhauerTMCG.RMD160_HASH_SIZE;

        // compute the digest
        String data = "pub|" + name + "|" + email + "|" + type +
                "|" + m.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) +
                "|" + y.toString(SchindelhauerTMCG.TMCG_MPZ_IO_BASE) +
                "|" + nizk + "|" + sig;
        byte[] digest = Utils.h(data);

        // convert the digest to a hexadecimal encoded string
        StringBuilder fingerprint = new StringBuilder();
        for (int i = 0; i < (hash_size / 2); i++) {
            fingerprint.append(String.format("%02X%02X ", digest[2 * i], digest[(2 * i) + 1]));
        }

        return fingerprint.toString();
    }

    @Override
    public boolean verify(String data, String s) {
        BigInteger foo;

        StringTokenizer st = new StringTokenizer(s, "|", false);

        // check magic
        if (!(st.hasMoreElements() && st.nextToken().equals("sig"))) {
            throw new SignatureException("Wrong magic");
        }

        // check keyID
        String kid = null;
        if (!(st.hasMoreTokens() && (kid = st.nextToken()) != null && kid.equals(keyId(keyIdSize(kid))))) {
            throw new DecryptException("Wrong key id. Expected " + keyId(keyIdSize(kid)) + ", found " + kid);
        }

        // value
        if (!(st.hasMoreTokens() && (foo = new BigInteger(st.nextToken(), SchindelhauerTMCG.TMCG_MPZ_IO_BASE)) != null)) {
            throw new ImportKeyException("Can't read signature");
        }

        // verify signature
        int mdsize = SchindelhauerTMCG.RMD160_HASH_SIZE;
        int mnsize = m.bitLength() / 8;

        assert m.bitLength() > mnsize * 8;
        assert mnsize > mdsize + SchindelhauerTMCG.TMCG_PRAB_K0;

        foo = foo.pow(2).mod(m);
        byte[] w = new byte[mdsize], r = new byte[SchindelhauerTMCG.TMCG_PRAB_K0];
        byte[] gamma = new byte[mnsize - mdsize - SchindelhauerTMCG.TMCG_PRAB_K0];
        ByteArrayInputStream buff = new ByteArrayInputStream(foo.toByteArray());
        Utils.skipSignByte(buff);
        try {
            buff.read(w);
            buff.read(r);
            buff.read(gamma);
        } catch (IOException e) {
            return false;
        }
        byte[] g12 = Utils.g(w, mnsize - mdsize);
        for (int i = 0; i < SchindelhauerTMCG.TMCG_PRAB_K0; i++) {
            r[i] ^= g12[i];
        }
        ByteArrayOutputStream mr = new ByteArrayOutputStream();
        try {
            mr.write(data.getBytes());
            mr.write(r);
        } catch (IOException e) {
            return false;
        }
        byte[] w2 = Utils.h(mr.toByteArray());
        if (Arrays.equals(w, w2) && Arrays.equals(gamma, Arrays.copyOfRange(g12, SchindelhauerTMCG.TMCG_PRAB_K0, g12.length))) {
            return true;
        }

        return false;
    }

    private int keyIdSize(String s) {
        int size;
        // check the format
        if ((s.length() < 4) || !s.startsWith("ID") || !s.contains("^")) {
            return 0;
        }

        // extract the size
        try {
            int indexOfCircumflex = s.indexOf('^');
            size = Integer.parseInt(s.substring(2, indexOfCircumflex));
            if (size != s.length() - indexOfCircumflex - 1) {
                return 0;
            }
        } catch (NumberFormatException ex) {
            return 0;
        }

        return size;
    }
}
