package ru.wiseman.jmpt.key;

import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;
import ru.wiseman.jmpt.SchindelhauerTMCG;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
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
        if (IntegerFunctions.jacobi(y, m) != 1) {
            return false;
        }
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
        if(Arrays.equals(w, w2) && Arrays.equals(gamma, Arrays.copyOfRange(g12, SchindelhauerTMCG.TMCG_PRAB_K0, g12.length))) {
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
            if(size != s.length() - indexOfCircumflex - 1) {
                return 0;
            }
        } catch (NumberFormatException ex) {
            return 0;
        }

        return size;
    }
}
