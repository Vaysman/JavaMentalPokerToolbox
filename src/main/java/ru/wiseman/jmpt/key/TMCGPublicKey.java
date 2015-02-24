package ru.wiseman.jmpt.key;

import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;
import ru.wiseman.jmpt.SchindelhauerTMCG;

import java.math.BigInteger;
import java.util.StringTokenizer;

public class TMCGPublicKey implements PublicKey {
    private BigInteger m;
    private BigInteger y;
    private String name;
    private String email;
    private String type;
    private String nizk;
    private String sig;

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
        if(sig != null && sig.isEmpty()) {
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
        if(st.hasMoreTokens()) {
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

        if(selfId.equals("ERROR")) {
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
    public String encrypt(String clearText) {
        return null;
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
    public boolean verify(String string, String signature) {
        return false;
    }
}
