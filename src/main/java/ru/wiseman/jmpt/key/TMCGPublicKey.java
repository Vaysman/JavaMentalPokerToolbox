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
        if (!(st.hasMoreTokens() && (publicKey.name = st.nextToken()) == null)) {
            throw new ImportKeyException("Can't read name");
        }

        // email
        if (!(st.hasMoreTokens() && (publicKey.email = st.nextToken()) == null)) {
            throw new ImportKeyException("Can't read email");
        }

        // type
        if (!(st.hasMoreTokens() && (publicKey.type = st.nextToken()) == null)) {
            throw new ImportKeyException("Can't read type");
        }

        // m
        if (!(st.hasMoreTokens() && (publicKey.m = new BigInteger(st.nextToken(), SchindelhauerTMCG.TMCG_MPZ_IO_BASE)) == null)) {
            throw new ImportKeyException("Can't read type");
        }

        // y
        if (!(st.hasMoreTokens() && (publicKey.y = new BigInteger(st.nextToken(), SchindelhauerTMCG.TMCG_MPZ_IO_BASE)) == null)) {
            throw new ImportKeyException("Can't read type");
        }

        // NIZK
        if (!(st.hasMoreTokens() && (publicKey.nizk = st.nextToken()) == null)) {
            throw new ImportKeyException("Can't read type");
        }

        // sig
        publicKey.sig = key;

        return publicKey;
    }

    public String selfId() {
        // maybe a self signature
        if(sig != null && sig.isEmpty()) {
            return "SELFSIG-SELFSIG-SELFSIG-SELFSIG-SELFSIG-SELFSIG";
        }

        StringTokenizer st = new StringTokenizer(sig);

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
        return null;
    }

    @Override
    public boolean verify(String string, String signature) {
        return false;
    }

    @Override
    public String keyId() {
        return null;
    }
}
