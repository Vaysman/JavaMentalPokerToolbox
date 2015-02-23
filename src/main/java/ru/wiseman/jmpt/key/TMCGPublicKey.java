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

    private TMCGPublicKey(BigInteger m, BigInteger y) {
        this.m = m;
        this.y = y;
    }

    public TMCGPublicKey(SecretKey secretKey) {
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


    private static String returnIfNotEmpty(String[] tokens, int index, String name, String sringifiedKey) throws InvalidStringifiedKey {
        if (index >= tokens.length) {
            throw new IndexOutOfBoundsException("max index " + (tokens.length - 1) + " got " + index);
        }

        if (tokens[index].isEmpty()) {
            throw new InvalidStringifiedKey(name + " is empty. parsed string is " + sringifiedKey);
        }
        return tokens[index];
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
