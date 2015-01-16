package ru.wiseman.jmpt.key;

import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;

import java.math.BigInteger;

public class TMCGPublicKey implements PublicKey {
    private BigInteger m;
    private BigInteger y;
    private String name;
    private String email;
    private String type;

    private TMCGPublicKey(BigInteger m, BigInteger y) {
        this.m = m;
        this.y = y;
    }

    public TMCGPublicKey(SecretKey secretKey) {
    }

    public static TMCGPublicKey importKey(String stringifiedKey) throws InvalidStringifiedKey {
        String[] parts = stringifiedKey.split("\\|");

        if (!"pub".equals(parts[0])) {
            throw new InvalidStringifiedKey("expected \"pub\" got \"" + parts[1] + "\"" + " " + stringifiedKey);
        }

        String name = returnIfNotEmpty(parts, 1, "name", stringifiedKey);

        String email = returnIfNotEmpty(parts, 2, "email", stringifiedKey);

        String type = returnIfNotEmpty(parts, 3, "type", stringifiedKey);

        String mString = returnIfNotEmpty(parts, 4, "module", stringifiedKey);

        String yString = returnIfNotEmpty(parts, 5, "y", stringifiedKey);

        String nizk = returnIfNotEmpty(parts, 6, "nizk", stringifiedKey);

        // signature

/*

        // sig
        sig = s;

        throw true;

  */
        BigInteger m = new BigInteger(mString, 36);
        BigInteger y = new BigInteger(yString, 36);

        return new TMCGPublicKey(m, y);
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
}
