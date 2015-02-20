package ru.wiseman.jmpt.key;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.BigIntUtils;
import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;

public class Utils {
    public static final BigInteger FOUR = BigInteger.valueOf(4L);
    public static final BigInteger THREE = BigInteger.valueOf(3);
    public static final BigInteger ONE = BigInteger.ONE;
    public static final BigInteger EIGHT = BigInteger.valueOf(8);
    public static final BigInteger FIVE = BigInteger.valueOf(5);
    private static Random random = new SecureRandom();

    public static byte[] h(String s) {
        return h(s.getBytes());
    }

    public static byte[] h(byte[] data) {
        setBcProvider();
        byte[] result;
        try {
            MessageDigest md = MessageDigest.getInstance("RIPEMD160");
            md.update(data);
            result = md.digest();
        } catch (NoSuchAlgorithmException e) {
            result = new byte[0];
        }
        return result;
    }

    private static void setBcProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
    
    public static byte[] g(String s, int osize) {
        return g(s.getBytes(), osize);
    }

    public static byte[] g(final byte[] s, int osize) {
        setBcProvider();
        int mdsize = 20;
        int usesize = mdsize / 4;
        byte[] output = new byte[osize];
        final byte[] padding = "libTMCG".getBytes();

        int times = (osize / usesize) + 1;
        byte[] out = new byte[times * mdsize];
        ByteArrayOutputStream data1 = new ByteArrayOutputStream();
        for (int i = 0; i < times; i++) {
            data1.reset();
            try {
                data1.write(s);
                data1.write(padding);
                // reproduce of bug in libTMCG
                data1.write((String.format("%02x", i).substring(0, 1)).getBytes());
                data1.write(0);
                // end
                data1.write(s);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            byte[] t = Utils.h(data1.toByteArray());
            System.arraycopy(t, 0, out, i * usesize, usesize);
        }
        System.arraycopy(out, 0, output, 0, osize);
        return output;
    }


    public static boolean mpz_qrmn_p(BigInteger foo, BigInteger p, BigInteger q, BigInteger m) {
        return IntegerFunctions.jacobi(foo, p) == 1 && IntegerFunctions.jacobi(foo, q) == 1;
    }

    public static BigInteger mpzImport(byte[] data) {
        return new BigInteger(1, data);
    }

    public static BigInteger mpz_sqrtmn_r(BigInteger a, BigInteger p, BigInteger q) {
        BigInteger[] gcd_ext = IntegerFunctions.extgcd(p, q);
        BigInteger g = gcd_ext[0];
        BigInteger u = gcd_ext[1];
        BigInteger v = gcd_ext[2];
        BigInteger n = p.multiply(q);


        if(g.equals(ONE)) {
            // single square roots
            BigInteger root_p = IntegerFunctions.ressol(a, p);
            BigInteger root_q = IntegerFunctions.ressol(a, q);
            // construct common square root
            BigInteger root1 = root_q;
            BigInteger root2 = root_p;
            BigInteger root3 = root_q;
            BigInteger root4 = root_p;
            root1 = root1.multiply(u).multiply(p);
            root2 = root2.multiply(v).multiply(q);
            root1 = root1.add(root2).mod(n);
            root2 = n.subtract(root1);
            root3 = root3.negate().multiply(u).multiply(p);
            root4 = root4.multiply(v).multiply(q);
            root3 = root3.add(root4).mod(n);
            root4 = n.subtract(root3);
            // choose smallest root
            return root1.min(root2).min(root3).min(root4);
        } else {
            // error, return zero root
            return BigInteger.ZERO;
        }
    }

    // prime congruent 3 modulo 4
    public static BigInteger mpz_sprime3mod4(int size, int iterations) {
        BigInteger result;
        do {
            result = BigInteger.probablePrime(size, random);
        } while (!result.mod(FOUR).equals(THREE));

        return result;
    }
}
