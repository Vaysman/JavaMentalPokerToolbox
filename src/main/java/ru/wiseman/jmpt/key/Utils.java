package ru.wiseman.jmpt.key;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class Utils {
    public static byte[] h(String s) {
        setBcProvider();
        byte[] result = null;
        try {
            MessageDigest md = MessageDigest.getInstance("RIPEMD160");
            md.update(s.getBytes());
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

    public static byte[] g(String s) {
        setBcProvider();
        int osize = 12;
        int isize = s.getBytes().length;
        int mdsize = 20;
        int usesize = mdsize / 4;
        byte[] output = new byte[osize];
        byte[] input = s.getBytes();

        int times = (osize / usesize) + 1;
        byte[] out = new byte[times * mdsize];
        for (int i = 0; i < times; i++) {
            String data = s + "libTMCG" + String.format("%02x", i).substring(0, 1) + "\0" + s;
            byte[] t = Utils.h(data);
            System.arraycopy(t, 0, out, i * usesize, usesize);
        }
        System.arraycopy(out, 0, output, 0, osize);
        return output;
    }

    public static BigInteger sqrtMod(BigInteger p, BigInteger q) {
        BigInteger g, u, v;
        BigInteger[] bezoutCoefficient = gcdExt(p, q);
/*
        mpz_t g, u, v;
	mpz_init(g), mpz_init(u), mpz_init(v);
	mpz_gcdext(g, u, v, p, q);
	if (mpz_cmp_ui(g, 1L) == 0)
	{
		mpz_t root_p, root_q, root1, root2, root3, root4;
		// single square roots
        mpz_init(root_p), mpz_init(root_q);
        mpz_sqrtmp_r(root_p, a, p);
        mpz_sqrtmp_r(root_q, a, q);
		// construct common square root
        mpz_init_set(root1, root_q);
        mpz_init_set(root2, root_p);
        mpz_init_set(root3, root_q);
        mpz_init_set(root4, root_p);
        mpz_mul(root1, root1, u);
        mpz_mul(root1, root1, p);
        mpz_mul(root2, root2, v);
        mpz_mul(root2, root2, q);
        mpz_add(root1, root1, root2);
        mpz_mod(root1, root1, n);
        mpz_sqrtmn_2(root2, root1, n);
        mpz_neg(root3, root3);
        mpz_mul(root3, root3, u);
        mpz_mul(root3, root3, p);
        mpz_mul(root4, root4, v);
        mpz_mul(root4, root4, q);
        mpz_add(root3, root3, root4);
        mpz_mod(root3, root3, n);
        mpz_sqrtmn_2 (root4, root3, n);
		// choose smallest root
        mpz_set(root, root1);
        if (mpz_cmpabs(root2, root) < 0)
            mpz_set(root, root2);
        if (mpz_cmpabs(root3, root) < 0)
            mpz_set(root, root3);
        if (mpz_cmpabs(root4, root) < 0)
            mpz_set(root, root4);
        mpz_clear(root_p), mpz_clear(root_q);
        mpz_clear(root1), mpz_clear(root2);
        mpz_clear(root3), mpz_clear(root4);
        mpz_clear(g), mpz_clear(u), mpz_clear(v);
        return;
    }
    mpz_clear(g), mpz_clear(u), mpz_clear(v);
    // error, return zero root
    mpz_set_ui(root, 0L);
         */
        return BigInteger.ONE;
    }

    public static BigInteger mpzImport(byte[] data) {
        return new BigInteger(1, data);
    }

    public static BigInteger[] gcdExt(BigInteger a, BigInteger b) {
        BigInteger[] result = new BigInteger[3];
        boolean swapXY = false;

        if (a.compareTo(b) < 0) {
            BigInteger t = a;
            a = b;
            b = t;
            swapXY = true;
        }

        if (b.equals(BigInteger.ZERO)) {
            result[0] = a;
            result[1] = BigInteger.ONE;
            result[2] = BigInteger.ZERO;
        }

        BigInteger x1 = BigInteger.ZERO;
        BigInteger x2 = BigInteger.ONE;
        BigInteger y1 = BigInteger.ONE;
        BigInteger y2 = BigInteger.ZERO;

        while (b.compareTo(BigInteger.ZERO) > 0) {
            BigInteger[] qr = a.divideAndRemainder(b);
            result[1] = x2.subtract(qr[0].multiply(x1));
            result[2] = y2.subtract(qr[0].multiply(y1));
            a = b;
            b = qr[1];
            x2 = x1;
            x1 = result[1];
            y2 = y1;
            y1 = result[2];
        }

        result[0] = a;
        result[1] = x2;
        result[2] = y2;

        if(swapXY) {
            BigInteger t = result[1];
            result[1] = result[2];
            result[2] = t;
        }
        return result;
    }
}
