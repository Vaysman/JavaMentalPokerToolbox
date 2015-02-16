package ru.wiseman.jmpt.key;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;

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
        return g(s, 12);
    }

    public static byte[] g(String s, int osize) {
        setBcProvider();
        int mdsize = 20;
        int usesize = mdsize / 4;
        byte[] output = new byte[osize];

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
        BigInteger result;
        BigInteger g, u, v;
        BigInteger[] bezoutCoefficient = gcdExt(p, q);
        g = bezoutCoefficient[0];
        u = bezoutCoefficient[1];
        v = bezoutCoefficient[2];
        if(g.equals(ONE)) {
            BigInteger rootP, rootQ, root1, root2, root3, root4;
                    // single square roots

        }
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
        return ONE;
    }

    public static boolean mpz_qrmn_p(BigInteger foo, BigInteger p, BigInteger q, BigInteger m) {
        return IntegerFunctions.jacobi(foo, p) == 1 && IntegerFunctions.jacobi(foo, q) == 1;
    }

    public static BigInteger mpzImport(byte[] data) {
        return new BigInteger(1, data);
    }

    public static BigInteger[] gcdExt(BigInteger firstNumber, BigInteger secondNumber) {
        class Pair {
            BigInteger number;
            BigInteger coefficient;

            public Pair(BigInteger number) {
                this.number = number;
            }

            public boolean mustSwap(Pair other) {
                return number.compareTo(other.number) < 0;
            }
        }

        Pair a = new Pair(firstNumber);
        Pair b = new Pair(secondNumber);
        BigInteger gcd;
        boolean swap;

        if (swap = a.mustSwap(b)) {
            Pair t = a;
            a = b;
            b = t;
        }

        if (b.number.equals(BigInteger.ZERO)) {
            BigInteger[] result = new BigInteger[3];
            gcd = a.number;
            a.coefficient = ONE;
            b.coefficient = BigInteger.ZERO;
        } else {
            BigInteger x1 = BigInteger.ZERO;
            BigInteger x2 = ONE;
            BigInteger y1 = ONE;
            BigInteger y2 = BigInteger.ZERO;
            BigInteger x, y;

            while (b.number.compareTo(BigInteger.ZERO) > 0) {
                BigInteger[] qr = a.number.divideAndRemainder(b.number);

                x = x2.subtract(qr[0].multiply(x1));
                y = y2.subtract(qr[0].multiply(y1));
                a.number = b.number;
                b.number = qr[1];
                x2 = x1;
                x1 = x;
                y2 = y1;
                y1 = y;
            }

            gcd = a.number;
            a.coefficient = x2;
            b.coefficient = y2;
        }

        if (swap) {
            Pair t = a;
            a = b;
            b = t;
        }

        return new BigInteger[]{ gcd, a.coefficient, b.coefficient };
    }

    public static BigInteger sqrtModR(BigInteger foo, BigInteger p, BigInteger q, BigInteger m) {
        BigInteger result;
        BigInteger g, u, v;
        BigInteger[] bezoutCoefficient = gcdExt(p, q);
        g = bezoutCoefficient[0];
        u = bezoutCoefficient[1];
        v = bezoutCoefficient[2];
        if(g.equals(ONE)) {
            BigInteger rootP, rootQ, root1, root2, root3, root4;
            // single square roots
//            rootP =
        }

        return null;
    }

    // prime congruent 3 modulo 4
    public static BigInteger mpz_sprime3mod4(int size, int iterations) {
        BigInteger result;
        do {
            result = BigInteger.probablePrime(size, random);
        } while (!result.mod(FOUR).equals(THREE));

        return result;
    }

    /*
        square roots mod p, with p prime
        [algorithm of Adleman, Manders, and Miller, 1977]
     */
    public static BigInteger mpz_sqrtmp_r(BigInteger a, BigInteger p) {
        return IntegerFunctions.ressol(a, p);
        /*if(a.equals(BigInteger.ZERO)) {
           return BigInteger.ZERO;
        }

        // ? p = 3 (mod 4)
        if(p.mod(FOUR).equals(THREE)) {
            BigInteger foo = p.add(ONE);
            foo = foo.divide(FOUR);
            return a.modPow(foo, p);
        } else {
            // ! p = 1 (mod 4)
            // ! s = (p-1)/4
            BigInteger s = p.subtract(ONE).divide(FOUR);
            // ? p = 5 (mod 8)
            if(p.mod(EIGHT).equals(FIVE)) {
                BigInteger foo, b;
                foo = a.modPow(s, p);
                b = p.add(THREE);
                b = b.divide(EIGHT);
                BigInteger root = a.modPow(b, p);
                // ? a^{(p-1)/4} = 1 (mod p)
                if(foo.equals(ONE)) {
                    return root;
                } else {
                    // ! a^{(p-1)/4} = -1 (mod p)
                    do {

                    } while (IntegerFunctions.jacobi(b, p) != -1);
                }
            }
        }
        /*
            else
            {
                if (mpz_congruent_ui_p(p, 5L, 8L))
                {
                    mpz_t foo, b;
                    mpz_init(foo);
                    mpz_powm(foo, a, s, p);
                    mpz_init_set(b, p);
                    mpz_add_ui(b, b, 3L);
                    mpz_fdiv_q_2exp(b, b, 3L);
                    mpz_powm(root, a, b, p);
				// ? a^{(p-1)/4} = 1 (mod p)
                    if (mpz_cmp_ui(foo, 1L) == 0)
                    {
                        mpz_clear(foo), mpz_clear(s), mpz_clear(b);
                        return;
                    }
				// ! a^{(p-1)/4} = -1 (mod p)
                    else
                    {
                        do
                            mpz_wrandomm(b, p);
                        while (mpz_jacobi(b, p) != -1);
                        mpz_powm(b, b, s, p);
                        mpz_mul(root, root, b);
                        mpz_mod(root, root, p);
                        mpz_clear(foo), mpz_clear(s), mpz_clear(b);
                        return;
                    }
                }
			// ! p = 1 (mod 8)
                else
                {
                    mpz_t foo, bar, b, t;
                    mpz_init(foo), mpz_init(bar);
                    mpz_powm(foo, a, s, p);
				// while a^s = 1 (mod p)
                    while (mpz_cmp_ui(foo, 1L) == 0)
                    {
					// ? s odd
                        if (mpz_odd_p(s))
                        {
                            mpz_add_ui(s, s, 1L);
                            mpz_fdiv_q_2exp(s, s, 1L);
                            mpz_powm(root, a, s, p);
                            mpz_clear(foo), mpz_clear(s);
                            return;
                        }
					// ! s even
                        else
                        {
                            mpz_fdiv_q_2exp(s, s, 1L);
                        }
                        mpz_powm(foo, a, s, p);
                    }
				// ! a^s = -1 (mod p)
                    mpz_init(b);
                    do
                        mpz_wrandomm(b, p);
                    while (mpz_jacobi(b, p) != -1);
                    mpz_init_set(t, p);
                    mpz_sub_ui(t, t, 1L);
                    mpz_fdiv_q_2exp(t, t, 1L);
				// while s even
                    while (mpz_even_p(s))
                    {
                        mpz_fdiv_q_2exp(s, s, 1L);
                        mpz_fdiv_q_2exp(t, t, 1L);
                        mpz_powm(foo, a, s, p);
                        mpz_powm(bar, b, t, p);
                        mpz_mul(foo, foo, bar);
                        mpz_mod(foo, foo, p);
                        mpz_set_si(bar, -1L);
					// ? a^s * b^t = -1 (mod p)
                        if (mpz_congruent_p(foo, bar, p))
                        {
                            mpz_set(bar, p);
                            mpz_sub_ui(bar, bar, 1L);
                            mpz_fdiv_q_2exp(bar, bar, 1L);
                            mpz_add(t, t, bar);
                        }
                    }
                    mpz_add_ui(s, s, 1L);
                    mpz_fdiv_q_2exp(s, s, 1L);
                    mpz_fdiv_q_2exp(t, t, 1L);
                    mpz_powm(foo, a, s, p);
                    mpz_powm(bar, b, t, p);
                    mpz_mul(root, foo, bar);
                    mpz_mod(root, root, p);
                    mpz_clear(foo), mpz_clear(bar);
                    mpz_clear(s), mpz_clear(b), mpz_clear(t);
                    return;
                }
            }

        */
        //return BigInteger.ZERO;
    }
}
