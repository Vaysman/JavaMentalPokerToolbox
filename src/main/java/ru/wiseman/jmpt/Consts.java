package ru.wiseman.jmpt;

public class Consts {
    /* Define the message digest algorithm for signatures and FS-heuristic;
       Underlying assumption: Random Oracle Model */
    public static final int RMD160_HASH_SIZE = 20;
    /* Define the security parameter of the DDH-hard group G;
           Underlying assumptions: DDH, CDH, DLOG */
    public static final int TMCG_DDH_SIZE = 1024;
    /* Define the security parameter of the used exponents;
           Underlying assumptions: DLSE (related to DDH), DLOG */
    public static final int TMCG_DLSE_SIZE = 160;
    /* Define the security parameter for the soundness of the interactive argument for Groth's VSSHE and SKC. */
    public static final int TMCG_GROTH_L_E = 80;
    /* Define whether hashed commitments (short values) should be used;
           Underlying assumption: Random Oracle Model */
    public static final boolean TMCG_HASH_COMMITMENT = true;
    /* Define the size of the unique TMCG key ID (in characters) */
    public static final int TMCG_KEYID_SIZE = 8;
    /* Define the maximum soundness error probability of the TMCG public key;
           NIZK proof (Gennaro, Micciancio, Rabin), Stage = 1: m is square free;
           d^{-TMCG_KEY_NIZK_STAGE1} with d = ... */
    public static final int TMCG_KEY_NIZK_STAGE1 = 16;
    /* Define the maximum soundness error probability of the TMCG public key;
           NIZK proof (Gennaro, Micciancio, Rabin), Stage = 2: m is prime power product;
           2^{-TMCG_KEY_NIZK_STAGE2} */
    public static final int TMCG_KEY_NIZK_STAGE2 = 128;
    /* Define the maximum soundness error probability for the TMCG public key;
           NIZK proof (Goldwasser, Micali); Stage = 3: y \in NQR^\circ_m;
           2^{-TMCG_KEY_NIZK_STAGE3} */
    public static final int TMCG_KEY_NIZK_STAGE3 = 128;
    /* Define the maximum number of stackable cards */
    public static final int TMCG_MAX_CARDS = 128;
    /* Define the maximum size of the exponent for fast exponentiation */
    public static final int TMCG_MAX_FPOWM_T = 2048;
    /* Define the maximum number of players in the scheme of Schindelhauer */
    public static final int TMCG_MAX_PLAYERS = 32;
    /* Define the number of bits which represents the maximum number of
           different card types in the scheme of Schindelhauer and the maximum
           size of the message space in the scheme of Barnett and Smart */
    public static final int TMCG_MAX_TYPEBITS = 8;
    /* Define the input/ouput base encoding of the iostream operators */
    public static final int TMCG_MPZ_IO_BASE = 36;
    /* Define the number of iterations for the Miller-Rabin primality test.
          (maximum soundness error probability = 4^{-TMCG_MR_ITERATIONS}) */
    public static final int TMCG_MR_ITERATIONS = 64;
    /* Define the security parameter for the signature generation
           with Rabin/PRab */
    public static final int TMCG_PRAB_K0 = 20;
    /* Define the security parameter of the TMCG public key;
           Underlying assumptions: QRA, FACTOR */
    public static final int TMCG_QRA_SIZE = 1024;
    /* Define a helping macro */
    public static final int TMCG_MAX_KEYBITS = ((TMCG_DDH_SIZE > TMCG_QRA_SIZE) ? TMCG_DDH_SIZE : TMCG_QRA_SIZE);
    /* Define a helping macro */
    public static final int TMCG_MAX_KEY_CHARS = (TMCG_MAX_KEYBITS * 1024);
    /* Define a helping macro */
    public static final int TMCG_MAX_VALUE_CHARS = (TMCG_MAX_KEYBITS / 2);
    /* Define a helping macro */
    public static final int TMCG_MAX_CARD_CHARS = (TMCG_MAX_PLAYERS * TMCG_MAX_TYPEBITS * TMCG_MAX_VALUE_CHARS);
    /* Define a helping macro */
    public static final int TMCG_MAX_STACK_CHARS = (TMCG_MAX_CARDS * TMCG_MAX_CARD_CHARS);
    /* Define the security parameter for the encryption with Rabin/SAEP */
    public static final int TMCG_SAEP_S0 = 20;

//    public static final int TMCG_GCRY_MD_ALGO GCRY_MD_RMD160;

}
