package ru.wiseman.jmpt.key;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class TMCGPublicKeyTest {
    public static final String EMAIL = "any string";
    public static final int KEY_SIZE_1024 = 1024;
    public static final int KEY_SIZE_2048 = 2048;
    public static final String NAME = "any string";
    private static final String PUBLIC_KEY_COMPATIBILITY_TEST = TestUtil.loadResource("public_key_with_nizk_import_from_libTMCG.txt");
    private static final String SECRET_KEY = TestUtil.loadResource("secret_key_without_nizk_with_small_modulus.txt");

    @Test
    public void allGetters_preparedKey_returnsCorrectData() throws Exception {
        TMCGPublicKey secretKey = TMCGPublicKey.importKey(TestUtil.loadResource("prepared_public_key.txt"));

        assertThat(secretKey.getName(), is("Alice"));
        assertThat(secretKey.getEmail(), is("alice@example.com"));
        assertThat(secretKey.getType(), is("TMCG/RABIN_768"));
        assertThat(secretKey.getModulus(), is(new BigInteger("3490736810401101981780369708355003783757678877239493833829453202637574524793586640880110716880277047754962383918824187392714540910315477326969545629046927749401470043194265815596477951100020089524482415319929393097141975924713693153")));
        assertThat(secretKey.getY(), is(new BigInteger("11")));
        assertThat(secretKey.getNizk(), is("nzk^16^128^128^"));
        assertThat(secretKey.getSig(), is("sig|ID8^ibhnizpi|2t9grlxzrvz76oj77g82d0zncujcrqlskaz2empm7xb23zlpyh6v2nw5dim0ylu79wi2x00qk2bvv4fwztt0dacokmkosoatd4bxf5zw28dgh0hlwlxz5iktaeoijpwgwk8y40g7wnx95ibhnizpi|"));
    }

    @Test
    @Category(SlowTest.class)
    public void check() throws Exception {
        TMCGSecretKey sec = new TMCGSecretKey("Name", "Email", 1024, true);
        TMCGPublicKey pub = new TMCGPublicKey(sec);
        assertTrue(pub.check());
        assertTrue(sec.check());
    }

    @Test
    @Category(SlowTest.class)
    public void check_createUsingSecretKey_returnsTrue() throws Exception {
        TMCGPublicKey publicKey = make_publicKey(KEY_SIZE_1024);

        assertThat(publicKey.check(), is(true));

        publicKey = make_publicKey(KEY_SIZE_2048);

        assertThat(publicKey.check(), is(true));
    }

    @Test
    @Category(SlowTest.class)
    public void check_keyWithProof_returnsTrue() throws Exception {
        boolean addProof = true;
        TMCGSecretKey secretKey = new TMCGSecretKey(NAME, EMAIL, KEY_SIZE_1024, addProof);
        TMCGPublicKey key = new TMCGPublicKey(secretKey);

        assertThat(key.check(), is(true));

        secretKey = new TMCGSecretKey(NAME, EMAIL, KEY_SIZE_2048, addProof);
        key = new TMCGPublicKey(secretKey);

        assertThat(key.check(), is(true));
    }

    @Test
    @Category(SlowTest.class)
    public void check_keyWithoutProof_returnsTrue() throws Exception {
        TMCGSecretKey secretKey = new TMCGSecretKey(NAME, EMAIL, KEY_SIZE_1024);
        TMCGPublicKey key = new TMCGPublicKey(secretKey);

        assertThat(key.check(), is(true));


        secretKey = new TMCGSecretKey(NAME, EMAIL, KEY_SIZE_2048);
        key = new TMCGPublicKey(secretKey);

        assertThat(key.check(), is(true));
    }

    @Test
    public void encrypt_emptyString_returnsEncryptedDataWithKeyID() throws Exception {
        TMCGSecretKey secretKey = TMCGSecretKey.importKey(SECRET_KEY);
        TMCGPublicKey publicKey = new TMCGPublicKey(secretKey);

        assertThat(publicKey.encrypt(""), is(startsWith("enc|ID8^uuc8jmxe|")));
    }

    @Test
    public void encrypt_randomText_returnsProperlyEncryptedData() throws Exception {
        TMCGSecretKey secretKey = TMCGSecretKey.importKey(SECRET_KEY);
        TMCGPublicKey publicKey = new TMCGPublicKey(secretKey);
        Random random = new SecureRandom();
        String text = new BigInteger(160, random).toString(32).substring(0, 20);

        assertThat(secretKey.decrypt(publicKey.encrypt(text)), is(text.getBytes()));
    }

    @Test
    public void fingerprint_keyFromTestFromlibTMCG_returnsProperFingerprint() throws Exception {
        String expected = "9031 C61A 8B72 75CD 0163 3AE5 6893 AF9A 9A76 9B3E ";
        TMCGPublicKey key = TMCGPublicKey.importKey(PUBLIC_KEY_COMPATIBILITY_TEST);

        assertThat(key.fingerprint(), is(expected));
    }

    @Test
    @Category(SlowTest.class)
    public void importKey_keyFromTestFromlibTMCG_returnsTrue() throws Exception {
        TMCGPublicKey publicKey = TMCGPublicKey.importKey(PUBLIC_KEY_COMPATIBILITY_TEST);
        assertThat(publicKey.check(), is(true));
    }

    @Test
    public void keyId_withSize5_returnsKeyIdSize5() throws Exception {
        TMCGPublicKey key = TMCGPublicKey.importKey(PUBLIC_KEY_COMPATIBILITY_TEST);

        assertThat(key.keyId(5), is("ID5^g54i8"));
    }

    @Test
    public void keyId_withoutSize_returnsKeyIdSize8() throws Exception {
        TMCGPublicKey key = TMCGPublicKey.importKey(PUBLIC_KEY_COMPATIBILITY_TEST);

        assertThat(key.keyId(), is("ID8^63gg54i8"));
    }

    @Test
    public void selfId_keyFromTestFromlibTMCGSignatureCleared_returnsSelfsig() throws Exception {
        TMCGPublicKey key = TMCGPublicKey.importKey(PUBLIC_KEY_COMPATIBILITY_TEST);
        key.setSignature(null);

        assertThat(key.selfId(), is("SELFSIG-SELFSIG-SELFSIG-SELFSIG-SELFSIG-SELFSIG"));
    }

    @Test
    public void selfId_keyFromTestFromlibTMCG_returnsSignaturData() throws Exception {
        TMCGPublicKey key = TMCGPublicKey.importKey(PUBLIC_KEY_COMPATIBILITY_TEST);

        assertThat(key.selfId(), is("1fgxqkxm5mowg0nctlzs6qlt9wt2pybft0fxdfne63lh8sqfto3eci4ezj8sjtqlyl96l2afuea3ff61m1kkywlpuhblmbgsyh8drearx304jnhefkjfktuu4u0b8klp15x05ssxp5p4oobo1fwfbk018avteu9cjugxrubpcmfllgh33tm18wdy26btt1h63gg54i8"));
    }

    @Test
    @Category(SlowTest.class)
    public void verify_validSignature_returnsTrue() throws Exception {
        String v = "To be signed ...";

        TMCGSecretKey sec = new TMCGSecretKey("Name", "Email", 1024, true);
        String sign = sec.sign(v);
        assertTrue(sec.verify(v, sign));
    }

    private TMCGPublicKey make_publicKey(int size) {
        TMCGSecretKey secretKey = new TMCGSecretKey(NAME, EMAIL, size, true);
        return new TMCGPublicKey(secretKey);
    }
}
