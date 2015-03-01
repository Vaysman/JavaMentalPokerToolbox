package ru.wiseman.jmpt.key;

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import ru.wiseman.jmpt.SchindelhauerTMCG;

import java.math.BigInteger;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

public class TMCGSecretKeyTest {
    private static final String NAME = "any string";
    private static final String EMAIL = "any string";
    private static final int KEY_SIZE_1024 = 1024;
    private static final int KEY_SIZE_2048 = 2048;
    private static final String ANY_STRING = "any string";
    private static final String ANY_STRING2 = "another any string";
    private static final String SECRET_KEY_COMPATIBILITY_TEST = TestUtil.loadResource("secret_key_with_nizk_import_from_libTMCG.txt");
    private static final String SECRET_KEY = TestUtil.loadResource("secret_key_without_nizk_with_small_modulus.txt");

    @Mock
    private TMCGPublicKey publicKey;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        when(publicKey.keyId(SchindelhauerTMCG.TMCG_KEYID_SIZE)).thenReturn("ID8^12345678");
    }

    @Test
    @Category(SlowTest.class)
    public void check_keyWithProof_returnsTrue() throws Exception {
        boolean addProof = true;
        TMCGSecretKey key = new TMCGSecretKey(NAME, EMAIL, KEY_SIZE_1024, addProof);

        assertThat(key.check(), is(true));

        key = new TMCGSecretKey(NAME, EMAIL, KEY_SIZE_2048, addProof);
        assertThat(key.check(), is(true));
    }

    @Test
    @Category(SlowTest.class)
    public void check_keyWithoutProof_returnsTrue() throws Exception {
        TMCGSecretKey key = new TMCGSecretKey(NAME, EMAIL, KEY_SIZE_1024);

        assertThat(key.check(), is(true));


        key = new TMCGSecretKey(NAME, EMAIL, KEY_SIZE_2048);

        assertThat(key.check(), is(true));
    }

    @Test
    public void check_default_delegatesToPublicKey() throws Exception {
        TMCGSecretKey key = make_secretKeyWithMockedPublicKey();

        key.check();

        verify(publicKey).check();
    }

    @Test
    public void verify_default_delegatesToPublicKey() throws Exception {
        TMCGSecretKey key = make_secretKeyWithMockedPublicKey();

        key.verify(ANY_STRING, ANY_STRING2);

        verify(publicKey).verify(ANY_STRING, ANY_STRING2);
    }

    @Test
    public void keyId_withoutKeyIdSize_delegatesToPublicKey() throws Exception {
        TMCGSecretKey key = make_secretKeyWithMockedPublicKey();

        key.keyId();

        verify(publicKey, atLeastOnce()).keyId(SchindelhauerTMCG.TMCG_KEYID_SIZE);
    }

    @Test
    public void keyId_withKeyIdSize_delegatesToPublicKey() throws Exception {
        TMCGSecretKey key = make_secretKeyWithMockedPublicKey();

        key.keyId(1);

        verify(publicKey).keyId(1);
    }

    @Test
    public void encrypt_default_delegatesToPublicKey() throws Exception {
        TMCGSecretKey key = make_secretKeyWithMockedPublicKey();

        key.encrypt(ANY_STRING);

        verify(publicKey).encrypt(ANY_STRING);
    }

    @Test
    public void fingerprint_default_delegatesToPublicKey() throws Exception {
        TMCGSecretKey key = make_secretKeyWithMockedPublicKey();

        key.fingerprint();

        verify(publicKey).fingerprint();
    }

    @Test
    @Category(SlowTest.class)
    public void importKey_keyFromTestFromlibTMCG_checkReturnsTrue() throws Exception {
        TMCGSecretKey secretKey = TMCGSecretKey.importKey(SECRET_KEY_COMPATIBILITY_TEST);

        assertThat(secretKey.check(), is(true));
    }

    @Test
    public void allGetters_preparedKey_returnsCorrectData() throws Exception {
        TMCGSecretKey secretKey = TMCGSecretKey.importKey(TestUtil.loadResource("prepared_secret_key.txt"));

        assertThat(secretKey.getName(), is("Alice"));
        assertThat(secretKey.getEmail(), is("alice@example.com"));
        assertThat(secretKey.getType(), is("TMCG/RABIN_768"));
        assertThat(secretKey.getModulus(), is(new BigInteger("3490736810401101981780369708355003783757678877239493833829453202637574524793586640880110716880277047754962383918824187392714540910315477326969545629046927749401470043194265815596477951100020089524482415319929393097141975924713693153")));
        assertThat(secretKey.getY(), is(new BigInteger("11")));
        assertThat(secretKey.getNizk(), is("nzk^16^128^128^"));
        assertThat(secretKey.getSig(), is("sig|ID8^ibhnizpi|2t9grlxzrvz76oj77g82d0zncujcrqlskaz2empm7xb23zlpyh6v2nw5dim0ylu79wi2x00qk2bvv4fwztt0dacokmkosoatd4bxf5zw28dgh0hlwlxz5iktaeoijpwgwk8y40g7wnx95ibhnizpi|"));
    }

    @Test
    public void sign_emptyString_returnsSignature() throws Exception {
        TMCGSecretKey secretKey = TMCGSecretKey.importKey(SECRET_KEY);

        assertThat(secretKey.sign(""), is(startsWith("sig|ID8^uuc8jmxe|")));
    }

    @Test
    public void sign_string_returnsSignature() throws Exception {
        TMCGSecretKey secretKey = TMCGSecretKey.importKey(SECRET_KEY);

        assertThat(secretKey.sign("string"), is(startsWith("sig|ID8^uuc8jmxe|")));
    }

    @Test
    public void sign_differentString_returnsDifferentSignature() throws Exception {
        TMCGSecretKey secretKey = TMCGSecretKey.importKey(SECRET_KEY);
        String signature1 = secretKey.sign("string1");
        String signature2 = secretKey.sign("string2");

        assertThat(signature1, is(not(signature2)));
    }

    @Test
    public void sign_differentSignatureSameKey_haveSameKeyID() throws Exception {
        TMCGSecretKey secretKey = TMCGSecretKey.importKey(SECRET_KEY);
        String signature1 = secretKey.sign("string1");
        String signature2 = secretKey.sign("string2");
        int start = signature1.indexOf("ID");
        int end = signature1.indexOf("|", start);

        assertThat(signature1.substring(start, end), is(signature2.substring(start, end)));
    }

    @Test
    public void decrypt_preparedEncyptedText_returnsDecryptedText() throws Exception {
        String text = "I never finish anyth";
        String encryptedText = TestUtil.loadResource("encrypted_text.txt");
        TMCGSecretKey secretKey = TMCGSecretKey.importKey(SECRET_KEY);

        assertThat(secretKey.decrypt(encryptedText), is(text.getBytes()));
    }

    @Test(expected = DecryptException.class)
    public void decrypt_emptyByteArray_returnsDecryptedText() throws Exception {
        TMCGSecretKey secretKey = TMCGSecretKey.importKey(SECRET_KEY);

        secretKey.decrypt(new byte[0]);
    }

    @Test
    @Category(SlowTest.class)
    public void toString_keyFromTestForlibTMCG_returnsStringEqualsToOriginal() throws Exception {
        TMCGSecretKey secretKey = TMCGSecretKey.importKey(SECRET_KEY_COMPATIBILITY_TEST);

        assertThat(secretKey.check(), is(true));
    }

    private TMCGSecretKey make_secretKeyWithMockedPublicKey() {
        return new TMCGSecretKey(NAME, EMAIL, 512, false, publicKey);
    }
}

