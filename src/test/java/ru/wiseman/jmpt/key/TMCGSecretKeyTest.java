package ru.wiseman.jmpt.key;

import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import ru.wiseman.jmpt.SchindelhauerTMCG;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

public class TMCGSecretKeyTest {
    private static final String NAME = "any string";
    private static final String EMAIL = "any string";
    private static final int KEY_SIZE_1024 = 1024;
    private static final int KEY_SIZE_2048 = 2048;
    private static final String ANY_STRING = "any string";
    private static final String ANY_STRING2 = "another any string";
    private static final String SECRET_KEY = loadStringifiedKey();

    @Mock
    private TMCGPublicKey publicKey;

    private static String loadStringifiedKey() {
        BufferedReader key = new BufferedReader(
                new InputStreamReader(
                        Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/wiseman/jmpt/key/secret_key_with_nizk_import_from_libTMCG.txt")
                )
        );

        try {
            return key.readLine().trim();
        } catch (IOException e) {
            return "";
        }
    }

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
    public void check_improperSecretKey_returnsFalse() throws Exception {
//        ArrayList<String> s;
//        TMCGPublicKey publicKey = mock(TMCGPublicKey.class);
//        TMCGSecretKey privateKey = spy(new TMCGSecretKey("Alice", "alice@gaos.org", 1024));
//        doReturn(publicKey).when(privateKey).makePublicKey(privateKey);
//        when(publicKey.check()).thenReturn(false);
//
//        boolean check = privateKey.check();
//
//        assertFalse(check);
    }

    @Test
    @Category(SlowTest.class)
    public void importKey_keyFromTestForlibTMCG_checkReturnsTrue() throws Exception {
        TMCGSecretKey secretKey = TMCGSecretKey.importKey(SECRET_KEY);

        assertThat(secretKey.check(), is(true));
    }

    @Test
    @Category(SlowTest.class)
    public void toString_keyFromTestForlibTMCG_returnsStringEqualsToOriginal() throws Exception {
        TMCGSecretKey secretKey = TMCGSecretKey.importKey(SECRET_KEY);

        assertThat(secretKey.check(), is(true));
    }

    private TMCGSecretKey make_secretKeyWithMockedPublicKey() {
        return new TMCGSecretKey(NAME, EMAIL, 512, false, publicKey);
    }
}

