package ru.wiseman.jmpt.key;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

public class KeyParserTest {
    private static final String SECRET_KEY = TestUtil.loadResource("prepared_secret_key.txt");

    @Test
    public void parse_preparedSecretKey_returnsSecretKey() throws Exception {
        Key key = KeyParser.parse(SECRET_KEY);

        assertThat(key, is(instanceOf(TMCGSecretKey.class)));
    }

    @Test
    public void parse_preparedSecretKey_returnsKeyFilledWithData() throws Exception {
        TMCGSecretKey key = (TMCGSecretKey) KeyParser.parse(SECRET_KEY);

        assertThat(key.getName(), is("Alice"));
    }
}