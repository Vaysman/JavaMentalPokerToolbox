package ru.wiseman.jmpt.key;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class TestUtil {
    public static String loadResource(final String name) {
        try {
            BufferedReader key = new BufferedReader(
                    new InputStreamReader(
                            Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/wiseman/jmpt/key/" + name)
                    )
            );

            return key.readLine().trim();
        } catch (IOException | NullPointerException e) {
            throw new IllegalArgumentException("Can't load resource " + name);
        }
    }
}
