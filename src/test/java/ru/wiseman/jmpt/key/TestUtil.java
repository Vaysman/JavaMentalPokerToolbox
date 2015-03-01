package ru.wiseman.jmpt.key;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class TestUtil {
    public static String loadStringifiedKey(final String name) {
        BufferedReader key = new BufferedReader(
                new InputStreamReader(
                        Thread.currentThread().getContextClassLoader().getResourceAsStream("ru/wiseman/jmpt/key/" + name)
                )
        );

        try {
            return key.readLine().trim();
        } catch (IOException e) {
            throw new IllegalArgumentException("Can't load key");
        }
    }
}
