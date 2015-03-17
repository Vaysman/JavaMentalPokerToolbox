package ru.wiseman.jmpt.card;

import java.util.AbstractMap;
import java.util.List;

public class TMCGStackSecret<T extends CardSecret> {
    private List<AbstractMap.SimpleImmutableEntry<Integer, CardSecret>> stack;
}