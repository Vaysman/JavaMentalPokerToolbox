package ru.wiseman.jmpt.key;

import org.junit.experimental.categories.Categories;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Categories.class)
@Categories.ExcludeCategory(SlowTest.class)
@Suite.SuiteClasses({TMCGSecretKeyTest.class, TMCGPublicKeyTest.class, UtilsTest.class})
public class KeysNotSlowTestSuite {
}
