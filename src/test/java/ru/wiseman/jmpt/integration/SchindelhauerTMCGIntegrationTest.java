package ru.wiseman.jmpt.integration;

import org.junit.Test;
import ru.wiseman.jmpt.SchindelhauerTMCG;
import ru.wiseman.jmpt.card.Card;
import ru.wiseman.jmpt.key.PublicKey;
import ru.wiseman.jmpt.key.PublicKeyRing;
import ru.wiseman.jmpt.key.PublicKeyRingImpl;

public class SchindelhauerTMCGIntegrationTest {


    public static final int NUMBER_OF_PALYERS = 3;

    @Test
    public void createOpenCard_properParametersProvided_returnsOpenCardWithSpecifiedCardType() throws Exception {
        SchindelhauerTMCG toolbox = make_SchindelhauerTMCG(NUMBER_OF_PALYERS);
        PublicKeyRing keyRing = make_PublicKeyRing();
        PublicKey playerPublicKeys[] = make_PlayersPublicKeys(NUMBER_OF_PALYERS);
        init_KeyRingWithPlayersKeys(keyRing, playerPublicKeys);

        int typeOfCard = 1;

        Card card = toolbox.createOpenCard(keyRing, typeOfCard);
    }

    private PublicKey[] make_PlayersPublicKeys(int numberOfPalyers) {
        return new PublicKey[numberOfPalyers];
    }

    private void init_KeyRingWithPlayersKeys(PublicKeyRing keyRing, PublicKey[] playerPublicKeys) {
        keyRing.clear();
        for (int i = 0; i < playerPublicKeys.length; i++) {
            keyRing.add(playerPublicKeys[i]);
        }
    }

    private PublicKeyRing make_PublicKeyRing() {
        return new PublicKeyRingImpl();
    }

    private SchindelhauerTMCG make_SchindelhauerTMCG(int numberOfPalyers) {
        int numberOfProofs = 4;
        int numberOfBitsForEncodingCard = 6;

        return new SchindelhauerTMCG(numberOfProofs, numberOfPalyers, numberOfBitsForEncodingCard);
    }
}
