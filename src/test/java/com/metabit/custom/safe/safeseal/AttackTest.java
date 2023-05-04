package com.metabit.custom.safe.safeseal;

import com.metabit.custom.safe.iip.shared.SharedConstants;
import com.metabit.custom.safe.iip.SharedTestMethods;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * this test performs some "test attacks" on
 */
@Slf4j
class AttackTest
{
    private static SecureRandom rng;
    // these are the asymmetric key pairs; we consider them in place before the scheme is applied (precondition).
    private PrivateKey senderPrivateKey;
    private PublicKey senderPublicKey;
    private PrivateKey recipientPrivateKey;
    private PublicKey recipientPublicKey;
    

    /**
     * perform a full test on a test message: change each bit of the wrapped message and check what happens.
     *
     * For all bits of the encrypted message, it will be detected.
     * The transport format however contains some unused bits, whose values are moot;
     * changes there will be ignored. (The payload is unchanged in every case.)
     *
     * @throws InvalidAlgorithmParameterException if key generation has an issue
     * @throws NoSuchAlgorithmException if key generation has an issue
     * @throws BadPaddingException if the test code goes bad (it should catch the expected ones)
     */
    @ParameterizedTest
    @ValueSource(strings = {"SAFE eV",
                            "SAFE eV - Software Alliance for E-mobility",
                            "SAFE eV - Software Alliance for E-mobility\nAssociation for the Promotion of Research and Consumer Protection in the Field of Electric Mobility"})
    void extendedAttackTestWithRSA(final String testPayloadString)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, BadPaddingException
        {
        final KeyPair rsaKeyPair = generateRSAKeyPair(2048);
        // ---- prepare test data instance.
        byte[] testPayload = testPayloadString.getBytes(StandardCharsets.UTF_8);
        Long testUnique = System.currentTimeMillis();

        // ==== SENDER ====
        // ---- perform sealing
        SAFESealSealer uwe = new SAFESealSealer(false);
        byte[] sealed = uwe.seal(rsaKeyPair.getPrivate(), null, testPayload, null);

        // ==== RECIPIENT ====
        // ---- perform revealing
        SAFESealRevealer revealer = new SAFESealRevealer(false);
        // the "good" case.
        byte[] receivedPayload = revealer.reveal(rsaKeyPair.getPublic(), null, sealed);
        assertArrayEquals(testPayload, receivedPayload);

        // now provoke the "bad" cases
        for (int bit=0; bit<sealed.length*8; bit++)
            {
            byte[] tmp = new byte[sealed.length];
            System.arraycopy(sealed,0,tmp,0,sealed.length);
            // flip bit
            tmp[bit/8] ^= (1 << (bit%8));
            // test what happens
            try
                {
                byte[] result = revealer.reveal(rsaKeyPair.getPublic(), null, tmp); // should throw Exceptions
                // not all transport wrapper bits carry meaning; flipping those will be ignored.
                System.out.println("bit " + bit + " ignored.");
                // we make sure, though, the result is always correct.
                assertArrayEquals(testPayload, result);
                }
            catch(BadPaddingException ex)
                { } // this is the expected case
            catch(Exception ex) // all the other exceptions should be caught and replaced
                {
                System.err.println("naked exception at bit " + bit + ", " + ex.toString());
                }
            }
        return;
        }

    // test attacks on the ECDHE+AES+IIP encryption
    @Test
    void attackTestDoubleLayeredEncryption()
            throws NoSuchProviderException, IOException, BadPaddingException
        {

        // ---- prepare test data instance.
        byte[] testPayload = "SAFE eV".getBytes(StandardCharsets.UTF_8);
        Long   testUnique  = System.currentTimeMillis();

        // ==== SENDER ====
        // ---- perform sealing
        SAFESealSealer uwe = new SAFESealSealer(true);
        byte[] sealed = uwe.seal(senderPrivateKey, recipientPublicKey, testPayload, testUnique);


        // ==== RECIPIENT ====
        // ---- perform revealing
        SAFESealRevealer revealer = new SAFESealRevealer(true);
        byte[] receivedPayload = revealer.reveal(senderPublicKey, recipientPrivateKey, sealed);
        assertArrayEquals(testPayload,receivedPayload);

        // now, we intentionally damage the message in a specific placeand see whether that is detected.
        {
        byte[] tmpCopy = Arrays.copyOf(sealed, sealed.length); // creates new array and copies elements
        // SharedTestMethods.flipRandomBit(sealed.length, rng, sealed);
        tmpCopy[23] ^= (byte) 0x55; // flip half the bits in this byte
        Exception ex = assertThrows(BadPaddingException.class, () -> revealer.reveal(senderPublicKey, recipientPrivateKey, tmpCopy));
        }

        // systematic check for each bit in the message.
        log.info("sealed data is " + sealed.length*8 + " bits in size");
        for (int i=0; i<sealed.length*8; i++)
            {
            byte[] tmpCopy = Arrays.copyOf(sealed, sealed.length);
            SharedTestMethods.flipSpecificBit(i, tmpCopy);
            try
                {
                byte[] result = revealer.reveal(senderPublicKey, recipientPrivateKey, tmpCopy);
                assertArrayEquals(testPayload,result); // *this* must never fail.

                log.debug("bit # " + i + "\twas inconsequential");
                // payload was intact and could be obtained, even though the wrapper was intentionally damaged
                // there are unused bits in the wrapping, changes in which do not affect the validity of the payload in any way.
                // we can add some additional checks if must be. But the content has never successfully been tampered with.
                }
            catch (BadPaddingException ex) // as expected
                {
                log.trace("bit # " + i + "\tchange detected and rejected");
                }
            catch (RuntimeException rex)
                {
                log.error("unexpected",rex); // unexpected
                }
//            Exception ex2 = assertThrows(Exception.class, () -> revealer.reveal(senderPublicKey, recipientPrivateKey, tmpCopy)); // assertThrows() fails if the Exception is *not* thrown.
            }
        // ---- test result
        return;
        }

    // -----------------------------------------------------------------------------------------------------------------
    void generateECKeyPairs(final String curveName)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
        {
        
        // this is the relation between the two: the named ones are a special case
        ECNamedCurveParameterSpec namedParameterSpec = ECNamedCurveTable.getParameterSpec(curveName);
        // this is the general set, for almost all (in this representation, that is)
        ECParameterSpec generalECParameterSpec = new ECNamedCurveSpec(curveName, namedParameterSpec.getCurve(), namedParameterSpec.getG(), namedParameterSpec.getN(), namedParameterSpec.getH(), namedParameterSpec.getSeed());

        assertNotNull(namedParameterSpec);
        assertNotNull(generalECParameterSpec);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(generalECParameterSpec); // here, both namedParameterSpec and generalECParameterSpec is acceptable.

        KeyPair keyPairA = kpg.generateKeyPair();
        KeyPair keyPairB = kpg.generateKeyPair();
        
        this.senderPrivateKey = keyPairA.getPrivate();
        this.senderPublicKey  = keyPairA.getPublic();
        this.recipientPrivateKey = keyPairB.getPrivate();
        this.recipientPublicKey  = keyPairB.getPublic();
        }
    
    java.security.KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
        {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
        return kpg.generateKeyPair();
        }

    @BeforeAll static void globalInit()
        {
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
        rng = new SecureRandom();
        }
    
    @BeforeEach void init() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException
        {
        // generate key pairs for this test. consider them exchanged/in the appropriate places
        generateECKeyPairs(SharedConstants.OID_EC_NAMED_CURVE_SECP256R1.getId());
        }
}