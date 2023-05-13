package com.metabit.custom.safe.safeseal;

import com.metabit.custom.safe.iip.shared.SharedConstants;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.metabit.support.format.HexDump;
import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SAFESealUseCaseTest
{
    @SuppressWarnings("all")
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SAFESealUseCaseTest.class);
    private static SecureRandom rng;
    // these are the asymmetric key pairs; we consider them in place before the scheme is applied (precondition).
    private PrivateKey senderPrivateKey;
    private PublicKey senderPublicKey;
    private PrivateKey recipientPrivateKey;
    private PublicKey recipientPublicKey;
    private KeyPair rsaKeyPair;

    @BeforeAll
    static void globalInit()
        {
        if (Security.getProvider("BC") == null) Security.addProvider(new BouncyCastleProvider());
        rng = new SecureRandom();
        }

    @Test
    void useCaseTestWithECDHE() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, BadPaddingException
        {
        // ---- prepare test data instance.
        byte[] testPayload = "SAFE eV".getBytes(StandardCharsets.UTF_8);
        Long testUnique = System.currentTimeMillis();
        // ==== SENDER ====
        // ---- perform sealing
        SAFESealSealer uwe = new SAFESealSealer(true);
        byte[] sealed = uwe.seal(senderPrivateKey, recipientPublicKey, testPayload, testUnique);
        //---- in between here, the transport would take place
// debug outputs
//        log.info("\n" + HexDump.bytesToHexString(sealed, " ", 16));
//        log.info("\n" + Base64.toBase64String(sealed));
// final File dummy = new File("/tmp/debug.der");
// Files.write(dummy.toPath(), sealed);
        // ==== RECIPIENT ====
        // ---- perform revealing
        SAFESealRevealer revealer = new SAFESealRevealer(true);
        byte[] receivedPayload = revealer.reveal(senderPublicKey, recipientPrivateKey, sealed);
        // ---- test result
        assertArrayEquals(testPayload, receivedPayload);
        return;
        }

    //<editor-fold defaultstate="collapsed" desc="delombok">
    // -----------------------------------------------------------------------------------------------------------------
    //</editor-fold>
    @Test
    void useCaseTestWithRSA() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, BadPaddingException
        {
        rsaKeyPair = generateRSAKeyPair(2048);
        // ---- prepare test data instance.
        byte[] testPayload = "SAFE eV".getBytes(StandardCharsets.UTF_8);
        Long testUnique = System.currentTimeMillis();
        // ==== SENDER ====
        // ---- perform sealing
        SAFESealSealer uwe = new SAFESealSealer(false);
        byte[] sealed = uwe.seal(rsaKeyPair.getPrivate(), null, testPayload, null);
//---- in between here, the transport would take place
//        log.info("\n" + HexDump.bytesToHexString(sealed, " ", 16));
//        log.info("\n" + Base64.toBase64String(sealed));
// final File dummy = new File("/tmp/debug.der");
// Files.write(dummy.toPath(), sealed);
        //---- in between here, the transport would take place
        // ==== RECIPIENT ====
        // ---- perform revealing
        SAFESealRevealer revealer = new SAFESealRevealer(false);
        byte[] receivedPayload = revealer.reveal(rsaKeyPair.getPublic(), null, sealed);
        // ---- test result
        assertArrayEquals(testPayload, receivedPayload);
        return;
        }

    // -----------------------------------------------------------------------------------------------------------------
    void generateECKeyPairs(final String curveName) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException
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
        this.senderPublicKey = keyPairA.getPublic();
        this.recipientPrivateKey = keyPairB.getPrivate();
        this.recipientPublicKey = keyPairB.getPublic();
        }

    java.security.KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
        {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
        return kpg.generateKeyPair();
        }

    @BeforeEach
    void init() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException
        {
        // generate key pairs for this test. consider them exchanged/in the appropriate places
        generateECKeyPairs(SharedConstants.OID_EC_NAMED_CURVE_SECP256R1.getId());
        }
}
//___EOF___
