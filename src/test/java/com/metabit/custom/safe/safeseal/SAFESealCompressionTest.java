package com.metabit.custom.safe.safeseal;

import com.metabit.custom.safe.iip.shared.SharedConstants;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.metabit.support.format.HexDump;

import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Slf4j
class SAFESealCompressionTest
{
    public static final int RSA_KEY_SIZE = 2048;
    private static SecureRandom rng;
    // these are the asymmetric key pairs; we consider them in place before the scheme is applied (precondition).
    private PrivateKey senderPrivateKey;
    private PublicKey senderPublicKey;
    private PrivateKey recipientPrivateKey;
    private PublicKey recipientPublicKey;
    private KeyPair rsaKeyPair;

    public static final String OCMF_TEST_DATA = "{\n" +
            "    \"FV\": \"1.0\",\n" +
            "    \"GI\": \"ABL SBC-301\",\n" +
            "    \"GS\": \"808829900001\",\n" +
            "    \"GV\": \"1.4p3\",\n" +
            "    \"PG\": \"T12345\",\n" +
            "    \"MV\": \"Phoenix Contact\",\n" +
            "    \"MM\": \"EEM-350-D-MCB\",\n" +
            "    \"MS\": \"BQ27400330016\",\n" +
            "    \"MF\": \"1.0\",\n" +
            "    \"IS\": true,\n" +
            "    \"IL\": \"VERIFIED\",\n" +
            "    \"IF\": [\n" +
            "        \"RFID_PLAIN\",\n" +
            "        \"OCPP_RS_TLS\"\n" +
            "    ],\n" +
            "    \"IT\": \"ISO14443\",\n" +
            "    \"ID\": \"1F2D3A4F5506C7\",\n" +
            "    \"TT\": \"Tarif 1\",\n" +
            "    \"RD\": [\n" +
            "        {\n" +
            "            \"TM\": \"2018-07-24T13:22:04,000+0200 S\",\n" +
            "            \"TX\": \"B\",\n" +
            "            \"RV\": 2935.6,\n" +
            "            \"RI\": \"1-b:1.8.0\",\n" +
            "            \"RU\": \"kWh\",\n" +
            "            \"RT\": \"AC\",\n" +
            "            \"EF\": \"\",\n" +
            "            \"ST\": \"G\"\n" +
            "        }\n" +
            "    ]\n" +
            "}"; // test data from OCMF readme.
    @BeforeAll
    static void globalInit()
        {
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
        rng = new SecureRandom();
        }

    @ParameterizedTest
    @ValueSource(booleans =  {true, false})
    void useCaseTestWithECDHE(boolean compression)
            throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
            BadPaddingException
        {
        // ---- prepare test data instance.
        byte[] testPayload = OCMF_TEST_DATA.getBytes(StandardCharsets.UTF_8);
        Long testUnique = System.currentTimeMillis();

        // ==== SENDER ====
        // ---- perform sealing
        SAFESealSealer uwe = new SAFESealSealer(0);
        uwe.setCompressionMode(compression);
        byte[] sealed = uwe.seal(senderPrivateKey, recipientPublicKey, testPayload, testUnique);

        // "transport", or rather
        log.info("payload " + testPayload.length + " bytes, sealed " + sealed.length + " bytes, ZLIB compression = " + compression);

        // ==== RECIPIENT ====
        // ---- perform revealing
        SAFESealRevealer revealer = new SAFESealRevealer(0);
        byte[] receivedPayload = revealer.reveal(senderPublicKey, recipientPrivateKey, sealed);

        // ---- test result
        assertArrayEquals(testPayload, receivedPayload);
        return;
        }
    // -----------------------------------------------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(booleans =  {true, false})
    void useCaseTestWithRSA(boolean compression)
            throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
            BadPaddingException
        {
        rsaKeyPair = generateRSAKeyPair(RSA_KEY_SIZE);
        // ---- prepare test data instance.
        byte[] testPayload = OCMF_TEST_DATA.getBytes(StandardCharsets.UTF_8);
        Long testUnique = System.currentTimeMillis();

        // ==== SENDER ====
        // ---- perform sealing
        SAFESealSealer sealer = new SAFESealSealer(1);
        sealer.setCompressionMode(compression);
        byte[] sealed = sealer.seal(rsaKeyPair.getPrivate(), null, testPayload, null);

        // "transport", or rather
        log.info("payload " + testPayload.length + " bytes, sealed " + sealed.length + " bytes with " + RSA_KEY_SIZE/8 + " byte block size, ZLIB compression = " + compression);

        //---- in between here, the transport would take place

        // ==== RECIPIENT ====
        // ---- perform revealing
        SAFESealRevealer revealer = new SAFESealRevealer(1);
        byte[] receivedPayload = revealer.reveal(rsaKeyPair.getPublic(), null, sealed);

        // ---- test result
        assertArrayEquals(testPayload, receivedPayload);
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
        this.senderPublicKey = keyPairA.getPublic();
        this.recipientPrivateKey = keyPairB.getPrivate();
        this.recipientPublicKey = keyPairB.getPublic();
        }

    KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
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
