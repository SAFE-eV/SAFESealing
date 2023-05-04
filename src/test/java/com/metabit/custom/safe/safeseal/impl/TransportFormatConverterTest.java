package com.metabit.custom.safe.safeseal.impl;

import com.metabit.custom.safe.iip.shared.SharedConstants;
import com.metabit.custom.safe.safeseal.SAFESealRevealer;
import com.metabit.custom.safe.safeseal.SAFESealSealer;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.metabit.support.format.HexDump;

import javax.crypto.BadPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECParameterSpec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Slf4j
class TransportFormatConverterTest
{

    private PrivateKey senderPrivateKey;
    private PublicKey senderPublicKey;
    private PrivateKey recipientPrivateKey;
    private PublicKey recipientPublicKey;
    
    @Test
    void testBasics() throws IOException, BadPaddingException
        {
        InternalTransportTuple ids = new InternalTransportTuple(true); // ECDHE setup
        ids.encryptedData = "SAFE eV".getBytes(StandardCharsets.UTF_8);
        ids.keyDiversificationData= "ECDUMMYIV".getBytes();
        ids.cryptoIV= "AESDUMMYIV".getBytes();
        
        TransportFormatConverter tfc = new TransportFormatConverter();
        byte[] wrapped = tfc.wrapForTransport(ids);
        log.info("only transport-wrapped but no encryption performed (format test only)");
        log.info("\n" + HexDump.bytesToHexString(wrapped, " ", 16));
        log.info("\n" + Base64.toBase64String(wrapped));
        
        InternalTransportTuple ids2 = tfc.unwrapTransportFormat(wrapped);
        assertArrayEquals(ids.encryptedData,ids2.encryptedData);
        }
    
    
    @Test
    void testWithKeys()
            throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
                   BadPaddingException
        {
        // generate key pairs.
        generateECKeyPairs(SharedConstants.OID_EC_NAMED_CURVE_SECP256R1.getId());
        // ---- prepare test data
        byte[] testPayload = "SAFE eV".getBytes(StandardCharsets.UTF_8);
        Long   testUnique  = System.currentTimeMillis();
        
        // ---- perform sealing
        SAFESealSealer uwe = new SAFESealSealer(true);
        byte[] sealed = uwe.seal(senderPrivateKey, recipientPublicKey, testPayload, testUnique);
        
        log.info("sealing test");
        log.info("\n" + HexDump.bytesToHexString(sealed, " ", 16));
        log.info("\n" + Base64.toBase64String(sealed));
        //---- in between here, the transport would take place

        // ---- perform revealing
        SAFESealRevealer revealer = new SAFESealRevealer(true);
        byte[] receivedPayload = revealer.reveal(senderPublicKey, recipientPrivateKey, sealed);
        
        // ---- test result
        assertArrayEquals(testPayload,receivedPayload);
        }
    
    
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
    
    @BeforeAll static void globalInit()
        {
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
        }
}