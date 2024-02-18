package com.metabit.custom.safe.iip;

import com.metabit.custom.safe.iip.shared.SharedConstants;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@Slf4j
public class AlgorithmLookupTest
{
    private static Provider securityProvider;
    
    @Test
    void testSomeLookupFunctions() throws NoSuchPaddingException, NoSuchAlgorithmException
        {


        String testCipher = "AES/ECB/NoPadding";
        ASN1ObjectIdentifier  testOID = SharedConstants.OID_AES_256_ECB;

        log.info("input: " + testCipher);
        Cipher symmetricCipher1 = Cipher.getInstance(testCipher, securityProvider);
    
        String algo1 = symmetricCipher1.getAlgorithm();
        log.info(algo1);
        
        
        log.info("-----");
        log.info("input: " + testOID.getId());
        Cipher symmetricCipher2 = Cipher.getInstance(testOID.getId(), securityProvider);
        String algo2 = symmetricCipher2.getAlgorithm();
        log.info(algo2);
        
        // ---- ok, but how to get the OID from an instantiated cipher? is it possible?
        
        return;
        }
    
    
    @Test void investigateECDHEDetails()
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException,
                   InvalidKeyException
        {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", securityProvider);
        // ECDH is ignorant to the specific EC used. So, how does the specific EC algorithm get in to the procedure?

        String name = "secp256r1";

        // this is the relation between the two: the named ones are a special case
        ECNamedCurveParameterSpec namedParameterSpec = ECNamedCurveTable.getParameterSpec(name);
        // this is the general set, for almost all (in this representation, that is)
        ECNamedCurveSpec generalECParameterSpec = new ECNamedCurveSpec(name, namedParameterSpec.getCurve(), namedParameterSpec.getG(), namedParameterSpec.getN(), namedParameterSpec.getH(), namedParameterSpec.getSeed());

        assertNotNull(namedParameterSpec);
        assertNotNull(generalECParameterSpec);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", securityProvider);
        kpg.initialize(generalECParameterSpec); // here, both namedParameterSpec and generalECParameterSpec is acceptable.

        KeyPair keyPairA = kpg.generateKeyPair();
        KeyPair keyPairB = kpg.generateKeyPair();

        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        aKeyAgree.init(keyPairA.getPrivate());

        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        bKeyAgree.init(keyPairB.getPrivate());

        aKeyAgree.doPhase((Key) keyPairB.getPublic(), true);
        bKeyAgree.doPhase((Key) keyPairA.getPublic(), true);

        byte[] aSecret = aKeyAgree.generateSecret();
        byte[] bSecret = bKeyAgree.generateSecret();

        Assertions.assertArrayEquals(aSecret, bSecret);
        // Assert.assertEquals(bitSize/8, aSecret.length);
        //----------------------------
        // so, the ECDH is agnostic to the key types
        // I assume (we can check) it will fail when presented with keys from different curves.
        // How can we know the key curves?
        // .getAlgorithm() just says "EC", which is correct; "RSA" would be the other.
        // but which curve? we don't want all the details, do we.
        log.info("key A (pub ) algorithm: " + keyPairA.getPublic().getAlgorithm());
        log.info("key A (priv) algorithm: " + keyPairA.getPrivate().getAlgorithm());
        log.info("key B (pub ) algorithm: " + keyPairB.getPublic().getAlgorithm());
        log.info("key B (priv) algorithm: " + keyPairB.getPrivate().getAlgorithm());
        
        log.info(keyPairA.getPublic().getFormat());
        }
    
    
    @BeforeAll
    static void globalInit()
        {
        securityProvider = Security.getProvider("BC");
        if (securityProvider == null)
            {
            securityProvider = new BouncyCastleProvider();
            Security.addProvider(securityProvider);
            }
        }
}
