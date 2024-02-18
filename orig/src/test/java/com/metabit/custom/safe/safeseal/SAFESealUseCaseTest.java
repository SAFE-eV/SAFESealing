package com.metabit.custom.safe.safeseal;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import javax.crypto.BadPaddingException;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.metabit.support.format.HexDump;

import com.metabit.custom.safe.iip.shared.SharedConstants;

import lombok.extern.slf4j.Slf4j;

@Slf4j
class SAFESealUseCaseTest {
    private static SecureRandom rng;
    // these are the asymmetric key pairs; we consider them in place before the
    // scheme is applied (precondition).
    private PrivateKey senderPrivateKey;
    private PublicKey senderPublicKey;
    private PrivateKey recipientPrivateKey;
    private PublicKey recipientPublicKey;
    private KeyPair rsaKeyPair;

    @BeforeAll
    static void globalInit() {
	if (Security.getProvider("BC") == null) {
	    Security.addProvider(new BouncyCastleProvider());
	}
	rng = new SecureRandom();
    }

    @Test
    void useCaseTestWithECDHE() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
	    NoSuchProviderException, BadPaddingException {
	// ---- prepare test data instance.
	final byte[] testPayload = "SAFE eV".getBytes(StandardCharsets.UTF_8);
	final Long testUnique = System.currentTimeMillis();

	// ==== SENDER ====
	// ---- perform sealing
	final SAFESealSealer uwe = new SAFESealSealer(true);
	final byte[] sealed = uwe.seal(senderPrivateKey, recipientPublicKey, testPayload, testUnique);

	// "transport", or rather
	log.info("\n" + HexDump.bytesToHexString(sealed, " ", 16));
	log.info("\n" + Base64.toBase64String(sealed));
	// ---- in between here, the transport would take place
// final File dummy = new File("/tmp/debug.der");
// Files.write(dummy.toPath(), sealed);

	// ==== RECIPIENT ====
	// ---- perform revealing
	final SAFESealRevealer revealer = new SAFESealRevealer(true);
	final byte[] receivedPayload = revealer.reveal(senderPublicKey, recipientPrivateKey, sealed);

	// ---- test result
	assertArrayEquals(testPayload, receivedPayload);
	return;
    }
    // -----------------------------------------------------------------------------------------------------------------

    @Test
    void useCaseTestWithRSA() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
	    NoSuchProviderException, BadPaddingException {
	rsaKeyPair = generateRSAKeyPair(2048);
	// ---- prepare test data instance.
	final byte[] testPayload = new byte[475];// "SAFE eV".getBytes(StandardCharsets.UTF_8);
	for (int i = 0; i < testPayload.length; i++) {
	    testPayload[i] = (byte) i;
	}
	final Long testUnique = System.currentTimeMillis();

	// ==== SENDER ====
	// ---- perform sealing
	final SAFESealSealer uwe = new SAFESealSealer(false);
	final byte[] sealed = uwe.seal(rsaKeyPair.getPrivate(), null, testPayload, null);

	// "transport", or rather
	log.info("\n" + HexDump.bytesToHexString(sealed, " ", 16));
	log.info("\n" + Base64.toBase64String(sealed));
// final File dummy = new File("/tmp/debug.der");
// Files.write(dummy.toPath(), sealed);

	// ---- in between here, the transport would take place

	// ==== RECIPIENT ====
	// ---- perform revealing
	final SAFESealRevealer revealer = new SAFESealRevealer(false);
	final byte[] receivedPayload = revealer.reveal(rsaKeyPair.getPublic(), null, sealed);

	// ---- test result
	assertArrayEquals(testPayload, receivedPayload);
	return;
    }

    // -----------------------------------------------------------------------------------------------------------------
    void generateECKeyPairs(final String curveName)
	    throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

	// this is the relation between the two: the named ones are a special case
	final ECNamedCurveParameterSpec namedParameterSpec = ECNamedCurveTable.getParameterSpec(curveName);
	// this is the general set, for almost all (in this representation, that is)
	final ECParameterSpec generalECParameterSpec = new ECNamedCurveSpec(curveName, namedParameterSpec.getCurve(),
		namedParameterSpec.getG(), namedParameterSpec.getN(), namedParameterSpec.getH(),
		namedParameterSpec.getSeed());

	assertNotNull(namedParameterSpec);
	assertNotNull(generalECParameterSpec);

	final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
	kpg.initialize(generalECParameterSpec); // here, both namedParameterSpec and generalECParameterSpec is
						// acceptable.

	final KeyPair keyPairA = kpg.generateKeyPair();
	final KeyPair keyPairB = kpg.generateKeyPair();

	senderPrivateKey = keyPairA.getPrivate();
	senderPublicKey = keyPairA.getPublic();
	recipientPrivateKey = keyPairB.getPrivate();
	recipientPublicKey = keyPairB.getPublic();
    }

    java.security.KeyPair generateRSAKeyPair(int keySize)
	    throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
	final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
	kpg.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
	return kpg.generateKeyPair();
    }

    @BeforeEach
    void init() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
	// generate key pairs for this test. consider them exchanged/in the appropriate
	// places
	generateECKeyPairs(SharedConstants.OID_EC_NAMED_CURVE_SECP256R1.getId());
    }
}
//___EOF___
