/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.iip;

import com.metabit.custom.safe.iip.shared.AlgorithmSpec;
import com.metabit.custom.safe.iip.shared.CryptoFactory;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * <p>ECDHEWithIntegrityPadding class.</p>
 * Performs IIP with symmetric keys derived from an ECDHE procedure.
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public class ECDHEWithIntegrityPadding implements AsymmetricEncryptionWithIIP
{
    private final CryptoFactory cf;
    private final AlgorithmSpec algorithmSpec;
    private SecureRandom rng;
    private KeyAgreement keyAgreement;
    private SymmetricEncryptionWithIntegrityPadding symmetricEncryption;

    
    /**
     * default constructor
     *
     * @throws java.security.NoSuchAlgorithmException if any.
     * @throws java.security.NoSuchProviderException if any.
     * @throws javax.crypto.NoSuchPaddingException if any.
     * @throws java.security.InvalidKeyException if any.
     */
/*
    public ECDHEWithIntegrityPadding()
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException
        {
        if (Security.getProvider("BC") == null)
            Security.addProvider(new BouncyCastleProvider());
        init(Security.getProvider("BC"));
        }
    */

    /**
     * constructor for ECDHE IIP
     * @param cryptoFactory cryptoFactory handle for JCE and algorithm lookup/instantiation
     * @param spec (symmetric) encryption algorithm to be used
     * @throws NoSuchAlgorithmException if algorithm lookup failed
     * @throws NoSuchProviderException if crypto provider was not available
     * @throws NoSuchPaddingException if padding or operation mode of cipher was not available
     * @throws InvalidKeyException if a key was invalid (unlikely)
     */
    public ECDHEWithIntegrityPadding(final CryptoFactory cryptoFactory, final AlgorithmSpec spec)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException
        {
        this.cf = cryptoFactory;
        this.algorithmSpec = spec;
        this.rng = new SecureRandom();
        this.keyAgreement = KeyAgreement.getInstance("ECDH"); // default key agreement
        // Cipher symmetricCipher = Cipher.getInstance("AES/ECB/NoPadding"); // default cipher
        Cipher symmetricCipher = cryptoFactory.getCipherFromCipherSpec(spec);
        symmetricEncryption = new SymmetricEncryptionWithIntegrityPadding(symmetricCipher,cryptoFactory); // default cipher spec
        }

    
    /**
     * create the ephemeral symmetric key, for AES, given a single recipient
     * @param otherSideECPublicKey public key of the recipient
     * @param ourECPrivateKey private key of the sender
     * @param uniqueID unique ID as key diversification
     * @return ephemeral secret key
     * @throws InvalidKeyException on invalid key inputs
     * @throws NoSuchAlgorithmException if algorithm is not available
     * @throws InvalidKeySpecException should no installed key generator want to generate our ephemeral key
     */
    SecretKey createEphemeralAESKey(final PublicKey otherSideECPublicKey, final PrivateKey ourECPrivateKey, final byte[] uniqueID)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException
        {
        keyAgreement.init(ourECPrivateKey);
        keyAgreement.doPhase(otherSideECPublicKey,true); // just a two-sided DH
        
        // this is where we use SHA for key derivation. It is *not* related to the input data in any way!
        //@TODO delegate to CryptoFactory
        MessageDigest kdf = MessageDigest.getInstance("SHA-256"); // SHA-512 would produce 64 byte keys instead.
        kdf.update(uniqueID);
        kdf.update(keyAgreement.generateSecret());
        //@TODO improvement variable size of AES key
        // kdf.digest(); will provide now 64 bytes since it is SHA-512. AES can take only 16, 24, 32 byte for 128, 192, 256 bit keys.
        // we would need to cut "n"byte out of the hash result here depending on the AES size specified.
        SecretKeySpec secretKeySpec = new SecretKeySpec(kdf.digest(), "AES"); // prepare the key input
        SecretKey ephKey = SecretKeyFactory.getInstance("AES").generateSecret(secretKeySpec); // and turn it into an AES key
        return ephKey;
        }
    
    
    // same as above, but for multiple recipients.
    SecretKey createEphemeralAESKey(final PublicKey[] multipleRecipientKeys, final PrivateKey ourECPrivateKey, final byte[] uniqueID)
            throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException
        {
        keyAgreement.init(ourECPrivateKey);
        for (PublicKey publicKey: multipleRecipientKeys)
            keyAgreement.doPhase(publicKey,true); // multi-recipient DH.
       
        // this is where we use SHA, for key derivation. It is *not* related to the input data in any way!
        //@TODO delegate to CryptoFactory
        MessageDigest kdf = MessageDigest.getInstance("SHA-256"); // SHA-512 would produce 64 byte keys instead.
        kdf.update(uniqueID);
        kdf.update(keyAgreement.generateSecret());
        //@TODO improvement variable size of AES key
        // kdf.digest(); will provide now 64 bytes since it is SHA-512. AES can take only 16, 24, 32 byte for 128, 192, 256 bit keys.
        // we would need to cut "n"byte out of the hash result here depending on the AES size specified.
        SecretKeySpec secretKeySpec = new SecretKeySpec(kdf.digest(), "AES"); // prepare the key input
        SecretKey ephKey = SecretKeyFactory.getInstance("AES").generateSecret(secretKeySpec); // and turn it into an AES key
        return ephKey;
        }
    
    
    /**
     * {@inheritDoc}
     *
     * perform the entire scheme: ephemeral key generation, pad, encrypt, package/wrap so the result is ready for transport.
     */
    @Override
    public byte[] padEncryptAndPackage(final byte[] data, final PublicKey otherSideECPublicKey, final PrivateKey ourECPrivateKey, final byte[] keyDiversification)
            throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
                   DestroyFailedException, InvalidKeySpecException
        {
        // derive symmetric ephemeral key
        SecretKey ephemeralKey = createEphemeralAESKey(otherSideECPublicKey, ourECPrivateKey, keyDiversification);
        // pad+encrypt content
        byte[] rawEncrypted = symmetricEncryption.padAndEncrypt(data, ephemeralKey);
        return rawEncrypted;
        }
    
    // variant with multiple recipients
    /** {@inheritDoc} */
    @Override public byte[] padEncryptAndPackage(byte[] contentToSeal, PublicKey[] recipientKeys, PrivateKey senderKey, byte[] keyDiversificationForEC)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException,
                   BadPaddingException
        {
        SecretKey ephemeralKey = createEphemeralAESKey(recipientKeys, senderKey, keyDiversificationForEC);
        // pad+encrypt content
        byte[] rawEncrypted = symmetricEncryption.padAndEncrypt(contentToSeal, ephemeralKey);
        // clear ephemeral key from memory where applicable
        // ephemeralKey.destroy();
        return rawEncrypted;
        }

    
    /** {@inheritDoc} */
    @Override
    public byte[] decryptAndVerify(final byte[] encryptedData, final PublicKey otherSideECPublicKey, final PrivateKey ourECPrivateKey, final byte[] keyDiversificationForEC, final byte[] ivForSymmetricCrypto)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
                   InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
        {
        // derive symmetric ephemeral key
        SecretKey ephemeralKey = createEphemeralAESKey(otherSideECPublicKey, ourECPrivateKey, keyDiversificationForEC);
        // perform symmetric decryption and padding integrity checks.
        byte[] decrypted = symmetricEncryption.decryptAndCheck(encryptedData, ephemeralKey, ivForSymmetricCrypto);
        // not replacing the data in ids here since there's nothing to protect
        return decrypted;
        }
    
    /** {@inheritDoc} */
    @Override public byte[] getSymmetricIV()
        {
        return symmetricEncryption.getIV();
        }
    
}
//___EOF___
