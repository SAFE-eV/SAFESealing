/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.safeseal;

import com.metabit.custom.safe.iip2.SAFESeal2;
import com.metabit.custom.safe.safeseal.impl.CryptoFactoryImpl;
import com.metabit.custom.safe.safeseal.impl.SAFESeal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * facade for sealing OCMF messages in encrypted messages, according to SAFE e.V. specifications.
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public class SAFESealSealer
{
    private CryptoFactoryImpl cryptoFactory;
    private Provider securityProvider;
    private boolean compressionMode;
    private int     version;

    /** default constructor (recommended) */
    public SAFESealSealer()
        {
        this.version = 2;
        init();
        }

    /**
     * constructor.
     *
     * @param version algorithm version to use.
     *                1 for UUP with RSA
     *                2 for IPS with RSA and triple AES
     */
    public SAFESealSealer(final int version)
        {
        this.version = version;
        init();
        }

    /**
     * activate or deactivate content compression mode. default: off
     * @param flag false to turn off, true to turn on. default: off.
     */
    public void setCompressionMode(boolean flag)    { this.compressionMode = flag; }

    // initialise crypto environment
    private void init()
        {
        securityProvider = Security.getProvider("BC");
        if (securityProvider == null)
            {
            securityProvider = new BouncyCastleProvider();
            Security.addProvider(securityProvider);
            }
        this.cryptoFactory = new CryptoFactoryImpl(securityProvider);
        return;
        }

    /**
     * seal for multiple recipients. Not available in version 1.
     * For use with key agreement protocol.
     *
     * @param rawPrivateKeySender an array of {@link byte} objects
     * @param rawPublicKeySingleRecipient an array of {@link byte} objects
     * @param uniqueID a {@link java.lang.Long} object
     * @param payloadToSeal an array of {@link byte} objects
     * @return an array of {@link byte} objects
     * @throws javax.crypto.BadPaddingException if any.
     */
    public byte[] seal(final byte[] rawPrivateKeySender, byte[] rawPublicKeySingleRecipient, final Long uniqueID, final byte[] payloadToSeal)
            throws BadPaddingException
        {
        throw new UnsupportedOperationException();
        }


    /**
     * seal a payload, encrypting and protecting it for transport.
     *
     * @param senderPrivateKey         private key of the sender
     * @param singleRecipientPublicKey public key of the single recipient
     * @param payloadToSeal            the payload data to be sealed for transport
     * @param uniqueID                 an unique ID assigned to this message. (monotonic counter or similar source recommended.
     * @return sealed message
     * @throws javax.crypto.BadPaddingException     if the sealing failed
     */
    public final byte[] seal(final PrivateKey senderPrivateKey, final PublicKey singleRecipientPublicKey, final byte[] payloadToSeal, final Long uniqueID)
            throws BadPaddingException
        {
        try
            {
            switch (version)
                {
                case 0:
                    return seal0(senderPrivateKey, singleRecipientPublicKey, payloadToSeal, uniqueID);
                case 1:
                    return seal1(senderPrivateKey, singleRecipientPublicKey, payloadToSeal, uniqueID);
                case 2:
                    return seal2(senderPrivateKey, singleRecipientPublicKey, payloadToSeal, uniqueID);
                default:
                    throw new UnsupportedOperationException("version not supported");
                }
            }
        catch (NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException |
               ShortBufferException | NoSuchProviderException | IOException e)
            {
            throw new RuntimeException(e);
            }
        catch (InvalidAlgorithmParameterException e)
            {
            throw new RuntimeException(e);
            }
        }

    private byte[] seal2(PrivateKey senderPrivateKey, PublicKey singleRecipientPublicKey, byte[] payloadToSeal, Long uniqueID)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, ShortBufferException,
            InvalidKeySpecException, BadPaddingException, IOException
        {
        SAFESeal2 sealer = new SAFESeal2(cryptoFactory, 2, 0);
        sealer.setCompressionMode(compressionMode);
        PublicKey[] publicKeys = new PublicKey[1];
        publicKeys[0] = singleRecipientPublicKey;
        byte[] payload = sealer.seal(payloadToSeal, senderPrivateKey, publicKeys, uniqueID);
        return payload;
        }

    private byte[] seal1(PrivateKey senderPrivateKey, PublicKey singleRecipientPublicKey, byte[] payloadToSeal, Long uniqueID)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, IOException,
            ShortBufferException
        {
        SAFESeal sealer = new SAFESeal(cryptoFactory);
        sealer.setKeyAgreementMode(false);
        sealer.setCompressionMode(compressionMode);
        PublicKey[] publicKeys = new PublicKey[1];
        publicKeys[0] = singleRecipientPublicKey;
        byte[] payload = sealer.seal(payloadToSeal, senderPrivateKey, publicKeys, uniqueID);
        return payload;
        }

    private byte[] seal0(PrivateKey senderPrivateKey, PublicKey singleRecipientPublicKey, byte[] payloadToSeal, Long uniqueID)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, IOException,
            ShortBufferException
        {
        SAFESeal sealer = new SAFESeal(cryptoFactory);
        sealer.setKeyAgreementMode(true);
        sealer.setCompressionMode(compressionMode);
        PublicKey[] publicKeys = new PublicKey[1];
        publicKeys[0] = singleRecipientPublicKey;
        byte[] payload = sealer.seal(payloadToSeal, senderPrivateKey, publicKeys, uniqueID);
        return payload;
        }
}
//___EOF___

