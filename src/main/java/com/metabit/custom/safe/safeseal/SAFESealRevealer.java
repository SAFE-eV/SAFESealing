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
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * facade for validating (and extracting) sealed OCMF message according to SAFE e.V. specification
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public class SAFESealRevealer
{
    private final int version;
    private Provider securityProvider;
    private final CryptoFactoryImpl cryptoFactory;

    /**
     * constructor with default algorithm setup.
     *
     * @param version 0 for ECDHE experiment, 1 for IIP v1 (RSA/IIP), 2 for IIP v2 (RSA,AES,IIP2).
     */
    public SAFESealRevealer(final int version)
        {
        this.version = version;
        securityProvider = Security.getProvider("BC");
        if (securityProvider == null)
            {
            securityProvider = new BouncyCastleProvider();
            Security.addProvider(securityProvider);
            }
        this.cryptoFactory = new CryptoFactoryImpl(securityProvider);
        }

    /**
     * <p>reveal.</p>
     *
     * @param rawPublicKeySingleSender an array of {@link byte} objects
     * @param rawPrivateKeyRecipient an array of {@link byte} objects
     * @param sealedMessage an array of {@link byte} objects
     * @return an array of {@link byte} objects
     * @throws javax.crypto.BadPaddingException if any.
     */
    public byte[] reveal(byte[] rawPublicKeySingleSender, final byte[] rawPrivateKeyRecipient, final byte[] sealedMessage) throws BadPaddingException
        {
        // todo perform deterministic conversion from bytearrays to keys.
        // then call the "real" function
        throw new UnsupportedOperationException();
        }


    /**
     * reveal the validated contents of the sealed message.
     *
     * @param singleSenderPublicKey the public key of the sender
     *                              // additional public keys of different recipients are possible.
     * @param recipientPrivateKey   the private key of the recipient
     * @param sealedMessage         the sealed message
     * @return validated payload data which was sealed
     * @throws javax.crypto.BadPaddingException if processing failed in some way, especially if the seal was not intact anymore.
     *                             This
     */
    public final byte[] reveal(final PublicKey singleSenderPublicKey, final PrivateKey recipientPrivateKey, final byte[] sealedMessage)
            throws BadPaddingException
        {
        try
            {
            switch (version)
                {
                default:
                    throw new UnsupportedOperationException("version not supported");
                case 0:
                    return reveal0(singleSenderPublicKey, recipientPrivateKey, sealedMessage);
                case 1:
                    return reveal1(singleSenderPublicKey, recipientPrivateKey, sealedMessage);
                case 2:
                    return reveal2(singleSenderPublicKey, recipientPrivateKey, sealedMessage);
                }

            }
        catch (InvalidAlgorithmParameterException | IllegalBlockSizeException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException |
               NoSuchPaddingException | ShortBufferException | IllegalArgumentException | IOException | NoSuchProviderException e)
            {
            throw new BadPaddingException(); // hiding the specific exception to prevent "padding oracle" type attacks, and simplify usage.
            }
        }

    private byte[] reveal2(PublicKey singleSenderPublicKey, PrivateKey recipientPrivateKey, byte[] sealedMessage)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, ShortBufferException,
            BadPaddingException, InvalidKeySpecException, IOException
        {

        SAFESeal2 revealer = new SAFESeal2(cryptoFactory, 2, 0);
        return revealer.reveal(sealedMessage, recipientPrivateKey, singleSenderPublicKey);
        }

    private byte[] reveal1(PublicKey singleSenderPublicKey, PrivateKey recipientPrivateKey, byte[] sealedMessage)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            InvalidKeySpecException, IOException, ShortBufferException
        {
        SAFESeal revealer = new SAFESeal(cryptoFactory);
        revealer.setKeyAgreementMode(false);
        return revealer.reveal(sealedMessage, recipientPrivateKey, singleSenderPublicKey);
        }

    private byte[] reveal0(PublicKey singleSenderPublicKey, PrivateKey recipientPrivateKey, byte[] sealedMessage)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            InvalidKeySpecException, IOException, ShortBufferException
        {
        SAFESeal revealer = new SAFESeal(cryptoFactory);
        revealer.setKeyAgreementMode(true);
        return revealer.reveal(sealedMessage, recipientPrivateKey, singleSenderPublicKey);
        }
}
//___EOF___
