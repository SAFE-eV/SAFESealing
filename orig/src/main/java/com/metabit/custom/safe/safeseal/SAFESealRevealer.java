/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.safeseal;

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
    private final boolean keyAgreement;
    private Provider securityProvider;
    private final CryptoFactoryImpl cryptoFactory;

    /**
     * constructor with default algorithm setup.
     *
     * @param useKeyAgreement true if ECDHE key agreement is to be used, false for RSA+IIP
     */
    public SAFESealRevealer(boolean useKeyAgreement)
        {
        this.keyAgreement = useKeyAgreement;
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
            SAFESeal revealer = new SAFESeal(cryptoFactory);
            revealer.setKeyAgreementMode(keyAgreement);
            return revealer.reveal(sealedMessage, recipientPrivateKey, singleSenderPublicKey);
            }
        catch (InvalidAlgorithmParameterException | IllegalBlockSizeException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException |
               NoSuchPaddingException | ShortBufferException | IllegalArgumentException | IOException | NoSuchProviderException e)
            {
            throw new BadPaddingException(); // hiding the specific exception to prevent "padding oracle" type attacks, and simplify usage.
            }
        }




}
//___EOF___
