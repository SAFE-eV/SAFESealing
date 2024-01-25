/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.safeseal.impl;

import com.metabit.custom.safe.iip.AsymmetricEncryptionWithIIP;
import com.metabit.custom.safe.iip.ECDHEWithIntegrityPadding;
import com.metabit.custom.safe.iip.RSAWithIntegrityPadding;
import com.metabit.custom.safe.iip.shared.AlgorithmSpecCollection;
import com.metabit.custom.safe.iip.shared.CryptoFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.DataLengthException;

import javax.crypto.*;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import static com.metabit.custom.safe.iip.shared.AlgorithmSpecCollection.COMPRESSION_GZIP;
import static com.metabit.custom.safe.iip.shared.AlgorithmSpecCollection.COMPRESSION_NONE;

/**
 * entry point, and coordination class. combines settings and provides combined method calls.
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public class SAFESeal
{
    private TransportFormatConverter  formatConverter;
    private AsymmetricEncryptionWithIIP asymmetricLayer;
    private boolean keyAgreementMode; // flag shorthand for NONE or ECDHE. later versions may use an enum.
    private boolean compressionMode; // flag shorthand for NONE or ZLIB. later versions may use an enum.
    private final CryptoFactory cryptoFactory;

    /**
     * <p>Constructor for SAFESeal.</p>
     *
     * @param cf a {@link CryptoFactory} object
     * @throws NoSuchPaddingException if any.
     * @throws NoSuchAlgorithmException if any.
     * @throws NoSuchProviderException if any.
     * @throws InvalidKeyException if any.
     */
    public SAFESeal(CryptoFactory cf)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
        {
        this.cryptoFactory = cf;
        this.keyAgreementMode = false;
        this.compressionMode = false;
        init();
        }

    /**
     * set key agreement mode.
     * @param keyAgreementUsed for RSA+IIP, set to false.
     */
    public void setKeyAgreementMode(final boolean keyAgreementUsed)
        {
        this.keyAgreementMode = keyAgreementUsed;
        this.compressionMode = false;
        init();
        }

    /**
     * accessor for key agreement mode.
     * @return true if key agreement mode is used, false if not.
     */
    public boolean getKeyAgreementMode() { return keyAgreementMode; }

    private void init()
        {
        formatConverter = new TransportFormatConverter();
        return;
        }

    /**
     * seal contents: perform calculation of ephemeral key, padding, encryption, and formatting for transport.
     *
     * @param contentToSeal payload content for sealed transport
     * @param senderKey     sender private key (caller's key)
     * @param recipientKeys recipient public key(s)
     * @param uniqueID      a unique ID to be provided e.g. from a monotonic counter
     * @return wrapped and sealed message
     * @throws NoSuchProviderException if crypto provider is unavailable
     * @throws NoSuchAlgorithmException if algorithm could not be found
     * @throws NoSuchPaddingException if the padding could not be found
     * @throws BadPaddingException if the padding fails
     * @throws InvalidKeyException if the key is invalid
     * @throws InvalidKeySpecException if the key is invalid
     * @throws IllegalBlockSizeException if key and algorithm don't match in regard to size.
     * @throws IOException if IO errors occur
     * @throws ShortBufferException if target buffer is too small
     */
    public byte[] seal(final byte[] contentToSeal, PrivateKey senderKey, PublicKey[] recipientKeys, final Long uniqueID)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
            IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, IOException, ShortBufferException
        {
        InternalTransportTuple itt;
        if (keyAgreementMode)
            {
            asymmetricLayer = new ECDHEWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.AES256ECB);
            itt = new InternalTransportTuple(true); // ECDHE+AES...
            itt.setDiversification(uniqueID);
            }
        else
            {
            asymmetricLayer = new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA2048);
            itt = new InternalTransportTuple(false); // RSA
            // no diversification needed for direct RSA application
            }

        byte[] payload;
        if (compressionMode == false)
            {
            payload = contentToSeal;
            }
        else // if compression is activated, perform compression and set respective flag
            {
            payload = tryToCompress(contentToSeal, itt);
            }

        // perform asymmetric crypto, symmetric crypto, and padding
        itt.encryptedData = asymmetricLayer.padEncryptAndPackage(payload, recipientKeys, senderKey, itt.getKeyDiversificationData());
        itt.cryptoIV= asymmetricLayer.getSymmetricIV();
        // format the tuple for transport
        return formatConverter.wrapForTransport(itt);
        }




    /**
     * carefully check the sealing, unseal, and return payload data.
     * performs transport unwrapping, calculation of ephemeral key, decryption, and integrity validation.
     * The most important Exception is the BadPaddingException which signals the integrity validation has failed.
     *
     * @param sealedInput an array of {@link byte} objects
     * @param recipientKey a {@link PrivateKey} object
     * @param senderPublicKey a {@link PublicKey} object
     * @return payload data, when everything went OK and the integrity has been validated.
     * @throws BadPaddingException                the integrity validation has failed.
     * @throws NoSuchProviderException if crypto provider is unavailable
     * @throws NoSuchAlgorithmException if algorithm could not be found
     * @throws InvalidAlgorithmParameterException if the algorithm was called with invalid parameters
     * @throws NoSuchPaddingException if the padding could not be found
     * @throws BadPaddingException if the padding fails
     * @throws InvalidKeyException if the key is invalid
     * @throws InvalidKeySpecException if the key is invalid
     * @throws IllegalBlockSizeException if key and algorithm don't match in regard to size.
     * @throws IOException if IO errors occur
     * @throws ShortBufferException if target buffer is too small
     */
    public byte[] reveal(final byte[] sealedInput, PrivateKey recipientKey, PublicKey senderPublicKey) // is one sender public key enough if several were used in sending?
            throws BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException,
            NoSuchProviderException, IOException, ShortBufferException
        {
        InternalTransportTuple tuple = formatConverter.unwrapTransportFormat(sealedInput);

        ASN1ObjectIdentifier compressionOID = tuple.cryptoSettings.getCompressionOID();
        if (compressionOID.equals(COMPRESSION_GZIP.getOID()))
            { compressionMode = true; }
        else if (compressionOID.equals(COMPRESSION_NONE.getOID()))
            { compressionMode = false; } // do nothing, ignore.
        else
            throw new NoSuchAlgorithmException("invalid compression");

        // @IMPROVEMENT for later versions: allow to for a more flexible selection of algorithms,
        if (keyAgreementMode)
            {
            asymmetricLayer = new ECDHEWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.AES256ECB);
            }
        else
            {
            asymmetricLayer = new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA2048);
            }
        try
            {
            byte[] payload = asymmetricLayer.decryptAndVerify(tuple.encryptedData, senderPublicKey, recipientKey, tuple.keyDiversificationData, tuple.cryptoIV);
            if (compressionMode == true)
                {
                payload = inflateZLIBcompressedData(payload);
                }
            return payload;
            }
        catch (ArrayIndexOutOfBoundsException | DataLengthException | DataFormatException ex)
            {
            throw new BadPaddingException();
            }
        }

    /*
     * try to apply ZLIB compression.
     * Important: Zlib wrapper fields must not be used/sent.
     * That also implies we always use the same settings in this context: BEST_COMPRESSION, nowrap.
     * @param rawPayload content to compress
     * @param itt settings, where we'd note the compression algorithm if any.
     * @return payload for further processing (compressed or not)
     * @throws NoSuchAlgorithmException if algorithm lookup fails.
     */
    private static byte[] tryToCompress(final byte[] rawPayload, final InternalTransportTuple itt) throws NoSuchAlgorithmException
        {
        byte[] payload;
        int inputSize = rawPayload.length;
        byte[] tmp = new byte[inputSize];
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION, true); // NB: must set "nowrap"! The header fields are moot, but we may not use checksums.
        deflater.setInput(rawPayload);
        deflater.finish();
        final int outputSize = deflater.deflate(tmp);
        if (outputSize >= inputSize) // in this case, keep original size
            {
            payload = rawPayload;
            itt.cryptoSettings.setCompressionOID(COMPRESSION_NONE.getOID());
            }
        else
            {
            payload = new byte[outputSize];
            System.arraycopy(tmp,0,payload,0,outputSize);
            itt.cryptoSettings.setCompressionOID(COMPRESSION_GZIP.getOID());
            }
        deflater.end();
        return payload;
        }

    /*
     * try to decompress if we've got compressed data.
     * using "nowrap" settings, we have neither header nor checksum.
     * @param payload data to decompress/inflate
     * @return decompressed/inflated data
     * @throws DataFormatException if the data is not matching the expected format
     */
    private byte[] inflateZLIBcompressedData(final byte[] payload) throws DataFormatException
        {
        Inflater inflater = new Inflater(true); // nowrap is important for our use case.
        int inputSize = payload.length;
        // measuring the required input size
        int outputSize;
        int tmpSize = 0;
        do
            {
            tmpSize += inputSize; // try multiple times with increasing buffer size
            inflater.setInput(payload);
            byte[] tmp = new byte[tmpSize]; // heuristics here.
            outputSize = inflater.inflate(tmp);
            if (outputSize == 0)
                throw new IllegalArgumentException("input compression level not handled");
            inflater.reset();
            }
        while (tmpSize==outputSize); // if the temp buffer was completely full, we need to try again with a larger buffer.

        // now performing actual decompression
        byte[] result = new byte[outputSize];
        inflater.setInput(payload);
        inflater.inflate(result);
        inflater.end();
        return result;
        }
    public void setCompressionMode(final boolean compressionMode)
        {  this.compressionMode = compressionMode; }

    public boolean getCompressionMode()
        { return compressionMode; }
}
//___EOF___

