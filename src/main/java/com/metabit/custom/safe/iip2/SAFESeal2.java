/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.iip2;

import com.metabit.custom.safe.iip.AsymmetricEncryptionWithIIP;
import com.metabit.custom.safe.iip.RSAWithIntegrityPadding;
import com.metabit.custom.safe.iip.shared.AlgorithmSpecCollection;
import com.metabit.custom.safe.iip.shared.CryptoFactory;
import com.metabit.custom.safe.safeseal.impl.CryptoSettingsStruct;
import com.metabit.custom.safe.safeseal.impl.InternalTransportTuple;
import com.metabit.custom.safe.safeseal.impl.TransportFormatConverter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.crypto.DataLengthException;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
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
public class SAFESeal2
{
    private final CryptoFactory               cryptoFactory;
    private       TransportFormatConverter    formatConverter;
    private       AsymmetricEncryptionWithIIP asymmetricLayer;
    private       boolean                     compressionMode; // flag shorthand for NONE or ZLIB. later versions may use an enum.
    private       CryptoSettingsStruct        css;

    /**
     * <p>Constructor for SAFESeal2.</p>
     *
     * @param cf a {@link CryptoFactory} object
     * @param version algorithm version to use.
     *                1 for UUP with RSA
     *                2 for IPS with RSA and triple AES
     * @param revision revision number, in case there will be variants. default 0.
     * @throws NoSuchPaddingException   if any.
     * @throws NoSuchAlgorithmException if any.
     * @throws NoSuchProviderException  if any.
     * @throws InvalidKeyException      if any.
     */
    public SAFESeal2(CryptoFactory cf, final int version, final int revision)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
        {
        this.cryptoFactory = cf;
        this.compressionMode = false;
        init(version, revision);
        }

    public boolean getCompressionMode()
        { return compressionMode; }

    public void setCompressionMode(final boolean compressionMode)
        { this.compressionMode = compressionMode; }

    /*
     * try to apply ZLIB compression.
     * Important: Zlib wrapper fields must not be used/sent.
     * That also implies we always use the same settings in this context: BEST_COMPRESSION, nowrap.
     * @param rawPayload content to compress
     * @param itt settings, where we'd note the compression algorithm if any.
     * @return payload for further processing (compressed or not)
     * @throws NoSuchAlgorithmException if algorithm lookup fails.
     */
    private static byte[] tryToCompress(final byte[] rawPayload, final InternalTransportTuple itt)
            throws NoSuchAlgorithmException
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
            itt.getCryptoSettings().setCompressionOID(COMPRESSION_NONE.getOID());
            }
        else
            {
            payload = new byte[outputSize];
            System.arraycopy(tmp, 0, payload, 0, outputSize);
            itt.getCryptoSettings().setCompressionOID(COMPRESSION_GZIP.getOID());
            }
        deflater.end();
        return payload;
        }


    private void init(int version, int revision)
        {
        formatConverter = new TransportFormatConverter();
        css = new CryptoSettingsStruct(version, revision);
        //@TODO use version, revision for code separation - version 1 for original SAFESeal
        return;
        }

    /**
     * Seal V2
     * seal contents: perform calculation of ephemeral key, padding, encryption, and formatting for transport.
     *
     * Ephemeral keys (usually symmetric keys) are automatically generated and used.
     *
     * @param contentToSeal payload content for sealed transport
     * @param senderKey     sender private key (caller's key)
     * @param recipientKeys recipient public key(s)
     * @param uniqueID      a unique ID to be provided e.g. from a monotonic counter
     * @return wrapped and sealed message
     *
     * @throws NoSuchProviderException   if crypto provider is unavailable
     * @throws NoSuchAlgorithmException  if algorithm could not be found
     * @throws NoSuchPaddingException    if the padding could not be found
     * @throws BadPaddingException       if the padding fails
     * @throws InvalidKeyException       if the key is invalid
     * @throws InvalidKeySpecException   if the key is invalid
     * @throws IOException               if IO errors occur
     * @throws ShortBufferException      if target buffer is too small
     * @throws IllegalBlockSizeException implementation issue
     * @throws InvalidAlgorithmParameterException   implementation issue
     */
    public byte[] seal(final byte[] contentToSeal, PrivateKey senderKey, PublicKey[] recipientKeys, final Long uniqueID)
            throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
            IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, IOException, ShortBufferException, InvalidAlgorithmParameterException
        {
        InternalTransportTuple itt;
        // lacking a proper API, we do this the factual way:
        final String description = senderKey.toString();
        final int privateKeyLength = SharedCode.getRSAPrivateKeyLengthInBits(description);
        switch (privateKeyLength)
            {
            case 1024:
                asymmetricLayer = new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA1024);
                break;
            case 2048:
                asymmetricLayer = new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA2048);
                break;
            case 4096:
                asymmetricLayer = new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA4096);
                break;
            default:
                throw new InvalidKeySpecException("key of unsupported size "+privateKeyLength);
            }
        itt = new InternalTransportTuple(new CryptoSettingsStruct(2, 0)); // RSA
        itt.getCryptoSettings().setEncryptionKeySize(privateKeyLength);

        //@TODO get this via CF from algorithm
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey key1 = keyGenerator.generateKey();
        SecretKey key2 = keyGenerator.generateKey();
        SecretKey key3 = keyGenerator.generateKey();

        itt.setEphemeralSymmetricKeyBytes(key1.getEncoded(), key2.getEncoded(), key3.getEncoded());

        // @TODO improve here
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
        //@TODO we need to use the IntegratedAlgorithm2_1 here instead.
        IntegrityPaddingSignature iip2 = new IntegrityPaddingSignature(cryptoFactory, css);
        byte[] encryptedData = iip2.performEncryption(payload, senderKey, key1, key2, key3);
        // old style! calling old code. byte[] encryptedData = asymmetricLayer.padEncryptAndPackage(payload, recipientKeys, senderKey, itt.getKeyDiversificationData());
        itt.setEncryptedData(encryptedData);
        // format the tuple for transport
        return formatConverter.wrapForTransport(itt);
        }

    /**
     * carefully check the sealing, unseal, and return payload data.
     * performs transport unwrapping, calculation of ephemeral key, decryption, and integrity validation.
     * The most important Exception is the BadPaddingException which signals the integrity validation has failed.
     *
     * @param sealedInput     an array of {@link byte} objects
     * @param recipientKey    a {@link PrivateKey} object
     * @param senderPublicKey a {@link PublicKey} object
     * @return payload data, when everything went OK and the integrity has been validated.
     *
     * @throws BadPaddingException                the integrity validation has failed.
     * @throws NoSuchProviderException            if crypto provider is unavailable
     * @throws NoSuchAlgorithmException           if algorithm could not be found
     * @throws InvalidAlgorithmParameterException if the algorithm was called with invalid parameters
     * @throws NoSuchPaddingException             if the padding could not be found
     * @throws BadPaddingException                if the padding fails
     * @throws InvalidKeyException                if the key is invalid
     * @throws InvalidKeySpecException            if the key is invalid
     * @throws IllegalBlockSizeException          if key and algorithm don't match in regard to size.
     * @throws IOException                        if IO errors occur
     * @throws ShortBufferException               if target buffer is too small
     */
    public byte[] reveal(final byte[] sealedInput, PrivateKey recipientKey, PublicKey senderPublicKey) // is one sender public key enough if several were used in sending?
            throws BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
            NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException,
            NoSuchProviderException, IOException, ShortBufferException
        {
        InternalTransportTuple tuple = formatConverter.unwrapTransportFormat(sealedInput);
        // check whether the ephemeral keys 1,2,3 are present.
        if ((tuple.getEphemeralSymmetricKeyBytes(1) == null) || (tuple.getEphemeralSymmetricKeyBytes(2) == null) || (tuple.getEphemeralSymmetricKeyBytes(3) == null))
            throw new IllegalArgumentException("ephemeral keys required for algorithm version 2");

        ASN1ObjectIdentifier compressionOID = tuple.getCryptoSettings().getCompressionOID();
        if (compressionOID.equals(COMPRESSION_GZIP.getOID()))
            { compressionMode = true; }
        else if (compressionOID.equals(COMPRESSION_NONE.getOID()))
            { compressionMode = false; } // do nothing, ignore.
        else
            throw new NoSuchAlgorithmException("invalid compression");

        // @IMPROVEMENT for later versions: allow to for a more flexible selection of algorithms.
        switch (tuple.getCryptoSettings().getEncryptionKeySize())
            {
            case 1024:
                asymmetricLayer = new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA1024);
                break;
            case 2048:
                asymmetricLayer = new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA2048);
                break;
            case 4096:
                asymmetricLayer = new RSAWithIntegrityPadding(cryptoFactory, AlgorithmSpecCollection.RSA4096);
                break;
            default:
                throw new InvalidKeyException("specified key size not supported");
            }

        try
            {
            IntegrityPaddingSignature cipherInstance = new IntegrityPaddingSignature(cryptoFactory, css);

            SecretKey key1 = new SecretKeySpec(tuple.getEphemeralSymmetricKeyBytes(1), 0, 16, "AES");
            SecretKey key2 = new SecretKeySpec(tuple.getEphemeralSymmetricKeyBytes(2), 0, 16, "AES");
            SecretKey key3 = new SecretKeySpec(tuple.getEphemeralSymmetricKeyBytes(3), 0, 16, "AES");

            byte[] payload = cipherInstance.performDecryptionAndValidation(tuple.getEncryptedData(), senderPublicKey, key1, key2, key3);
            if (compressionMode == true)
                {
                payload = inflateZLIBcompressedData(payload);
                }
            return payload;
            }
        catch (ArrayIndexOutOfBoundsException|DataLengthException|DataFormatException ex)
            {
            throw new BadPaddingException();
            }
        }

    /*
     * try to decompress if we've got compressed data.
     * using "nowrap" settings, we have neither header nor checksum.
     * @param payload data to decompress/inflate
     * @return decompressed/inflated data
     * @throws DataFormatException if the data is not matching the expected format
     */
    private byte[] inflateZLIBcompressedData(final byte[] payload)
            throws DataFormatException
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
        while (tmpSize == outputSize); // if the temp buffer was completely full, we need to try again with a larger buffer.

        // now performing actual decompression
        byte[] result = new byte[outputSize];
        inflater.setInput(payload);
        inflater.inflate(result);
        inflater.end();
        return result;
        }


}
//___EOF___

