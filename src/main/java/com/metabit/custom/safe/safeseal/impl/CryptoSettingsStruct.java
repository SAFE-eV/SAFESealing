/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.safeseal.impl;

import com.metabit.custom.safe.iip.shared.AlgorithmSpec;
import com.metabit.custom.safe.iip.shared.AlgorithmSpecCollection;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.security.NoSuchAlgorithmException;


/**
 * handling object for cryptographic objects in the SAFEsealing implementation.
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public final class CryptoSettingsStruct
{
    private AlgorithmSpec encryption;
    private AlgorithmSpec padding;
    private AlgorithmSpec compression;
    private AlgorithmSpec sig1Algorithm;
    private AlgorithmSpec keyAgreementProtocol;
    private AlgorithmSpec keyAgreementCipher;
    private AlgorithmSpec keyDiversificationAlgorithm;
    private int           encryptionKeySize;
    private int           protocolVersion;


    /**
     * constructor for the defined use cases, initializing with default values.
     *
     * @param withKeyAgreement when false, RSA 2048 with IIP; RSA/ECB/NoPadding+IIP at 2048 bit.
     *                         when true, ECDHE with secp256r1 and AES/CBC 256 bit.
     * deprecated replaced by constructor with version+revision number.
     */
    /*
    @Deprecated
    public CryptoSettingsStruct(boolean withKeyAgreement)
        {
        if (withKeyAgreement)
            {
            compression = AlgorithmSpecCollection.COMPRESSION_NONE;
            padding = AlgorithmSpecCollection.IIP;
            encryption = AlgorithmSpecCollection.AES256CBC_PADDED;
            // for deriving the symmetric ephemeral key, we need this for ECHDE
            keyAgreementProtocol = AlgorithmSpecCollection.ECDH;
            keyAgreementCipher = AlgorithmSpecCollection.ECSECP256R1;
            keyDiversificationAlgorithm = AlgorithmSpecCollection.SHA256;
            encryptionKeySize = encryption.getKeySizeInBit();
            }
        else
            {
            compression = AlgorithmSpecCollection.COMPRESSION_NONE;
            padding = AlgorithmSpecCollection.IIP;
            encryption = AlgorithmSpecCollection.RSA2048;
            encryptionKeySize = encryption.getKeySizeInBit();
            keyAgreementProtocol = null;
            keyAgreementCipher = null;
            keyDiversificationAlgorithm = null;
            }
        return;
        }
    */

    /**
     * fully parameterized constructor.
     * @param version                   version specified
     * @param keyAgreementProtocolToUse Key Agreement protocol. currently supported: null, ECDH
     * @param keyAgreementCipherToUse   cipher to use in key agreemnet. currently supported: some EC curves  @TODO list/reference
     * @param keyDiversificationToUse   key diversification algorithm. currently supported: SHA-256, SHA-512
     * @param encryptionToUse           encryption to use. with key agreement, this should be symmetric (AES-256); without, this should be asymmetric (RSA-2048).
     * @param sig1Algorithm             symmetric algorithm; we expect AES-CBC
     * @param compressionUsed           indicator for recipient whether sender used some compression on the content. Implementation just passes this on, it is not performed here.
     */
    public CryptoSettingsStruct(int version, AlgorithmSpec keyAgreementProtocolToUse, AlgorithmSpec keyAgreementCipherToUse, AlgorithmSpec keyDiversificationToUse, AlgorithmSpec encryptionToUse, AlgorithmSpec sig1Algorithm, AlgorithmSpec compressionUsed)
        {
        this.protocolVersion = version;
        compression = compressionUsed;
        padding = AlgorithmSpecCollection.IIP;
        encryption = encryptionToUse;
        keyDiversificationAlgorithm = keyDiversificationToUse;
        keyAgreementCipher = keyAgreementCipherToUse;
        keyAgreementProtocol = keyAgreementProtocolToUse;
        this.sig1Algorithm = sig1Algorithm;
        }

    /**
     * constructor initializing according to version specified.
     *
     * @param version version of the algorithm to use
     *                 1 for UUP with RSA
     *                 2 for IPS with RSA and triple AES
     * @param revision optional revision for variants within a version
     */
    public CryptoSettingsStruct(int version, int revision)
        {
        switch (version)
            {
            default:
                throw new UnsupportedOperationException("revision not supported");
            case 0:
                switch (revision)
                    {
                    default:
                        throw new UnsupportedOperationException("revision not supported");
                    case 9: // 0.9 to keep ECDHE*AES available for testing.
                    {
                    compression = AlgorithmSpecCollection.COMPRESSION_NONE;
                    padding = AlgorithmSpecCollection.IIP;
                    encryption = AlgorithmSpecCollection.AES256CBC_PADDED;
                    // for deriving the symmetric ephemeral key, we need this for ECHDE
                    keyAgreementProtocol = AlgorithmSpecCollection.ECDH;
                    keyAgreementCipher = AlgorithmSpecCollection.ECSECP256R1;
                    keyDiversificationAlgorithm = AlgorithmSpecCollection.SHA256;
                    encryptionKeySize = encryption.getKeySizeInBit();
                    sig1Algorithm = null;
                    }
                    }
                break;
            case 1:
                switch (revision)
                    {
                    default:
                        throw new UnsupportedOperationException("revision not supported");
                    case 0: // 1.0, the first published version
                    {
                    compression = AlgorithmSpecCollection.COMPRESSION_NONE;
                    padding = AlgorithmSpecCollection.IIP;
                    encryption = AlgorithmSpecCollection.RSA2048;
                    encryptionKeySize = encryption.getKeySizeInBit();
                    sig1Algorithm = null;
                    keyAgreementProtocol = null;
                    keyAgreementCipher = null;
                    keyDiversificationAlgorithm = null;
                    }
                    break;
                    case 1: // 1.1, activating compression
                    {
                    compression = AlgorithmSpecCollection.COMPRESSION_GZIP;
                    padding = AlgorithmSpecCollection.IIP;
                    encryption = AlgorithmSpecCollection.RSA2048;
                    encryptionKeySize = encryption.getKeySizeInBit();
                    sig1Algorithm = null;
                    keyAgreementProtocol = null;
                    keyAgreementCipher = null;
                    keyDiversificationAlgorithm = null;
                    }
                    break;
                    }
            case 2:
                switch (revision)
                    {
                    default:
                        throw new UnsupportedOperationException("revision not supported");
                    case 0:
                    case 1:
                    {
                    compression = AlgorithmSpecCollection.COMPRESSION_NONE;
                    padding = AlgorithmSpecCollection.IIP2;
                    encryption = AlgorithmSpecCollection.RSA2048;
                    encryptionKeySize = encryption.getKeySizeInBit();
                    sig1Algorithm = AlgorithmSpecCollection.AES256CBC; // without padding
                    keyAgreementProtocol = null;
                    keyAgreementCipher = null;
                    keyDiversificationAlgorithm = null;
                    }
                    break;
                    }
            }
        this.protocolVersion = version;
        return;
        }

    /**
     * <p>Getter for the field <code>keyAgreementProtocol</code>.</p>
     *
     * @return a {@link AlgorithmSpec} object
     */
    public AlgorithmSpec getKeyAgreementProtocol() { return keyAgreementProtocol; }

    /**
     * <p>getKeyAgreementProtocolOID.</p>
     *
     * @return a {@link ASN1ObjectIdentifier} object
     */
    public ASN1ObjectIdentifier getKeyAgreementProtocolOID() { return (keyAgreementProtocol != null) ? keyAgreementProtocol.getOID() : null; }

    /**
     * <p>Getter for the field <code>keyAgreementCipher</code>.</p>
     *
     * @return a {@link AlgorithmSpec} object
     */
    public AlgorithmSpec getKeyAgreementCipher() { return keyAgreementCipher; }

    /**
     * <p>getKeyAgreementCipherOID.</p>
     *
     * @return a {@link ASN1ObjectIdentifier} object
     */
    public ASN1ObjectIdentifier getKeyAgreementCipherOID() { return (keyAgreementCipher != null) ? keyAgreementCipher.getOID() : null; }

    void setKeyAgreementCipherOID(final ASN1ObjectIdentifier oid)
            throws NoSuchAlgorithmException
        { keyAgreementCipher = lookupValidatedByOID(oid, AlgorithmSpec.Type.ELLIPTIC_CURVE); }

    /**
     * <p>Getter for the field <code>keyDiversificationAlgorithm</code>.</p>
     *
     * @return a {@link AlgorithmSpec} object
     */
    public AlgorithmSpec getKeyDiversificationAlgorithm() { return keyDiversificationAlgorithm; }

    /**
     * <p>getKeyDiversificationOID.</p>
     *
     * @return a {@link ASN1ObjectIdentifier} object
     */
    public ASN1ObjectIdentifier getKeyDiversificationOID() { return (keyDiversificationAlgorithm != null) ? keyDiversificationAlgorithm.getOID() : null; }

    void setKeyDiversificationOID(final ASN1ObjectIdentifier oid)
            throws NoSuchAlgorithmException
        { keyDiversificationAlgorithm = lookupValidatedByOID(oid, AlgorithmSpec.Type.DIGEST); }

    /**
     * <p>Getter for the field <code>encryption</code>.</p>
     *
     * @return a {@link AlgorithmSpec} object
     */
    public AlgorithmSpec getEncryption() { return encryption; }

    /**
     * <p>getEncryptionOID.</p>
     *
     * @return a {@link ASN1ObjectIdentifier} object
     */
    public ASN1ObjectIdentifier getEncryptionOID() { return (encryption != null) ? encryption.getOID() : null; }

    void setEncryptionOID(final ASN1ObjectIdentifier oid)
            throws NoSuchAlgorithmException
        { encryption = lookupValidatedByOID(oid, AlgorithmSpec.Type.CIPHER); }


    /**
     * <p>Getter for the field <code>padding</code>.</p>
     *
     * @return a {@link AlgorithmSpec} object
     */
    public AlgorithmSpec getPadding() { return padding; }

    /**
     * <p>getPaddingOID.</p>
     *
     * @return a {@link ASN1ObjectIdentifier} object
     */
    public ASN1ObjectIdentifier getPaddingOID() { return (padding != null) ? padding.getOID() : null; }

    void setPaddingOID(final ASN1ObjectIdentifier oid)
            throws NoSuchAlgorithmException
        { padding = lookupValidatedByOID(oid, AlgorithmSpec.Type.PADDING); }

    /**
     * <p>Getter for the field <code>compression</code>.</p>
     *
     * @return a {@link AlgorithmSpec} object
     */
    public AlgorithmSpec getCompression() { return compression; }

    /**
     * <p>getCompressionOID.</p>
     *
     * @return a {@link ASN1ObjectIdentifier} object
     */
    public ASN1ObjectIdentifier getCompressionOID() { return (compression != null) ? compression.getOID() : null; }

    /* setters  */
    public void setCompressionOID(final ASN1ObjectIdentifier oid)
            throws NoSuchAlgorithmException
        { compression = lookupValidatedByOID(oid, AlgorithmSpec.Type.COMPRESSION); }

    void setKeyAgreementProtocolByOID(final ASN1ObjectIdentifier oid)
            throws NoSuchAlgorithmException
        { keyAgreementProtocol = lookupValidatedByOID(oid, AlgorithmSpec.Type.KEY_AGREEMENT); }

    private AlgorithmSpec lookupValidatedByOID(final ASN1ObjectIdentifier oid, final AlgorithmSpec.Type expectedType)
            throws NoSuchAlgorithmException
        {
        if (oid == null)
            { return null; } // null is valid for not used/not set.
        AlgorithmSpec spec = AlgorithmSpecCollection.lookupByOID(oid);
        if (spec == null)
            { throw new NoSuchAlgorithmException("algorithm not supported in current implementation: "+oid.getId()); }
        if (spec.getType() != expectedType)
            { throw new NoSuchAlgorithmException("algorithm used in wrong function: "+oid.getId()); }
        return spec;
        }

    /**
     * <p>validate.</p>
     *
     * @return a boolean
     */
    public boolean validate()
        {
        // switch-case doesn't work with this type
        if (getPadding().equals(AlgorithmSpecCollection.IIP))
            {
            if (encryption == null) return false; // required.
            // we could check encryption some more; but since our lookup will work only for algorithms specified here anyways.
            if (keyAgreementProtocol != null) // if in use at all
                {
                if (keyAgreementProtocol != AlgorithmSpecCollection.ECDH) return false; // only supported variant now
                if (keyDiversificationAlgorithm == null) return false; // if keyAgreement, then this is required
                // currently optional; the provided key will determine the curve. if (keyAgreementCipher == null) return false; -- improvement.
                }

            }
        else if (getPadding().equals(AlgorithmSpecCollection.IIP2))
            {
            if (encryption == null) return false;
            // ITT to contain three ephemeral AES keys
            if (sig1Algorithm == null) return false;
            }
        else
            {
            return false; // algorithm not supported
            }
        return true;
        }

    /**
     * <p>Setter for the field <code>encryptionKeySize</code>.</p>
     *
     * @param encryptionKeySize a int
     */
    public void setEncryptionKeySize(final int encryptionKeySize)
        {
        this.encryptionKeySize = encryptionKeySize;
        }

    /**
     * <p>Getter for the field <code>encryptionKeySize</code>.</p>
     *
     * @return a int
     */
    public int getEncryptionKeySize()
        {
        return encryptionKeySize;
        }


    public ASN1ObjectIdentifier getSig1AlgorithmOID() { return (sig1Algorithm != null) ? sig1Algorithm.getOID() : null; }

    void setSig1AlgorithmByOID(final ASN1ObjectIdentifier oid)
            throws NoSuchAlgorithmException
        {
        if (sig1Algorithm.isAsymmetricCipher())
            throw new IllegalArgumentException("symmetric algorithms only");
        sig1Algorithm = lookupValidatedByOID(oid, AlgorithmSpec.Type.CIPHER);
        }

    public int getSig1KeySize() { return (sig1Algorithm == null) ? 0 : sig1Algorithm.getKeySizeInBit(); }


    public AlgorithmSpec getSig1() { return sig1Algorithm; }

    public int getProtocolVersion()
        {
        return protocolVersion;
        }

    public void setProtocolVersion(int protocolVersion)
        {
        this.protocolVersion = protocolVersion;
        }
}
//___EOF___
