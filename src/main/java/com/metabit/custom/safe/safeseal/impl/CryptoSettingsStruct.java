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
    private AlgorithmSpec keyAgreementProtocol;
    private AlgorithmSpec keyAgreementCipher;
    private AlgorithmSpec keyDiversificationAlgorithm;
    private int encryptionKeySize;

    /**
     * constructor for the defined use cases, initialising with default values.
     *
     * @param withKeyAgreement when false, RSA 2048 with IIP; RSA/ECB/NoPadding+IIP at 2048 bit.
     *                         when true, ECDHE with secp256r1 and AES/CBC 256 bit.
     */
    public CryptoSettingsStruct(boolean withKeyAgreement)
        {
        if (withKeyAgreement)
            {
            compression = AlgorithmSpecCollection.COMPRESSION_NONE;
            padding = AlgorithmSpecCollection.IIP;
            encryption = AlgorithmSpecCollection.AES256CBC;
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

    /**
     * fully parameterised constructor.
     *
     * @param keyAgreementProtocolToUse Key Agreement protocol. currently supported: null, ECDH
     * @param keyAgreementCipherToUse   cipher to use in key agreemnet. currently supported: some EC curves  @TODO list/reference
     * @param keyDiversificationToUse   key diversification algorithm. currently supported: SHA-256, SHA-512
     * @param encryptionToUse           encryption to use. with key agreement, this should be symmetric (AES-256); without, this should be asymmetric (RSA-2048).
     * @param compressionUsed           indicator for recipient whether sender used some compression on the content. Implementation just passes this on, it is not performed here.
     */
    public CryptoSettingsStruct(AlgorithmSpec keyAgreementProtocolToUse, AlgorithmSpec keyAgreementCipherToUse, AlgorithmSpec keyDiversificationToUse, AlgorithmSpec encryptionToUse, AlgorithmSpec compressionUsed)
        {
        compression = compressionUsed;
        padding = AlgorithmSpecCollection.IIP;
        encryption = encryptionToUse;
        keyDiversificationAlgorithm = keyDiversificationToUse;
        keyAgreementCipher = keyAgreementCipherToUse;
        keyAgreementProtocol = keyAgreementProtocolToUse;
        }

    /**
     * <p>Getter for the field <code>keyAgreementProtocol</code>.</p>
     *
     * @return a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec} object
     */
    public AlgorithmSpec getKeyAgreementProtocol() {return keyAgreementProtocol;}

    /**
     * <p>getKeyAgreementProtocolOID.</p>
     *
     * @return a {@link org.bouncycastle.asn1.ASN1ObjectIdentifier} object
     */
    public ASN1ObjectIdentifier getKeyAgreementProtocolOID() {return (keyAgreementProtocol != null) ? keyAgreementProtocol.getOID() : null;}

    /**
     * <p>Getter for the field <code>keyAgreementCipher</code>.</p>
     *
     * @return a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec} object
     */
    public AlgorithmSpec getKeyAgreementCipher() {return keyAgreementCipher;}

    /**
     * <p>getKeyAgreementCipherOID.</p>
     *
     * @return a {@link org.bouncycastle.asn1.ASN1ObjectIdentifier} object
     */
    public ASN1ObjectIdentifier getKeyAgreementCipherOID() {return (keyAgreementCipher != null) ? keyAgreementCipher.getOID() : null;}

    void setKeyAgreementCipherOID(final ASN1ObjectIdentifier oid) throws NoSuchAlgorithmException
        {keyAgreementCipher = lookupValidatedByOID(oid, AlgorithmSpec.Type.ELLIPTIC_CURVE);}

    /**
     * <p>Getter for the field <code>keyDiversificationAlgorithm</code>.</p>
     *
     * @return a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec} object
     */
    public AlgorithmSpec getKeyDiversificationAlgorithm() {return keyDiversificationAlgorithm;}

    /**
     * <p>getKeyDiversificationOID.</p>
     *
     * @return a {@link org.bouncycastle.asn1.ASN1ObjectIdentifier} object
     */
    public ASN1ObjectIdentifier getKeyDiversificationOID() {return (keyDiversificationAlgorithm != null) ? keyDiversificationAlgorithm.getOID() : null;}

    void setKeyDiversificationOID(final ASN1ObjectIdentifier oid) throws NoSuchAlgorithmException
        {keyDiversificationAlgorithm = lookupValidatedByOID(oid, AlgorithmSpec.Type.DIGEST);}

    /**
     * <p>Getter for the field <code>encryption</code>.</p>
     *
     * @return a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec} object
     */
    public AlgorithmSpec getEncryption() {return encryption;}

    /**
     * <p>getEncryptionOID.</p>
     *
     * @return a {@link org.bouncycastle.asn1.ASN1ObjectIdentifier} object
     */
    public ASN1ObjectIdentifier getEncryptionOID() {return (encryption != null) ? encryption.getOID() : null;}

    void setEncryptionOID(final ASN1ObjectIdentifier oid) throws NoSuchAlgorithmException
        {encryption = lookupValidatedByOID(oid, AlgorithmSpec.Type.CIPHER);}

    /**
     * <p>Getter for the field <code>padding</code>.</p>
     *
     * @return a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec} object
     */
    public AlgorithmSpec getPadding() {return padding;}

    /**
     * <p>getPaddingOID.</p>
     *
     * @return a {@link org.bouncycastle.asn1.ASN1ObjectIdentifier} object
     */
    public ASN1ObjectIdentifier getPaddingOID() {return (padding != null) ? padding.getOID() : null;}

    void setPaddingOID(final ASN1ObjectIdentifier oid) throws NoSuchAlgorithmException
        {padding = lookupValidatedByOID(oid, AlgorithmSpec.Type.PADDING);}

    /**
     * <p>Getter for the field <code>compression</code>.</p>
     *
     * @return a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec} object
     */
    public AlgorithmSpec getCompression() {return compression;}

    /**
     * <p>getCompressionOID.</p>
     *
     * @return a {@link org.bouncycastle.asn1.ASN1ObjectIdentifier} object
     */
    public ASN1ObjectIdentifier getCompressionOID() {return (compression != null) ? compression.getOID() : null;}

    /* setters  */
    void setCompressionOID(final ASN1ObjectIdentifier oid) throws NoSuchAlgorithmException
        {compression = lookupValidatedByOID(oid, AlgorithmSpec.Type.COMPRESSION);}

    void setKeyAgreementProtocolByOID(final ASN1ObjectIdentifier oid) throws NoSuchAlgorithmException
        {keyAgreementProtocol = lookupValidatedByOID(oid, AlgorithmSpec.Type.KEY_AGREEMENT);}

    private AlgorithmSpec lookupValidatedByOID(final ASN1ObjectIdentifier oid, final AlgorithmSpec.Type expectedType) throws NoSuchAlgorithmException
        {
        if (oid == null)
            {return null;} // null is valid for not used/not set.
        AlgorithmSpec spec = AlgorithmSpecCollection.lookupByOID(oid);
        if (spec == null)
            {throw new NoSuchAlgorithmException("algorithm not supported in current implementation: " + oid.getId());}
        if (spec.getType() != expectedType)
            {throw new NoSuchAlgorithmException("algorithm used in wrong function: " + oid.getId());}
        return spec;
        }

    /**
     * <p>validate.</p>
     *
     * @return a boolean
     */
    public boolean validate()
        {
        if (padding != AlgorithmSpecCollection.IIP) return false; // only supported variant now.
        if (encryption == null) return false; // required.
        // we could check encryption some more; but since our lookup will work only for algorithms specified here anyways.
        if (keyAgreementProtocol != null) // if in use at all
            {
            if (keyAgreementProtocol != AlgorithmSpecCollection.ECDH) return false; // only supported variant now
            if (keyDiversificationAlgorithm == null) return false; // if keyAgreement, then this is required
            // currently optional; the provided key will determine the curve. if (keyAgreementCipher == null) return false; -- improvement.
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
}
//___EOF___
