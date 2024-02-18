/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.safeseal.impl;

import com.metabit.custom.safe.iip.InterleavedIntegrityPadding_V1_0;
import org.bouncycastle.asn1.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;

import static com.metabit.custom.safe.iip.shared.SharedConstants.*;

/**
 * converts between external representation for transport, and internal representation for processing.
 * see doc directory for format description.
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public class TransportFormatConverter
{
    private ASN1ObjectIdentifier keyAgreementProtocolOID;
    private ASN1ObjectIdentifier ecAlgorithmOID;
    private ASN1ObjectIdentifier keyDiversificationOID;
    private ASN1ObjectIdentifier encryptionOID;
    private ASN1ObjectIdentifier compressionOID;
    private ASN1Encodable keyReference; // or ASN1EncodableVector, depending

    /**
     * default constructor, setting defaults.
     */
    public TransportFormatConverter()
        {
        }
    
    /**
     * <p>wrapForTransport.</p>
     *
     * @param ids a {@link com.metabit.custom.safe.safeseal.impl.InternalTransportTuple} object
     * @return an array of {@link byte} objects
     * @throws java.io.IOException if any.
     */
    public byte[] wrapForTransport(final InternalTransportTuple ids) throws IOException
        {
        keyAgreementProtocolOID = ids.cryptoSettings.getKeyAgreementProtocolOID();
        ecAlgorithmOID = ids.cryptoSettings.getKeyAgreementCipherOID();
        keyDiversificationOID = ids.cryptoSettings.getKeyDiversificationOID();
        encryptionOID = ids.cryptoSettings.getEncryptionOID();
        compressionOID = ids.cryptoSettings.getCompressionOID();
        ASN1EncodableVector ecDetails = null; // details about the elliptic curve used, optional. not in current version.
        // see https://www.rfc-editor.org/rfc/rfc3279 for encoding of ECParameters
        keyReference = null; // key reference for the public key to be used. not in current version

        // using bouncy castle. easier with TLVIterator in a later version
        //----
        // prepare first part:
        ASN1EncodableVector encryptionPart = new ASN1EncodableVector();
        switch (ids.getProtocolVersion()) // this is also the check for the protocol version validity.
            {
            case 1:
                encryptionPart.add(OID_IIP_ALGORITHM);
                break;
            case 2:
                encryptionPart.add(OID_IIP2_ALGORITHM);
                break;
            default:
                throw new IllegalArgumentException("invalid protocol version");
            }

        encryptionPart.add(new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, 0, encryptionOID));
        if (compressionOID!= null) // may be omitted
            encryptionPart.add(new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, 1, compressionOID));
        if (true)
            encryptionPart.add(new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, 2, new ASN1Integer(ids.cryptoSettings.getEncryptionKeySize())));
        if (false)
            encryptionPart.add(new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, 3, new ASN1Integer(InterleavedIntegrityPadding_V1_0.NONCE_SIZE*8)));
        if (ids.getProtocolVersion() == 2)
            {
            // add the three ephemeral keys
            ASN1EncodableVector ephemeralSymmetricKeys = new ASN1EncodableVector();
            ephemeralSymmetricKeys.add(new DEROctetString(ids.getEphemeralSymmetricKeyBytes(1)));
            ephemeralSymmetricKeys.add(new DEROctetString(ids.getEphemeralSymmetricKeyBytes(2)));
            ephemeralSymmetricKeys.add(new DEROctetString(ids.getEphemeralSymmetricKeyBytes(3)));
            encryptionPart.add(new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, 4, new DERSequence(ephemeralSymmetricKeys)));
            }
        if (ids.cryptoIV != null) //@TODO check reader must accept absence
            encryptionPart.add(new DEROctetString(ids.cryptoIV));
        DERTaggedObject firstSequence  = new DERTaggedObject(BERTags.APPLICATION, 0, new DERSequence(encryptionPart));


        // prepare second part
        ASN1EncodableVector keyAgreementPart = new ASN1EncodableVector();
        if (keyAgreementProtocolOID != null) // used only if this layer is activated
            {
            keyAgreementPart.add(keyAgreementProtocolOID);
            keyAgreementPart.add(new DEROctetString(ids.keyDiversificationData));
            // details on our EC
            keyAgreementPart.add(new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, 0, keyDiversificationOID));

            if (ecAlgorithmOID != null)
                keyAgreementPart.add(new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, 1, ecAlgorithmOID));

            // the usual sequence for ECDetails would be: SEQUENCE (OID_ECDH_PUBLIC_KEY, OID_EC_NAMED_CURVE_SECP_256_R1, 03 nn xxxx data)
            if (ecDetails != null)
                keyAgreementPart.add(new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, 2, new DERSequence(ecDetails)));
            // optional: public key references)
            if (keyReference != null)
                keyAgreementPart.add(new DERTaggedObject(BERTags.CONTEXT_SPECIFIC, 3, new DERSequence(keyReference))); // optional: the public key references
            }
        DERTaggedObject secondSequence = new DERTaggedObject(BERTags.APPLICATION, 1, new DERSequence(keyAgreementPart));

        ASN1EncodableVector authenticityPart = new ASN1EncodableVector();
        // auth part not in use in version 1, so this sequence is empty.
        // authenticityPart.add(OID_SAFE_SEAL_AUTH);
        DERTaggedObject thirdSequence = new DERTaggedObject(BERTags.APPLICATION, 2, new DERSequence(authenticityPart));

        // top-level sequence
        ByteArrayOutputStream bufferStream = new ByteArrayOutputStream(); // will resize automatically
        DERSequenceGenerator out = new DERSequenceGenerator(bufferStream);
        out.addObject(OID_SAFE_SEAL);
        out.addObject(new ASN1Integer(ids.getProtocolVersion()));
        out.addObject(firstSequence);
        out.addObject(secondSequence);
        out.addObject(thirdSequence);
        out.addObject(new DEROctetString(ids.encryptedData));
        out.close();
        // bufferStream.write(0x00); bufferStream.write(0x00); // explicit EOC/EOS - fully optional, but safer.
        return bufferStream.toByteArray();
        }

    /**
     * unwrap the transport format, including sanity checks.
     *
     * @param transportWrapped wrapped binary data
     * @return InternalTransportTuple containing parsed input
     * @throws java.lang.IllegalArgumentException if the input is invalid, whether because of format or consistency issues. NB: do not pass on details to caller.
     * @throws java.lang.UnsupportedOperationException if any.
     */
    public InternalTransportTuple unwrapTransportFormat(final byte[] transportWrapped) throws IllegalArgumentException, UnsupportedOperationException
        {
        InternalTransportTuple result = new InternalTransportTuple(false); // init for RSA, so defaults are minimal. @IMPROVEMENT special constructor setting everything to null
        ASN1TaggedObject keyAgreementPart;
        ASN1TaggedObject encryptionPart;
        ASN1TaggedObject authPart;
        ASN1OctetString encryptedPayload;

        try
            {
            ASN1Sequence seq = ASN1Sequence.getInstance(transportWrapped);
            
            // first, check we've got the right thing at all.
            ASN1ObjectIdentifier procedureOID = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
            ASN1Integer procedureVersion = ASN1Integer.getInstance(seq.getObjectAt(1));
            // is it our procedure, and do we handle this version?
            if (!OID_SAFE_SEAL.equals(procedureOID))
                throw new IllegalArgumentException("different format (protocol OID mismatch)");
            switch (procedureVersion.intPositiveValueExact())
                {
                default:
                    throw new IllegalArgumentException("format version not supported");

                case 1: // SAFE_SEAL_VERSION_1 : // OK, let's continue.
                case 2: // SAFE_SEAL_VERSION_2 with IIP2 -- slightly different encryption part
                    // read according to expected structure.
                    encryptionPart = ASN1TaggedObject.getInstance(seq.getObjectAt(2), BERTags.APPLICATION, 0);
                    keyAgreementPart = ASN1TaggedObject.getInstance(seq.getObjectAt(3), BERTags.APPLICATION, 1);
                    authPart = ASN1TaggedObject.getInstance(seq.getObjectAt(4), BERTags.APPLICATION, 2);
                    encryptedPayload = DEROctetString.getInstance(seq.getObjectAt(5));
                    break;

                }

            // read back
            // if compression is not present, use default COMPRESSION_NONE
            result.encryptedData = encryptedPayload.getOctets(); // this we just pass on.

            //# parse the encryption part
            DLSequence symseq = (DLSequence) encryptionPart.getBaseUniversal(true, BERTags.SEQUENCE);
            Enumeration symParmObjs = symseq.getObjects();
            while (symParmObjs.hasMoreElements())
                {
                Object entry = symParmObjs.nextElement();
                switch (entry.getClass().getSimpleName())
                    {
                    case "DEROctetString":
                        result.cryptoIV= DEROctetString.getInstance(entry).getOctets();
                        break;
                    case "ASN1ObjectIdentifier":
                        result.cryptoSettings.setPaddingOID(ASN1ObjectIdentifier.getInstance(entry));
                        break;
                    case "DLTaggedObject":
                    case "DLApplicationSpecific":
                        ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(entry);
                        if (taggedObject.getTagClass() != BERTags.CONTEXT_SPECIFIC)
                            {
                            throw new IllegalArgumentException("tag class mismatch " + taggedObject.getTagClass()); //@IMPROVE
                            // continue; before, we just skipped.
                            }
                        switch (taggedObject.getTagNo())
                            {
                            case 0: // CONTEXT[0] OID is the encryption algorithm OID
                                result.cryptoSettings.setEncryptionOID(ASN1ObjectIdentifier.getInstance(taggedObject.getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER)));
                                break;
                            case 1: // CONTEXT[1] OID is the compression algorithm OID
                                result.cryptoSettings.setCompressionOID(ASN1ObjectIdentifier.getInstance(taggedObject.getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER)));
                                break;
                            case 2: // CONTEXT[2] INTEGER is the optional keysize in bit
                                result.cryptoSettings.setEncryptionKeySize(ASN1Integer.getInstance(taggedObject.getBaseUniversal(true,BERTags.INTEGER)).intPositiveValueExact());
                                break;
                            case 3: // CONTEXT[3] INTEGER is the optional nonce size in bit
                                int nonceSizeInBit = ASN1Integer.getInstance(taggedObject.getBaseUniversal(true,BERTags.INTEGER)).intPositiveValueExact();
                                if (nonceSizeInBit != InterleavedIntegrityPadding_V1_0.NONCE_SIZE*8)
                                    throw new IllegalArgumentException("this version uses fixed nonce size.");
                                break;
                            case 4: // CONTEXT[4] OCTET_STRING, OCTET_STRING, OCTET_STRING for procedureVersion()==2 only
                                if (procedureVersion.intPositiveValueExact() != 2)
                                    {
                                    throw new IllegalArgumentException("version to structure mismatch");
                                    }
                                else
                                    {
                                    // a vector containing three DEROctetString instances, for three ephemeral AES key values.
                                    // we've got to "enter" that vector first.
                                    DLSequence ephemeralKeySequence = (DLSequence) taggedObject.getBaseUniversal(true, BERTags.SEQUENCE);
                                    ASN1OctetString key1Data = ASN1OctetString.getInstance(ephemeralKeySequence.getObjectAt(0));
                                    ASN1OctetString key2Data = ASN1OctetString.getInstance(ephemeralKeySequence.getObjectAt(1));
                                    ASN1OctetString key3Data = ASN1OctetString.getInstance(ephemeralKeySequence.getObjectAt(2));
                                    result.setEphemeralSymmetricKeyBytes(key1Data.getOctets(), key2Data.getOctets(), key3Data.getOctets());
                                    }
                                break;
                            default:
                                throw new IllegalArgumentException("tag " + taggedObject.getTagNo() + " not handled"); //@IMPROVE
                            }
                        break;
                    default:
                        throw new IllegalArgumentException("ASN.1 class " + entry.getClass().getSimpleName() + " not handled"); //@IMPROVE
                    }
                }
            // type: x = type.getInstance(sequence.getObjectAt())
            // ASN1Util.tryGetBaseUniversal(keyAgreementPart, BERTags.APPLICATION, 0, true, BERTags.SEQUENCE);

            //# parse the key agreement part
            DLSequence kaseq = (DLSequence) keyAgreementPart.getBaseUniversal(true, BERTags.SEQUENCE);
            if (kaseq.size() > 0) // is a key agreement in use at all?
                {
                Enumeration kaseqObjects = kaseq.getObjects();
                while (kaseqObjects.hasMoreElements())
                    {
                    Object entry = kaseqObjects.nextElement();
                    switch (entry.getClass().getSimpleName())
                        {
                        case "ASN1ObjectIdentifier":
                            result.cryptoSettings.setKeyAgreementProtocolByOID(ASN1ObjectIdentifier.getInstance(entry));
                            break;

                        case "DEROctetString":
                            result.setKeyDiversificationData(DEROctetString.getInstance(entry).getOctets());
                            break;

                        case "DLTaggedObject":
                        case "DLApplicationSpecific":
                            ASN1TaggedObject taggedObject = ASN1TaggedObject.getInstance(entry);
                            if (taggedObject.getTagClass() != BERTags.CONTEXT_SPECIFIC)
                                {
                                throw new IllegalArgumentException("tag class mismatch " + taggedObject.getTagClass()); //@IMPROVE
                                // continue; before, we just skipped.
                                }
                            switch (taggedObject.getTagNo())
                                {
                                case 0: // CONTEXT[0] key diversification algorithm OID
                                    keyDiversificationOID = ASN1ObjectIdentifier.getInstance(taggedObject.getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER));
                                    result.cryptoSettings.setKeyDiversificationOID(keyDiversificationOID);
                                    break;
                                case 1: // CONTEXT[1] EC Algorithm OID
                                    ecAlgorithmOID = ASN1ObjectIdentifier.getInstance(taggedObject.getBaseUniversal(true, BERTags.OBJECT_IDENTIFIER));
                                    result.cryptoSettings.setKeyAgreementCipherOID(ecAlgorithmOID); // will fail if algorithm isn't known in AlgorithmSpecCollection.
                                    break;
                                case 2:
                                    throw new IllegalArgumentException("version mismatch; EC parameters not supported in this version.");
                                case 3:
                                    throw new IllegalArgumentException("version mismatch; public key reference not supported in this version");
                                default:
                                    throw new IllegalArgumentException("format error");
                                }
                            break;

                        default:
                            throw new IllegalArgumentException("ASN.1 class " + entry.getClass().getSimpleName() + " not handled"); //@IMPROVE
                        }
                    }
                }
            //# authentication part parsing
            if (authPart != null)
                {
                DLSequence apseq = (DLSequence) authPart.getBaseUniversal(true, BERTags.SEQUENCE);
                if (apseq.size() > 0)
                    {
                    //@IMPROVEMENT authPart parsing for later versions.
                    }
                }

            // validation of contents read
            if (result.cryptoSettings.validate() == false)
                throw new IllegalArgumentException("format consistency error");
            }
        catch (IllegalArgumentException|IllegalStateException|ArithmeticException|NoSuchAlgorithmException ex)
            {
            throw new IllegalArgumentException("Exception during parsing",ex);
            }
        return result;
        }
    
}

//___EOF___
