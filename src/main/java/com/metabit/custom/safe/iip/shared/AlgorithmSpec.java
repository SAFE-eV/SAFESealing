/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.iip.shared;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Algorithm specification.
 * The usual java interfaces do not provide key size, do not allow OID&lt;-&gt;Name lookups, lack some data.
 * Hence, this class to provide the missing information.
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public class AlgorithmSpec
{
    /**
     * get algorithm OID
     *
     * @return a {@link org.bouncycastle.asn1.ASN1ObjectIdentifier} object
     */
    public ASN1ObjectIdentifier getOID() {return cipherID;}

    /**
     * get name (human readable, but for consistency, it should comply with usual specification spelling used e.g. in Cipher lookup.
     *
     * @return a {@link java.lang.String} object
     */
    public String getName() {return name;}

    /**
     * check flag: is asymmetric cipher?
     *
     * @return a boolean
     */
    public boolean isAsymmetricCipher() {return asymmetric;}

    /**
     * get the general type, see enum in this class
     *
     * @return a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec.Type} object
     */
    public Type getType() {return type;}

    /**
     * for keys, get key size in bit.
     *
     * @return a int
     */
    public int getKeySizeInBit() {return keySizeInBit;}

    /**
     * for block ciphers, get block size in bytes. 0 for not applicable, -1 for stream ciphers.
     *
     * @return a int
     */
    public int getCipherBlockSize() {return cipherBlockSize;}

    /**
     * for block ciphers, get number of bytes in block usable for data. -1 for stream ciphers.
     *
     * @return a int
     */
    public int getUsableBlockSize() {return usableBlockSize;}

    /**
     * {@inheritDoc}
     */
    @Override public String toString()
        {
        switch (type)
            {
            case CIPHER:
                return name + " " + Integer.toString(getKeySizeInBit());
            case COMPRESSION:
            case DIGEST:
            case KEY_AGREEMENT:
            case PADDING:
                return name;
            }
        throw new UnsupportedOperationException("internal error, invalid type");
        }

    /**
     * the type of cryptographic object
     */
    public enum Type
    {
        /**
         * compression algorithms
         */
        COMPRESSION,
        /**
         * encryption/decryption ciphers
         */
        CIPHER,
        /**
         * message digests. Used here for key diversification or key derivation purposes only.
         */
        DIGEST,
        /**
         * key agreement algorithm.
         */
        KEY_AGREEMENT,
        /**
         * padding schemes
         */
        PADDING,
        /**
         * elliptic curve cryptography (ECC) curves
         */
        ELLIPTIC_CURVE
    }

    /**
     * construct an algorithm spec, with reduced content.
     *
     * @param oid  the OID
     * @param name the name
     * @param type the type
     */
    AlgorithmSpec(final ASN1ObjectIdentifier oid, final String name, final Type type)
        {
        this.cipherID = oid;
        this.name = name;
        this.type = type;
        // leaving everything else on default == 0
        }

    /**
     * construct a complete algorithm spec
     *
     * @param oid             the OID
     * @param name            the name
     * @param type            the type
     * @param asymmetricFlag  true if asymmetric crypto, false if symmetric or N/A
     * @param keySize         key size, <b>in bit</b>, if applicable
     * @param cipherBlockSize cipher block size, <b>in byte</b>, if applicable
     * @param tara            bytes of the cipher block not usable for payload
     */
    public AlgorithmSpec(final ASN1ObjectIdentifier oid, final String name, final Type type, boolean asymmetricFlag, int keySize, int cipherBlockSize, int tara)
        {
        this.cipherID = oid;
        this.name = name;
        this.type = type;
        this.asymmetric = asymmetricFlag;
        this.keySizeInBit = keySize;
        this.cipherBlockSize = cipherBlockSize;
        this.usableBlockSize = cipherBlockSize - tara;
        }

    private ASN1ObjectIdentifier cipherID;
    boolean asymmetric;
    String name;
    private Type type;
    int keySizeInBit; // for keys
    int cipherBlockSize; // for ciphers
    int usableBlockSize; // in addition to cipherBlockSize; the amount of data each "update" or "final" can process per call.
}
