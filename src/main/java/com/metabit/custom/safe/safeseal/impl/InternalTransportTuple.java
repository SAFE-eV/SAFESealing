/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.safeseal.impl;

import com.metabit.custom.safe.iip.SharedCode;
import com.metabit.custom.safe.iip.shared.AlgorithmSpecCollection;

import javax.crypto.SecretKey;
import java.security.Provider;
import java.security.Security;

/**
 * package-private class to combine the data from and to transport format.
 * used to simplify parameter passing between TransportFormatConverter and asymmetric crypto
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public class InternalTransportTuple
{

    byte[]               keyDiversificationData;
    byte[]               cryptoIV;
    byte[]               encryptedData;
    CryptoSettingsStruct cryptoSettings;
    // --- V1.1 symmetric layer additions ---
    SecretKey            phase1Key;
    byte[]               phase1IV;
    SecretKey            phase2Key;
    byte[]               phase2IV;
    SecretKey            phase3Key;
    byte[]               phase3IV;
    private byte[] ephemeralSymmetricKey1;
    private byte[] ephemeralSymmetricKey2;
    private byte[] ephemeralSymmetricKey3;
    //-----------------------------------------------------------------------------------------------------------------

    /**
     * <p>Constructor for InternalTransportTuple.</p>
     *
     * @param css a {@link CryptoSettingsStruct} object
     */
    public InternalTransportTuple(CryptoSettingsStruct css)
        {
        this.cryptoSettings = css;
        }

    @Deprecated
    InternalTransportTuple(final byte[] encryptedData, final Long uniqueID)
        {
        this.cryptoSettings = new CryptoSettingsStruct(0, 9); // ECDH + secp1r + AES256
        this.cryptoSettings.setProtocolVersion(1);
        this.encryptedData = encryptedData;
        setDiversification(uniqueID);
        //@TODO magic to get our default algorithms and their OID
        }

    @Deprecated
    InternalTransportTuple(byte[] encryptedData, Long uniqueID, String asymmetricAlgorithm, String symmetricAlgorithm)
        {
        cryptoSettings = new CryptoSettingsStruct(0, 9); // ECDH + secp1r + AES256
        // this.cryptoSettings.set ... @TODO perform calls to lookup and set provided algorithms.
        this.cryptoSettings.setProtocolVersion(1);
        this.encryptedData = encryptedData;
        setDiversification(uniqueID);
        Provider bc = Security.getProvider("BC");
        //@TODO magic to lookup algorithm OIDs
        }

    // for automated tests using defaults only
    @Deprecated
    InternalTransportTuple(boolean withKeyAgreement)
        {
        if (withKeyAgreement)
            {
            cryptoSettings = new CryptoSettingsStruct(1, AlgorithmSpecCollection.ECDH, AlgorithmSpecCollection.ECSECP256R1, AlgorithmSpecCollection.SHA256, AlgorithmSpecCollection.AES256CBC_PADDED, AlgorithmSpecCollection.AES256CBC_PADDED, AlgorithmSpecCollection.COMPRESSION_NONE);
            }
        else
            {
            cryptoSettings = new CryptoSettingsStruct(1, null, null, null, AlgorithmSpecCollection.RSA2048, AlgorithmSpecCollection.AES256CBC_PADDED, AlgorithmSpecCollection.COMPRESSION_NONE);
            }
        //@TODO still, add the magic
        }


    public int getProtocolVersion()
        {
        return cryptoSettings.getProtocolVersion();
        }

    /**
     * <p>setDiversification.</p>
     *
     * @param numericalValue a {@link Long} object
     */
    public void setDiversification(final Long numericalValue)
        {
        keyDiversificationData = new byte[Long.BYTES];
        SharedCode.write8ByteUnsignedLongToBuffer(numericalValue, keyDiversificationData);
        }

    /**
     * <p>Getter for the field <code>encryptedData</code>.</p>
     *
     * @return an array of {@link byte} objects
     */
    public byte[] getEncryptedData() { return encryptedData; }

    /**
     * <p>Setter for the field <code>encryptedData</code>.</p>
     *
     * @param encryptedData an array of {@link byte} objects
     */
    public void setEncryptedData(byte[] encryptedData) { this.encryptedData = encryptedData; }

    /**
     * <p>Getter for the field <code>keyDiversificationData</code>.</p>
     *
     * @return an array of {@link byte} objects
     */
    public byte[] getKeyDiversificationData() { return keyDiversificationData; }

    /**
     * <p>Setter for the field <code>keyDiversificationData</code>.</p>
     *
     * @param keyDiversificationData an array of {@link byte} objects
     */
    public void setKeyDiversificationData(final byte[] keyDiversificationData)
        {
        this.keyDiversificationData = keyDiversificationData;
        }

    public CryptoSettingsStruct getCryptoSettings()
        {
        return cryptoSettings;
        }

    public void setCryptoIV(byte[] cryptoIV)
        {
        this.cryptoIV = cryptoIV;
        }

    public byte[] getCryptoIV()
        {
        return cryptoIV;
        }


    public void setEphemeralSymmetricKeyBytes(final byte[] key1data, final byte[] key2data, final byte[] key3data)
        {
        this.ephemeralSymmetricKey1 = key1data;
        this.ephemeralSymmetricKey2 = key2data;
        this.ephemeralSymmetricKey3 = key3data;
        }

    public byte[] getEphemeralSymmetricKeyBytes(final int index)
        {
        switch (index)
            {
            default:
                throw new IllegalArgumentException();
            case 1:
                return this.ephemeralSymmetricKey1;
            case 2:
                return this.ephemeralSymmetricKey2;
            case 3:
                return this.ephemeralSymmetricKey3;
            }
        }

    public SecretKey getEphemeralSymmetricKey1()
        {
        return phase1Key;
        }

    public SecretKey getEphemeralSymmetricKey2()
        {
        return phase2Key;
        }

    public SecretKey getEphemeralSymmetricKey3()
        {
        return phase3Key;
        }

/*
    //@TODO needs a name
    public void setXXLayerKeysAndIVs(final byte[] key1, final byte[] iv1,
                                     final byte[] key2, final byte[] iv2,
                                     final byte[] key3, final byte[] iv3)
            throws NoSuchAlgorithmException, InvalidKeySpecException
        {
        // conversion - not tested yet!
        SecretKeySpec sks1 = new SecretKeySpec(key1, "AES");
        SecretKeySpec sks2 = new SecretKeySpec(key2, "AES");
        SecretKeySpec sks3 = new SecretKeySpec(key3, "AES");
        SecretKeyFactory skf = SecretKeyFactory.getInstance("AES");
        this.phase1Key = skf.generateSecret(sks1);
        this.phase2Key = skf.generateSecret(sks2);
        this.phase3Key = skf.generateSecret(sks3);
        this.phase1IV = iv1;
        this.phase2IV = iv2;
        this.phase3IV = iv3;
        }
    */




    // @TODO constructor for reading incoming from TransportFormatConverter.

//---- accessors ----

}
//___EOF___