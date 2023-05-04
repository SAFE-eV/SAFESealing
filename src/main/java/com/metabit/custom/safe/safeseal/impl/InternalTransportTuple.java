/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.safeseal.impl;

import com.metabit.custom.safe.iip.SharedCode;
import com.metabit.custom.safe.iip.shared.AlgorithmSpecCollection;

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

    /**
     * <p>Constructor for InternalTransportTuple.</p>
     *
     * @param css a {@link com.metabit.custom.safe.safeseal.impl.CryptoSettingsStruct} object
     */
    public InternalTransportTuple(CryptoSettingsStruct css)
        {
        this.cryptoSettings = css;
        }

    /**
     * <p>setDiversification.</p>
     *
     * @param numericalValue a {@link java.lang.Long} object
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
    public byte[] getEncryptedData() {return encryptedData;}

    /**
     * <p>Setter for the field <code>encryptedData</code>.</p>
     *
     * @param encryptedData an array of {@link byte} objects
     */
    public void setEncryptedData(byte[] encryptedData) {this.encryptedData = encryptedData;}

    /**
     * <p>Getter for the field <code>keyDiversificationData</code>.</p>
     *
     * @return an array of {@link byte} objects
     */
    public byte[] getKeyDiversificationData() {return keyDiversificationData;}

    /**
     * <p>Setter for the field <code>keyDiversificationData</code>.</p>
     *
     * @param keyDiversificationData an array of {@link byte} objects
     */
    public void setKeyDiversificationData(final byte[] keyDiversificationData)
        {
        this.keyDiversificationData = keyDiversificationData;
        }

    //-----------------------------------------------------------------------------------------------------------------

    @Deprecated
    InternalTransportTuple(final byte[] encryptedData, final Long uniqueID)
        {
        this.cryptoSettings = new CryptoSettingsStruct(true); // ECDH + secp1r + AES256
        this.encryptedData = encryptedData;
        setDiversification(uniqueID);
        //@TODO magic to get our default algorithms and their OID
        }

     @Deprecated
    InternalTransportTuple(byte[] encryptedData, Long uniqueID, String asymmetricAlgorithm, String symmetricAlgorithm)
        {
        cryptoSettings = new CryptoSettingsStruct(true); // ECDH + secp1r + AES256
        // this.cryptoSettings.set ... @TODO perform calls to lookup and set provided algorithms.
        this.encryptedData = encryptedData;
        setDiversification(uniqueID);
        Provider bc = Security.getProvider("BC");
        //@TODO magic to lookup algorithm OIDs
        }


    // for automated tests using defaults only
    InternalTransportTuple(boolean withKeyAgreement)
        {
        if (withKeyAgreement)
            {
            cryptoSettings = new CryptoSettingsStruct(AlgorithmSpecCollection.ECDH, AlgorithmSpecCollection.ECSECP256R1, AlgorithmSpecCollection.SHA256, AlgorithmSpecCollection.AES256CBC, AlgorithmSpecCollection.COMPRESSION_NONE);
            }
        else
            {
            cryptoSettings = new CryptoSettingsStruct(null, null, null, AlgorithmSpecCollection.RSA2048, AlgorithmSpecCollection.COMPRESSION_NONE);
            }
        //@TODO still, add the magic
        }

// @TODO constructor for reading incoming from TransportFormatConverter.

    byte[] keyDiversificationData;
    byte[] cryptoIV;
    byte[] encryptedData;
    CryptoSettingsStruct cryptoSettings;

    // --- accessors ----

}
