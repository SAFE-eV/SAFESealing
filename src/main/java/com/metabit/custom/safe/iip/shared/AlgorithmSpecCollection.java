/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.iip.shared;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * lookup table for algorithms used by this implementation.
 * The JCE API lacks some data important for this use case, e.g. cipher block size and tara.
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public class AlgorithmSpecCollection
{

    /**
     * <p>lookupByOID.</p>
     *
     * @param oid a {@link org.bouncycastle.asn1.ASN1ObjectIdentifier} object
     * @return a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec} object
     */
    public static AlgorithmSpec lookupByOID(final ASN1ObjectIdentifier oid)
        {return algorithms.get(oid);}

    /**
     * <p>getAllDefined.</p>
     *
     * @return a {@link java.util.Collection} object
     */
    public static Collection<AlgorithmSpec> getAllDefined()
        {return algorithms.values();}

    /** Constant <code>ECDH</code> */
    public static final AlgorithmSpec ECDH = new AlgorithmSpec(SharedConstants.OID_ECDH_ALGORITHM, "ECDH", AlgorithmSpec.Type.KEY_AGREEMENT);
    /** Constant <code>ECSECP256R1</code> */
    public static final AlgorithmSpec ECSECP256R1 = new AlgorithmSpec(SharedConstants.OID_EC_NAMED_CURVE_SECP256R1, "secp256r1", AlgorithmSpec.Type.ELLIPTIC_CURVE, true, 0, 0, 0); // EC @TODO additional parmeters?
    /** Constant <code>SHA256</code> */
    public static final AlgorithmSpec SHA256 = new AlgorithmSpec(SharedConstants.OID_SHA256, "SHA-256", AlgorithmSpec.Type.DIGEST);
    /** Constant <code>COMPRESSION_NONE</code> */
    public static final AlgorithmSpec COMPRESSION_NONE = new AlgorithmSpec(SharedConstants.OID_COMPRESSION_NONE, "no compression", AlgorithmSpec.Type.COMPRESSION);

    /** Constant <code>COMPRESSION_GZIP</code> */
    public static final AlgorithmSpec COMPRESSION_GZIP = new AlgorithmSpec(SharedConstants.OID_COMPRESSION_GZIP, "gzip", AlgorithmSpec.Type.COMPRESSION);

    /** Constant <code>AES256ECB</code> means AES/ECB/NoPadding*/
    public static final AlgorithmSpec AES256ECB = new AlgorithmSpec(SharedConstants.OID_AES_256_ECB, "AES/ECB", AlgorithmSpec.Type.CIPHER, false, 256, 16, 16);
    /** Constant <code>AES256CBC</code> */
    public static final AlgorithmSpec AES256CBC = new AlgorithmSpec(SharedConstants.OID_AES_256_CBC, "AES/CBC", AlgorithmSpec.Type.CIPHER, false, 256, 16, 16);
    /** Constant <code>IIP</code> */
    public static final AlgorithmSpec IIP = new AlgorithmSpec(SharedConstants.OID_IIP_ALGORITHM, "IIP", AlgorithmSpec.Type.PADDING);
    public static final AlgorithmSpec RSA1024 = new AlgorithmSpec(SharedConstants.OID_RSA_ECB, "RSA/ECB/NoPadding", AlgorithmSpec.Type.CIPHER, true, 1024, 128, 1);
    /** Constant <code>RSA2048</code> */
    public static final AlgorithmSpec RSA2048 = new AlgorithmSpec(SharedConstants.OID_RSA_ECB, "RSA/ECB/NoPadding", AlgorithmSpec.Type.CIPHER, true, 2048, 256, 1);
    /** Constant <code>RSA4096</code> */
    public static final AlgorithmSpec RSA4096 = new AlgorithmSpec(SharedConstants.OID_RSA_ECB, "RSA/ECB/NoPadding", AlgorithmSpec.Type.CIPHER, true, 4096, 512, 1);

    /** Constant <code>RSA2048_on_SunJCE</code> */
    public static AlgorithmSpec RSA2048_on_SunJCE = new AlgorithmSpec(SharedConstants.OID_RSA_ECB, "RSA/ECB/NoPadding", AlgorithmSpec.Type.CIPHER, true, 2048, 256, 0); // internal test constructor, not public

    private static final Map<ASN1ObjectIdentifier, AlgorithmSpec> algorithms = new HashMap();

    /**
     * all valid algorithms available to the implementation must be listed here.
     */
    static
        {
        algorithms.put(SharedConstants.OID_AES_256_ECB, AES256ECB);
        algorithms.put(SharedConstants.OID_AES_256_CBC, AES256CBC);
        algorithms.put(SharedConstants.OID_IIP_ALGORITHM, IIP);
        algorithms.put(SharedConstants.OID_RSA_ECB, RSA2048); // RSA algorithm in general uses this OID; default keysize is 2048.
        algorithms.put(SharedConstants.OID_COMPRESSION_NONE, COMPRESSION_NONE);
        algorithms.put(SharedConstants.OID_COMPRESSION_GZIP, COMPRESSION_GZIP);
        algorithms.put(SharedConstants.OID_ECDH_ALGORITHM, ECDH);
        // all supported algorithms must be specified here, lest they fail parse/validation.
        algorithms.put(SharedConstants.OID_EC_NAMED_CURVE_SECP256R1, ECSECP256R1);
        algorithms.put(SharedConstants.OID_SHA256, SHA256);
        }
}
//___EOF___
