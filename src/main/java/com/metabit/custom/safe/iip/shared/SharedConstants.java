/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.iip.shared;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * a collection of constants, and lookup for OIDs
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public final class SharedConstants
{
    /** Constant <code>OID_SAFE_SEAL</code> */
    public final static ASN1ObjectIdentifier OID_SAFE_SEAL = new ASN1ObjectIdentifier("1.3.6.1.4.1.60279.1.1");
    /** Constant <code>OID_SAFE_SEAL_AUTH</code> */
    public final static ASN1ObjectIdentifier OID_SAFE_SEAL_AUTH = new ASN1ObjectIdentifier("1.3.6.1.4.1.60279.1.2");

    // see https://www.rfc-editor.org/rfc/rfc8017.html A.1
    /** Constant <code>OID_RSA_ECB</code> */
    public final static ASN1ObjectIdentifier OID_RSA_ECB = new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"); // issues with BouncyCastle vs. Oracle JCE

    ;// no instantiation wanted
    private SharedConstants() {}

    /**
     * algorithm name lookup from OID.
     * This is not a generic function, its scope is limited to this software.
     *
     * @param oid OID to look up
     * @return name/algorithm spec belonging to the OID
     * @throws java.security.NoSuchAlgorithmException if this class could not find the OID provided
     */
    public static String getNameForOID(final ASN1ObjectIdentifier oid) throws NoSuchAlgorithmException
        {
        if (combinedForwardMap.containsKey(oid))
            return String.valueOf(combinedForwardMap.get(oid));
        throw new NoSuchAlgorithmException(oid.getId());
        }

    /**
     * reverse lookup from name to OID. Note this is not checking for aliases;
     * you may have provided a String that would be perfectly understandable for a human,
     * but fails in this automated lookup.
     *
     * @param algorithmName the name or algorithm spec to look up
     * @return corresponding OID
     * @throws java.security.NoSuchAlgorithmException if this specific lookup could not find a match
     */
    public static ASN1ObjectIdentifier getOIDForName(final String algorithmName) throws NoSuchAlgorithmException
        {
        if (combinedReverseMap.containsKey(algorithmName))
            return combinedReverseMap.get(algorithmName);
        throw new NoSuchAlgorithmException(algorithmName);
        }

    // accessors for automated tests
    /**
     * <p>getCiphersOIDs.</p>
     *
     * @return a {@link java.util.Set} object
     */
    public static Set<ASN1ObjectIdentifier> getCiphersOIDs() {return ciphers.keySet();}

    /**
     * <p>getKeyDiversificationOIDs.</p>
     *
     * @return a {@link java.util.Set} object
     */
    public static Set<ASN1ObjectIdentifier> getKeyDiversificationOIDs() {return keyDiversificationAlgorithms.keySet();}

    /**
     * <p>getKeyExchangeAlgorithmsOIDs.</p>
     *
     * @return a {@link java.util.Set} object
     */
    public static Set<ASN1ObjectIdentifier> getKeyExchangeAlgorithmsOIDs() {return keyExchangeAlgorithms.keySet();}


    //--------------------------------------------------------------------------------------------------------------------
    // we got a bunch of possible EC curves.

    /** Constant <code>OID_EL_GAMAL</code> */
    public final static ASN1ObjectIdentifier OID_EL_GAMAL = new ASN1ObjectIdentifier("1.3.6.1.4.1.3029.1.2");
    /** Constant <code>OID_ECDH_PUBLIC_KEY</code> */
    public final static ASN1ObjectIdentifier OID_ECDH_PUBLIC_KEY = new ASN1ObjectIdentifier("1.2.840.10045.2.1");
    // our SAFE eV default as of 2023 is secp256r1
  
  /*
  the recommended curves are:
        secp256r1 	1.2.840.10045.3.1.7 	NIST P-256, X9.62 prime256v1
        secp384r1 	1.3.132.0.34 	NIST P-384
        secp521r1 	1.3.132.0.35 	NIST P-521
   */

    /** Constant <code>OID_EC_NAMED_CURVE_SECP256R1</code> */
    public final static ASN1ObjectIdentifier OID_EC_NAMED_CURVE_SECP256R1 = new ASN1ObjectIdentifier("1.2.840.10045.3.1.7");
    /** Constant <code>OID_EC_NAMED_CURVE_SECP192R1</code> */
    public final static ASN1ObjectIdentifier OID_EC_NAMED_CURVE_SECP192R1 = new ASN1ObjectIdentifier("1.2.840.10045.3.1.1");
    /** Constant <code>OID_EC_NAMED_CURVE_X25519</code> */
    public final static ASN1ObjectIdentifier OID_EC_NAMED_CURVE_X25519 = new ASN1ObjectIdentifier("1.3.6.1.4.1.3029.1.5.1"); // "curvey25519""

    /** Constant <code>OID_COMPRESSION_NONE</code> */
    public final static ASN1ObjectIdentifier OID_COMPRESSION_NONE = new ASN1ObjectIdentifier("1.3.6.1.4.1.21876.1.1.1.1.0");
    /** Constant <code>OID_COMPRESSION_DEFLATE</code> */
    public final static ASN1ObjectIdentifier OID_COMPRESSION_DEFLATE = new ASN1ObjectIdentifier("1.3.6.1.4.1.21876.1.1.1.1.1");
    /** Constant <code>OID_COMPRESSION_GZIP</code> */
    public final static ASN1ObjectIdentifier OID_COMPRESSION_GZIP = new ASN1ObjectIdentifier("1.3.6.1.4.1.21876.1.1.1.1.2");
    /** Constant <code>OID_COMPRESSION_BROTLI</code> */
    public final static ASN1ObjectIdentifier OID_COMPRESSION_BROTLI = new ASN1ObjectIdentifier("1.3.6.1.4.1.21876.1.1.1.1.3");

    // oracle provided, see oracle.security.crypto.cms
    final static ASN1ObjectIdentifier oracle_id_ct_compressedData = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.9");
    final static ASN1ObjectIdentifier oraclie_id_alg_zlibCompress = new ASN1ObjectIdentifier("1.2.840.113549.1.3.86.2.14");


    /** Constant <code>OID_AES_128_ECB</code> */
    public final static ASN1ObjectIdentifier OID_AES_128_ECB = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.1");
    /** Constant NIST <code>OID_AES_128_CBC</code> <em>with padding</em> - the information about this is hidden and only found in the OID database. */
    public final static ASN1ObjectIdentifier OID_AES_128_CBC_PAD = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.2");
    public final static ASN1ObjectIdentifier OID_AES_128_CBC_NOPAD = new ASN1ObjectIdentifier("1.3.6.1.4.1.21876.1.1.1.2.1.2");
    /** Constant <code>OID_AES_192_ECB</code> */
    public final static ASN1ObjectIdentifier OID_AES_192_ECB = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.21");
    /** Constant NIST <code>OID_AES_192_CBC</code> <em>with padding</em> - the information about this is hidden and only found in the OID database. */
    public final static ASN1ObjectIdentifier OID_AES_192_CBC_PAD = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.22");
    public final static ASN1ObjectIdentifier OID_AES_192_CBC_NOPAD = new ASN1ObjectIdentifier("1.3.6.1.4.1.21876.1.1.1.2.1.41");

    /** Constant <code>OID_AES_256_ECB</code> */
    public final static ASN1ObjectIdentifier OID_AES_256_ECB_NOPAD = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.41");
    /** Constant NIST <code>OID_AES_256_CBC</code> <em>with padding</em> - the information about this is hidden and only found in the OID database. */
    public final static ASN1ObjectIdentifier OID_AES_256_CBC_PAD   = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.1.42"); // aes256-CBC-PAD(42)
    /** no-padding OID specifically derived as alternative to the padding */
    public final static ASN1ObjectIdentifier OID_AES_256_CBC_NOPAD = new ASN1ObjectIdentifier("1.3.6.1.4.1.21876.1.1.1.2.1.42");

    // ---- used for key derivation only ----
    // RFC8017:   id-sha512    OBJECT IDENTIFIER ::= { joint-iso-itu-t (2) country (16) us (840) organization (1) gov (101) csor (3) nistalgorithm (4) hashalgs (2) 3 }
    /** Constant <code>OID_SHA_512</code> */
    public final static ASN1ObjectIdentifier OID_SHA_512 = new ASN1ObjectIdentifier("1.2.840.1.101.3.4.2.3");

    //RFC8017:  id-sha256    OBJECT IDENTIFIER ::= { joint-iso-itu-t (2) country (16) us (840) organization (1) gov (101) csor (3) nistalgorithm (4) hashalgs (2) 1 }
    /** Constant <code>OID_SHA256</code> */
    public final static ASN1ObjectIdentifier OID_SHA256 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");

    // source: https://oidref.com/2.16.840.1.101.3.4.2 NIST Algorithm IDs
    /** Constant <code>OID_SHA512</code> */
    public final static ASN1ObjectIdentifier OID_SHA512 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.3");
    /** Constant <code>OID_SHA512_256</code> */
    public final static ASN1ObjectIdentifier OID_SHA512_256 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.6");
    /** Constant <code>OID_SHA3_256</code> */
    public final static ASN1ObjectIdentifier OID_SHA3_256 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.8");
    /** Constant <code>OID_SHA3_512</code> */
    public final static ASN1ObjectIdentifier OID_SHA3_512 = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.10");


    // supported OIDs, maintenance here.
    /** Constant <code>OID_ECDH_ALGORITHM</code> */
    public final static ASN1ObjectIdentifier OID_ECDH_ALGORITHM = new ASN1ObjectIdentifier("1.3.132.1.12");
    // ECDSA and ECDH use the same OID; as per RFC 3279 2.3.5
    // placed under the ANSI X9 62 branch  at 1.2.840.10045
    /** Constant <code>OID_EC_PUBLIC_KEY_TYPE</code> */
    public final static ASN1ObjectIdentifier OID_EC_PUBLIC_KEY_TYPE = new ASN1ObjectIdentifier("1.2.840.10045.62.2");
    /** Constant <code>OID_EC_PUBLIC_KEY</code> */
    public final static ASN1ObjectIdentifier OID_EC_PUBLIC_KEY = new ASN1ObjectIdentifier("1.2.840.10045.62.2.1");

    /** Constant <code>OID_EC_UNRESTRICTED</code> */
    public final static ASN1ObjectIdentifier OID_EC_UNRESTRICTED = new ASN1ObjectIdentifier("1.2.840.10045.2.1");


    //--------------------------------------------------------------------------------------------------------------------

    private static final Map keyExchange = new HashMap<ASN1ObjectIdentifier, String>();

    static
        {
        keyExchange.put(OID_ECDH_ALGORITHM, "ECDH"); // see RFC 6637; and RFC 5480 clause 2.1.2
        // keyExchange.put(OIWObjectIdentifiers.elGamalAlgorithm, "ELGAMAL"); -- not valid yet, possible future extension
        }

    private static final Map keyExchangeAlgorithms = new HashMap<ASN1ObjectIdentifier, String>();

    static
        {
        // supported EC algorithms go here.
        }

    // NB: we are not using any algorithm for HMAC purposes; these are used for key diversification at key exchange level only.
    private static final Map keyDiversificationAlgorithms = new HashMap<ASN1ObjectIdentifier, String>();

    static
        {
        keyDiversificationAlgorithms.put(NISTObjectIdentifiers.id_sha224, "SHA224");
        keyDiversificationAlgorithms.put(NISTObjectIdentifiers.id_sha256, "SHA256");
        keyDiversificationAlgorithms.put(NISTObjectIdentifiers.id_sha384, "SHA384");
        keyDiversificationAlgorithms.put(NISTObjectIdentifiers.id_sha512, "SHA512");
        keyDiversificationAlgorithms.put(NISTObjectIdentifiers.id_sha3_224, "SHA3-224");
        keyDiversificationAlgorithms.put(NISTObjectIdentifiers.id_sha3_256, "SHA3-256");
        keyDiversificationAlgorithms.put(NISTObjectIdentifiers.id_sha3_384, "SHA3-384");
        keyDiversificationAlgorithms.put(NISTObjectIdentifiers.id_sha3_512, "SHA3-512");
        }

    private static final Map ciphers = new HashMap<ASN1ObjectIdentifier, String>();
    private static final Map futureCiphers = new HashMap<ASN1ObjectIdentifier, String>();

    static
        {
        ciphers.put(NISTObjectIdentifiers.id_aes256_CBC, "AES-256/CBC");
        ciphers.put(NISTObjectIdentifiers.id_aes256_ECB, "AES-256/ECB");
        ciphers.put(NISTObjectIdentifiers.id_aes128_ECB, "AES-128/ECB");
        ciphers.put(NISTObjectIdentifiers.id_aes192_ECB, "AES-192/ECB");
        ciphers.put(NISTObjectIdentifiers.id_aes128_CBC, "AES-128/CBC");
        ciphers.put(NISTObjectIdentifiers.id_aes192_CBC, "AES-192/CBC");
        // this has been tested, works in crypto, but not in current implementation - yet
        futureCiphers.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        // these have not been tested yet
        futureCiphers.put(NTTObjectIdentifiers.id_camellia128_cbc, "CAMELLIA-128/CBC");
        futureCiphers.put(NTTObjectIdentifiers.id_camellia192_cbc, "CAMELLIA-192/CBC");
        futureCiphers.put(NTTObjectIdentifiers.id_camellia256_cbc, "CAMELLIA-256/CBC");
        futureCiphers.put(KISAObjectIdentifiers.id_seedCBC, "SEED/CBC");
        futureCiphers.put(MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC, "IDEA/CBC");
        futureCiphers.put(MiscObjectIdentifiers.cast5CBC, "CAST5/CBC");
        futureCiphers.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_ECB, "Blowfish/ECB");
        futureCiphers.put(MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC, "Blowfish/CBC");
        futureCiphers.put(GNUObjectIdentifiers.Serpent_128_ECB, "Serpent-128/ECB");
        futureCiphers.put(GNUObjectIdentifiers.Serpent_128_CBC, "Serpent-128/CBC");
        futureCiphers.put(GNUObjectIdentifiers.Serpent_192_ECB, "Serpent-192/ECB");
        futureCiphers.put(GNUObjectIdentifiers.Serpent_192_CBC, "Serpent-192/CBC");
        futureCiphers.put(GNUObjectIdentifiers.Serpent_256_ECB, "Serpent-256/ECB");
        futureCiphers.put(GNUObjectIdentifiers.Serpent_256_CBC, "Serpent-256/CBC");
        }

    /** Constant <code>OID_IIP_ALGORITHM</code> */
    public final static ASN1ObjectIdentifier OID_IIP_ALGORITHM = new ASN1ObjectIdentifier("1.3.6.1.4.1.21876.4.3.1");
    public final static ASN1ObjectIdentifier OID_IIP2_ALGORITHM = new ASN1ObjectIdentifier("1.3.6.1.4.1.21876.4.3.2");
    private static final Map<ASN1ObjectIdentifier, String> paddings = new HashMap();

    static
        {
        paddings.put(OID_IIP_ALGORITHM, "IIP");
        paddings.put(OID_IIP2_ALGORITHM, "IIP2");
        }

    private static final Map<ASN1ObjectIdentifier, String> combinedForwardMap = new HashMap<>();
    private static final Map<String, ASN1ObjectIdentifier> combinedReverseMap = new HashMap<>();

    // how can we be sure java manages to initialise this in the right order?
    static
        {
        // since OID are guaranteed to be globally unique, no collision can occur here.
        combinedForwardMap.putAll(keyExchange);
        combinedForwardMap.putAll(keyExchangeAlgorithms);
        combinedForwardMap.putAll(keyDiversificationAlgorithms);
        combinedForwardMap.putAll(ciphers);
        // combinedForwardMap.putAll(futureCiphers); -- during development/testing only
        combinedForwardMap.putAll(paddings);

        // constructing the reverse map could, theorhetically, cause collisions; above limited data set should not generate any.
        combinedForwardMap.entrySet().stream().forEach(entry -> combinedReverseMap.put(entry.getValue(), entry.getKey()));
        }
}
//___EOF___
