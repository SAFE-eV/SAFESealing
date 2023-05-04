/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.iip.shared;

import org.bouncycastle.crypto.params.ECDomainParameters;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * <p>CryptoFactory interface.</p>
 * This interface provides a facade to JCE SecurityProvider, enabling algorithm lookups by OID and specification.
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public interface CryptoFactory
{
    /**
     * <p>getCipherFromCipherSpec.</p>
     *
     * @param algorithmSpec a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec} object
     * @return a {@link javax.crypto.Cipher} object
     * @throws javax.crypto.NoSuchPaddingException if any.
     * @throws java.security.NoSuchAlgorithmException if any.
     * @throws java.security.NoSuchProviderException if any.
     */
    Cipher getCipherFromCipherSpec(AlgorithmSpec algorithmSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException;

    /**
     * <p>getEllipticCurve.</p>
     *
     * @param algorithmSpec a {@link com.metabit.custom.safe.iip.shared.AlgorithmSpec} object
     * @return a {@link org.bouncycastle.crypto.params.ECDomainParameters} object
     */
    ECDomainParameters getEllipticCurve(AlgorithmSpec algorithmSpec);
}
