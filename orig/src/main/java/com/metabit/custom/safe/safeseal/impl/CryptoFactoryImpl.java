/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.safeseal.impl;

import com.metabit.custom.safe.iip.shared.AlgorithmSpec;
import com.metabit.custom.safe.iip.shared.CryptoFactory;
import com.metabit.custom.safe.iip.shared.SharedConstants;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;

/**
 * a factory to instantiate algorithms from AlgorithmSpec.
 * encapsulates the java SecurityProvider.
 *
 * @author jwilkes
 * @version $Id: $Id
 */
public class CryptoFactoryImpl implements CryptoFactory
{
    private Provider securityProvider;

    /**
     * default constructor.
     * Uses BouncyCastle security provider.
     */
    public CryptoFactoryImpl() // default: use BC
        {
        securityProvider = Security.getProvider("BC");
        if (securityProvider == null)
            {
            securityProvider = new BouncyCastleProvider();
            Security.addProvider(securityProvider);
            }
        return;
        }

    /**
     * constructor for use of a specific security provider instance.
     *
     * @param securityProvider security provider instance to use.
     */
    public CryptoFactoryImpl(Provider securityProvider)
        {
        this.securityProvider = securityProvider;
        }


    /**
     * {@inheritDoc}
     */
    @Override
    public Cipher getCipherFromCipherSpec(AlgorithmSpec algorithmSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException
        {
        switch (algorithmSpec.getType())
            {
            case CIPHER:
            case DIGEST:
                // we need special handling for RSA/ECB/NoPadding
                if (algorithmSpec.getOID().getId().equals(SharedConstants.OID_RSA_ECB.getId()))
                    {
                    return getRSAECB(algorithmSpec);
                    }
                // 1.3.132.1.12   for KEY_AGREEMENT

                // regular case
                Cipher cipher = Cipher.getInstance(algorithmSpec.getOID().getId(), securityProvider);
                return cipher;
            default:
                throw new IllegalArgumentException("wrong type");
            }
        }

    /**
     * {@inheritDoc}
     */
    @Override public ECDomainParameters getEllipticCurve(final AlgorithmSpec algorithmSpec)
        {
        if (algorithmSpec.getType() != AlgorithmSpec.Type.ELLIPTIC_CURVE)
            throw new IllegalArgumentException("wrong type");
        String curveName = algorithmSpec.getName();
        X9ECParameters curve = curveName.contains("brain") ? TeleTrusTNamedCurves.getByName(curveName) : SECNamedCurves.getByName(curveName);
        ECDomainParameters domain = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
        return domain;
        }

    /**
     * workaround for differences in crypto providers.
     * BouncyCastle reduces the usable part of the RSA block by a full byte;
     * SunJCE does not (but the MSB of the block still isn't usable).
     * The practical effect of this difference is found in the blocksizes, though -
     * which are of high importance to padding.
     * <p>
     * Additional workaround for BC behaviour not returning regular "plain RSA"
     * for the specification-compliant OID, but some other RSA variant instead.
     *
     * @param algorithmSpec algorithm spec provided.
     * @return
     */
    private Cipher getRSAECB(AlgorithmSpec algorithmSpec) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException
        {
        if (securityProvider.getName().equals("BC"))
            {
            // getting by OID from BC returns something else, probably padding which wasn't requested.
            return Cipher.getInstance("RSA/ECB/NoPadding", "BC"); // this works as expected, with the -1 BC RSA workaround.
            }
        else if (securityProvider.getName().equals("SunJCE"))
            {
            return Cipher.getInstance("RSA/ECB/NoPadding", "SunJCE"); // hasn't got the 255/256 bit issue, so it works differently -- without the 1 byte "tara"
            // BUT! algorithmSpec.getUsableBlockSize()+1   is necessary
            // integrityPaddingInstance = new InterleavedIntegrityPadding(algorithmSpec.getUsableBlockSize() + 1);
            }
        else
            return Cipher.getInstance("RSA/ECB/NoPadding", securityProvider);
        }
}
//___EOF___

