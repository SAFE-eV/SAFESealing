package com.metabit.custom.safe.safeseal.impl;

import com.metabit.custom.safe.iip.shared.SharedConstants;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class SharedConstantsTest
{
    @Test
    void checkStaticInstantiation() throws NoSuchAlgorithmException
        {
        Set<ASN1ObjectIdentifier> tmp = SharedConstants.getCiphersOIDs();
        for (ASN1ObjectIdentifier asn1ObjectIdentifier : tmp)
            {
            assertNotNull(SharedConstants.getNameForOID(asn1ObjectIdentifier));
            }
        return;
        }
}