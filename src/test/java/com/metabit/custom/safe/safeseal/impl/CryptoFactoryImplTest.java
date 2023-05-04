package com.metabit.custom.safe.safeseal.impl;

import com.metabit.custom.safe.iip.shared.AlgorithmSpec;
import com.metabit.custom.safe.iip.shared.AlgorithmSpecCollection;
import com.metabit.custom.safe.iip.shared.CryptoFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Collection;

class CryptoFactoryImplTest
{
 @Test
    void testInstantiationOfAllAlgorithms() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException
     {
     CryptoFactory cf = new CryptoFactoryImpl();

     Collection<AlgorithmSpec> all = AlgorithmSpecCollection.getAllDefined();
     for (AlgorithmSpec algorithmSpec : all)
         {
         switch (algorithmSpec.getType())
             {
             case CIPHER:
                Cipher louis = cf.getCipherFromCipherSpec(algorithmSpec);
                Assertions.assertNotNull(louis);
                break;
             // more tests here possible
             }
         }
     return;
     }
}