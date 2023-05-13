package com.metabit.custom.safe.safeseal;

import com.metabit.custom.safe.safeseal.CommandLineMain;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

class CommandLineMainTest
{
    @Test
    void createWriteAndReadBackKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, InvalidKeySpecException
        {
        final Path privKeyFilePath = tmpdir.resolve("privatekey.pem");
        final Path pubKeyFilePath = tmpdir.resolve("publickey.pem");

        KeyPair keypair = generateRSAKeyPair(2048);
        Assertions.assertNotNull(keypair);

        RSAPrivateKey privateKey = (RSAPrivateKey) keypair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keypair.getPublic();

        Files.write(privKeyFilePath, pemExportPrivateKey(privateKey).getBytes());
        Files.write(pubKeyFilePath, pemExportPublicKey(publicKey).getBytes());

        String readbackKey = new String(Files.readAllBytes(pubKeyFilePath), Charset.defaultCharset());
        final RSAPublicKey pubKeyInstance = readPublicKey(readbackKey);
        Assertions.assertEquals(publicKey, pubKeyInstance);

        readbackKey = new String(Files.readAllBytes(privKeyFilePath), Charset.defaultCharset());
        final RSAPrivateKey privKeyInstance = readPrivateKey(readbackKey);
        Assertions.assertEquals(privateKey, privKeyInstance);

        CommandLineMain instance = new CommandLineMain();

        String privKeyString = new String(Files.readAllBytes(privKeyFilePath), Charset.defaultCharset());
        final PrivateKey privKey2 = instance.readRSAPrivateKeyFromPKCS8PEMFile(privKeyString);
        Assertions.assertEquals(privateKey, privKey2);

        String pubKeyString = new String(Files.readAllBytes(pubKeyFilePath), Charset.defaultCharset());
        final PublicKey pubKey2 = instance.readRSAPublicKeyFromPEMFile(pubKeyString);
        Assertions.assertEquals(publicKey, pubKey2);
        }




    private static Path tmpdir;

    @BeforeAll
    static void init() throws IOException
        {
        String tmpdirName = Files.createTempDirectory("tmpDirPrefix").toFile().getAbsolutePath();
        final File tmpdirfile = new File(tmpdirName);
        tmpdir = tmpdirfile.toPath();
        }

    @AfterAll
    static void exit()
        {
        tmpdir.toFile().delete();
        }

    private static RSAPublicKey readPublicKey(final String readbackKey) throws NoSuchAlgorithmException, InvalidKeySpecException
        {
        String publicKeyPEM = readbackKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        }

    private static RSAPrivateKey readPrivateKey(final String readbackKey) throws NoSuchAlgorithmException, InvalidKeySpecException
        {
        String privateKeyPEM = readbackKey
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        }


    // using JCE, not BC

    private static String pemExportPublicKey(final RSAPublicKey key)
        {
        byte[] der = key.getEncoded();
        String pem = Base64.getEncoder().encodeToString(der);
        return "-----BEGIN PUBLIC KEY-----" + "\n" + pem + "-----END PUBLIC KEY-----" + "\n";
        }

    private static String pemExportPrivateKey(final RSAPrivateKey key)
        {
        byte[] der = key.getEncoded();
        String pem = Base64.getEncoder().encodeToString(der);
        return "-----BEGIN PRIVATE KEY-----" + "\n" + pem + "-----END PRIVATE KEY-----" + "\n";
        }

    java.security.KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
        {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4));
        return kpg.generateKeyPair();
        }

}