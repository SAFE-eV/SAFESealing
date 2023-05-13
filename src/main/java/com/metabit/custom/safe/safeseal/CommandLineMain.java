/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.safeseal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import picocli.CommandLine;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * command-line interface for testing purposes.
 * given keys and unique ID as parameters, it will perform sealing and de-sealing
 * <p>
 * reads input from stdin, writes output to stdout - standard *ix semantics.
 *
 * @author jwilkes, metabit
 * @version $Id: $Id
 *
 *      WORK IN PROGRESS!
 */
public class CommandLineMain implements Runnable {
    private Provider securityProvider;
    private final KeyFactory keyFactory;

    /**
     * <p>main.</p>
     * load BC, parse commandline, run.
     *
     * @param args an array of {@link java.lang.String} objects
     * @throws NoSuchAlgorithmException if RSA is not available
     */
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final CommandLineMain instance = new CommandLineMain();
        CommandLine.run(instance, args);
    }

    @CommandLine.Option(names = {"-P", "--privateKey"})
    private Path privateKeyInfo;
    @CommandLine.Option(names = {"-p", "--publicKey"})
    private Path publicKeyInfo;
    @CommandLine.Option(names = {"-i", "--uniqueID"})
    private Long uniqueIDValue;

    CommandLineMain() throws NoSuchAlgorithmException {
        securityProvider = Security.getProvider("BC");
        if (securityProvider == null) {
            securityProvider = new BouncyCastleProvider();
            Security.addProvider(securityProvider);
        }
        //<editor-fold defaultstate="collapsed" desc="delombok">
        keyFactory = KeyFactory.getInstance("RSA");
    }
        //</editor-fold>

    /**
     * {@inheritDoc} -- when called without arguments, print usage to stdout.
     */
    @Override
    public void run() {
        try {
            CommandLine.usage(new CommandLineMain(), System.out);
        } catch (final java.lang.Throwable $ex) {
            throw lombok.Lombok.sneakyThrow($ex);
        }
    //<editor-fold defaultstate="collapsed" desc="delombok">
    }
    //</editor-fold>

    @CommandLine.Command(name = "seal")
    void seal() {
        // prepare keys: private key of sealer is required.
        // read stdin
        // write stdout
        // error to stderr
    //<editor-fold defaultstate="collapsed" desc="delombok">
    }
    //</editor-fold>

    @CommandLine.Command(name = "unseal")
    void unseal() {
    }

    /**
     * read a RSA public key from an PEM file (see RFC5280, SubjectPublicKeyInfo).
     * @param pemEncodedRSAPublicKey the PEM encoded public key
     * @return RSA public key object
     * @throws NoSuchAlgorithmException if the algorithm doesn't match expectations
     * @throws InvalidKeySpecException if the key has some other issue
     * @see {RFC5208}
     */
    RSAPublicKey readRSAPublicKeyFromPEMFile(final String pemEncodedRSAPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyPEM = pemEncodedRSAPublicKey.replace("-----BEGIN PUBLIC KEY-----", "").replaceAll(System.lineSeparator(), "").replace("-----END PUBLIC KEY-----", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    /**
     * read an RSA private key from an PKCS8 PEM file.
     * @param pkcs8encodedRSAPrivateKey
     * @return RSA private key object
     * @throws NoSuchAlgorithmException if the algorithm doesn't match expectations
     * @throws InvalidKeySpecException if the key has some other issue
     * @see {RFC5208}
     */
    RSAPrivateKey readRSAPrivateKeyFromPKCS8PEMFile(final String pkcs8encodedRSAPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyPEM = pkcs8encodedRSAPrivateKey.replace("-----BEGIN PRIVATE KEY-----", "").replaceAll(System.lineSeparator(), "").replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
    }
}
//___EOF___
