/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.safeseal;

import lombok.SneakyThrows;
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
 *
 */
public class CommandLineMain implements Runnable
{
    private Provider securityProvider;
    private final KeyFactory keyFactory;

    /**
     * <p>main.</p>
     * load BC, parse commandline, run.
     *
     * @param args an array of {@link java.lang.String} objects
     * @throws NoSuchAlgorithmException if RSA is not available
     */
    public static void main(String[] args) throws NoSuchAlgorithmException
        {
        final CommandLineMain instance = new CommandLineMain();
        CommandLine.run(instance, args);
        }


    @CommandLine.Option(names = {"-P", "--privateKey"})
    private Path privateKeyInfo;

    @CommandLine.Option(names = {"-p", "--publicKey"})
    private Path publicKeyInfo;

    @CommandLine.Option(names = {"-i", "--uniqueID"})
    private Long uniqueIDValue;

    CommandLineMain() throws NoSuchAlgorithmException
        {
        securityProvider = Security.getProvider("BC");
        if (securityProvider == null)
            {
            securityProvider = new BouncyCastleProvider();
            Security.addProvider(securityProvider);
            }
        keyFactory = KeyFactory.getInstance("RSA");
        }

    /**
     * {@inheritDoc} -- when called without arguments, print usage to stdout.
     */
    @SneakyThrows @Override
    public void run()
        {
        CommandLine.usage(new CommandLineMain(), System.out);
        }

    @CommandLine.Command(name = "seal")
    void seal()
        {
        // prepare keys: private key of sealer is required.

        // read stdin
        // write stdout
        // error to stderr


        }

    @CommandLine.Command(name = "unseal")
    void unseal()
        {

        }


    // intentionally allowing standard exceptions to happen without explicit checks, for shorter code.
    PublicKey readRSAPublicKeyFromPEMFile(final Path inputFile) throws IOException, InvalidKeySpecException
        {
        FileReader keyReader = new FileReader(inputFile.toFile());
        PemReader pemReader = new PemReader(keyReader);
        PemObject pemObject = pemReader.readPemObject();

        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pemObject.getContent());
        return (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);
        }


    PrivateKey readRSAPrivateKeyFromPKCS8PEMFile(final Path inputFile) throws IOException, InvalidKeySpecException
        {

        FileReader keyReader = new FileReader(inputFile.toFile());
        PemReader pemReader = new PemReader(keyReader);
        PemObject pemObject = pemReader.readPemObject();
        // or use PEMParser, JcaPEMKeyConverter, and then go
        // (RSAPrivateKey) converter.getPrivateKey(PrivateKeyInfo.getInstance(pemParser.readObject()));

        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
        return (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);
        }

}
//___EOF___
