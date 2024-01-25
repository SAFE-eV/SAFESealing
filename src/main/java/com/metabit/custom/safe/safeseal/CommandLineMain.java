/*
 *  this source code is part of the SAFEsealing package published by S.A.F.E. e.V.
 *  written 2022-2023 by JWilkes, metabit,
 *  placed under CC-BY-ND 4.0 license.
 */
package com.metabit.custom.safe.safeseal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import picocli.CommandLine;

import javax.crypto.BadPaddingException;
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
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
 * <p>
 * WORK IN PROGRESS!
 */
public class CommandLineMain implements Runnable
{

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

    @CommandLine.Option(names = {"-a", "--algorithm"}, defaultValue = "2")
    String algorithmVersionString = "2"; // picoCLI default setting fails here.
    @CommandLine.Option(names = {"-P", "--privateKey"}) Path privateKeyInfo;
    @CommandLine.Option(names = {"-p", "--publicKey"}) Path publicKeyInfo;
    @CommandLine.Option(names = {"-u", "--uniqueID"}) private Long uniqueIDValue;
    @CommandLine.Option(names = {"-i", "--input"}, defaultValue = "-") String inputName;
    @CommandLine.Option(names = {"-o", "--output"}, defaultValue = "-") String outputName;

    CommandLineMain() throws NoSuchAlgorithmException
        {
        Provider securityProvider = Security.getProvider("BC");
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
    @Override
    public void run()
        {
        try
            {
            CommandLine.usage(new CommandLineMain(), System.out);
            }
        catch (final java.lang.Throwable $ex)
            {
            throw lombok.Lombok.sneakyThrow($ex);
            }
        }

    @CommandLine.Command(name = "seal")
    void seal()
        {
        int algorithmVersion = Integer.parseInt(algorithmVersionString);  // workaround for picoCLI failure
        // prepare keys: private key of sealer is required.
        String fileContents;
        try
            {
            // prepare I/O
            InputStream input;
            OutputStream output;
            if (inputName.equals("-"))
                {input = System.in;}
            else
                {input = new FileInputStream(inputName);}
            if (outputName.equals("-"))
                {output = System.out;}
            else
                {output = Files.newOutputStream(Paths.get(outputName));}
            // prepare private key
            fileContents = new String(Files.readAllBytes(privateKeyInfo), Charset.defaultCharset());
            final RSAPrivateKey sealerKey = readRSAPrivateKeyFromPKCS8PEM(fileContents);
            assert (sealerKey.getAlgorithm().equals("RSA"));

            // read stdin
            final byte[] payload = input.readAllBytes();
            // process
            SAFESealSealer sealer = new SAFESealSealer(algorithmVersion);
            sealer.setCompressionMode(true);
            byte[] sealed = sealer.seal(sealerKey, null, payload, uniqueIDValue);
            // write stdout
            output.write(sealed);
            output.flush();
            }
        // error to stderr
        catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e)
            {
            System.err.println(e.getMessage());
            System.exit(1);
            }
        catch (BadPaddingException e)
            {
            System.err.println(e.getMessage());
            System.exit(2);
            }
        return; // or System.exit(0);
        }

    @CommandLine.Command(name = "reveal")
    void unseal()
        {
        int algorithmVersion = Integer.parseInt(algorithmVersionString);  // workaround for picoCLI failure
        // prepare keys: private key of sealer is required.
        String fileContents = null;
        try
            {
            // prepare I/O
            InputStream input;
            OutputStream output;
            if (inputName.equals("-"))
                {input = System.in;}
            else
                {input = new FileInputStream(inputName);}
            if (outputName.equals("-"))
                {output = System.out;}
            else
                {output = Files.newOutputStream(Paths.get(outputName));}

            // prepare public key
            fileContents = new String(Files.readAllBytes(publicKeyInfo), Charset.defaultCharset());
            final RSAPublicKey sealerPublicKey = readRSAPublicKeyFromPEM(fileContents);
            assert (sealerPublicKey.getAlgorithm().equals("RSA"));

            // read stdin
            final byte[] sealedData = input.readAllBytes();
            // process
            SAFESealRevealer revealer = new SAFESealRevealer(algorithmVersion);
            byte[] revealedData = revealer.reveal(sealerPublicKey, null, sealedData);
            // write stdout
            output.write(revealedData);
            output.flush();
            }
        // error to stderr
        catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e)
            {
            System.err.println(e.getMessage());
            System.exit(1);
            }
        catch (BadPaddingException e)
            {
            System.err.println(e.getMessage());
            System.exit(2);
            }
        return; // or System.exit(0);
        }

    /**
     * read a RSA public key from an PEM file (see RFC5280, SubjectPublicKeyInfo).
     *
     * @param pemEncodedRSAPublicKey the PEM encoded public key
     * @return RSA public key object
     * @throws NoSuchAlgorithmException if the algorithm doesn't match expectations
     * @throws InvalidKeySpecException  if the key has some other issue
     * @see {RFC5208}
     */
    RSAPublicKey readRSAPublicKeyFromPEM(final String pemEncodedRSAPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException
        {
        String publicKeyPEM = pemEncodedRSAPublicKey.replace("-----BEGIN PUBLIC KEY-----", "").replaceAll(System.lineSeparator(), "").replace("-----END PUBLIC KEY-----", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        }

    /**
     * read an RSA private key from an PKCS8 PEM file.
     *
     * @param pkcs8encodedRSAPrivateKey
     * @return RSA private key object
     * @throws NoSuchAlgorithmException if the algorithm doesn't match expectations
     * @throws InvalidKeySpecException  if the key has some other issue
     * @see {RFC5208}
     */
    RSAPrivateKey readRSAPrivateKeyFromPKCS8PEM(final String pkcs8encodedRSAPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException
        {
        String privateKeyPEM = pkcs8encodedRSAPrivateKey.replace("-----BEGIN PRIVATE KEY-----", "").replaceAll(System.lineSeparator(), "").replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        }
}
//___EOF___
