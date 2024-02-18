package com.metabit.custom.safe.iip;

import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static com.metabit.custom.safe.iip.shared.SharedTestingCode.generateRSAKeyPair;

/**
 * generating RSA keys is the main effort / time consuming activity in our tests.
 * It is an efficiency gain to generate and store them in advance, then read and reuse them.
 * This class provides an implementation for the purpose.
 */
public class RSATestKeyStorage
{

private Path          keyStorageFile;
private List<KeyPair> keyPairs;

public RSATestKeyStorage()
    {
    init("/tmp/keyteststorage.json");
    }

void init(final String keyStorageFileName)
    {
    keyStorageFile = Paths.get(keyStorageFileName);
//    if (keyStorageFile.toFile().canRead() != true)
//        throw new IllegalArgumentException(keyStorageFileName+" is not readable");
    }


@Test
void dummy()
        throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException
    {
    keyStorageFile = Paths.get("/tmp/testkeystorage.txt");
    keyPairs = generateRSAKeyPairs(2048, 5);
    writeKeyStorageFile("RSA 2045 E4", 2048);
    }

private static List<KeyPair> generateRSAKeyPairs(final int keySizeInBit, final int numberOfKeys)
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {
    // prepare keypairs to work with
    List<KeyPair> keyPairs = new ArrayList<>(numberOfKeys);
    for (int i = 0; i < numberOfKeys; i++)
        {
        keyPairs.add(generateRSAKeyPair(keySizeInBit));
        }
    return keyPairs;
    }
/*
 * the format we use is simply a sequence of key data lines.
 */

public void readKeyStorageFile()
    {


    }

public void writeKeyStorageFile(final String algorithmForHeader, final int keysizesInBitForHeader)
        throws IOException
    {
    Base64.Encoder encoder = Base64.getEncoder();

//    if (!keyStorageFile.toFile().canWrite()) -- only if exists
//        throw new IllegalArgumentException(keyStorageFile+" not writable");
    PrintWriter pw = new PrintWriter(keyStorageFile.toAbsolutePath().toString());
    BufferedWriter out = new BufferedWriter(pw);
    //--- write header
    out.write('{'); // JSON header


    out.write("\"algorithm\":\"RSA\",\n");
    out.write("\"keysize\":"+keysizesInBitForHeader+",\n");
    out.write("\n\"keys\":[\n");
    //--- write body
    boolean firstLine = true;
    for (KeyPair keyPair : keyPairs)
        {
        if (firstLine)
            { firstLine = false; }
        else
            { out.write(','); }
        String rsakeyJSON = convertRSAKeyToJSON(keyPair, encoder);
        out.write(rsakeyJSON);
        // for some reason, the java crypt API does not allow us to get the bitsize of a key without the workaround of its text representation.
        }
    //--- write footer
    out.write("]}\n");
    //--- close
    out.flush();
    pw.close();
    ;
    }

    public static String convertRSAKeyToJSON(KeyPair keyPair, Base64.Encoder encoder)
            throws IOException
        {
        String priv = encoder.encodeToString(keyPair.getPrivate().getEncoded());
        String publ = encoder.encodeToString(keyPair.getPublic().getEncoded());
        return String.format("{\n\t\"privkey\":\"%s\", \n\t\"pubkey\":\"%s\"}\n", priv, publ);
        }

}
