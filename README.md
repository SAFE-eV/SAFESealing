# IIP - Interleaved Integrity Padding

A method to provide integrity validation of an encrypted message without use of hashes or other MACs.

Publisher: SAFE e.V.  https://www.safe-ev.de/en/
Author: J.Wilkes, metabit

## goal

The purpose of this method and implementation is to provide means of conditioning a payload message for encryption 
in a way so its integrity can be validated after decryption, 
without using any hash or other "unique description of the message" in the overall process.

It does not aim to provide confidentiality, nor improve over well-know cryptographic padding schemes.

# Install and use

## import library

Add the library JAR to your project.

## build from source 

Be sure that maven is installed https://maven.apache.org/. To package the application run:

`mvn clean package`

This will create library JAR files in the target folder, named safesealing*.jar .
A number of tests will be run, taking some time.


`mvn install` allows you to use the JAR locally in your other projects.


## library use

* Add the JAR to your project.
* Import SAFESealSealer class.
* load your PrivateKey, get uniqueID, prepare payload to be sent. 
* Instantiate the SAFESealer class, then call its seal() function:

```java
    PrivateKey  senderPrivateKey;
    Long        uniqueID;
    byte[]      payload;
    ...
    SAFESealSealer  sealer  = new SAFESealSealer();
        
    byte[] sealedForTransport =  sealer.seal(senderPrivateKey, null, payload, uniqueID);
```
The resulting byte array contains the padded, encrypted, formatted, serialised representation ready for transport.


# development

In IntelliJ open the project as a maven project (choose the pom.xml file).

The main entry points of the application are the SAFESealingSealer and SAFESealingRevealer classes.

The application has 4 major packages.
* safeseal: API and commandline test
* iip:      this contains the core cryptography
* shared:   constants, functions, algorithm specifications
* safeseal/impl: the implementation behind the API

Additional crypto algorithms are to be added to shared/AlgorithmSpecCollection.java, and tested before use.

# background
## padding procedure description

Integrity without knowledge of payload data (plaintext) is achieved by to applying a random sequence of byte (nonce) 
to the message multiple times for protective purposes. 
This sequence is in no way related to the message contents. Its sole purpose is for integrity validation.

The message has to be encrypted with an encryption algorithm which provides a solid degree of diffusion
(see [references](#references) for background on diffusion; also see Avalanche Effect).

After decryption, the padding is checked for consistency of the protective nonce values. Should the ciphertext have been
changed, the change will have propagated to the protective nonce, where it will be detected.

Thus, integrity can be provided without use of the plaintext contents.

# implementation

This repository contains both the core algorithm implementation, tests, 
as well as code for use as a library component for integration, including serialisation.

The core algorithm described above is implemented in the class InterleavedIntegrityPadding.java; it is pure JDK Java.

The library uses the BouncyCastle crypto provider library.

The tests use additional libraries and maven build engine plugins.

# References

* [1] Claude E. Shannon, "A Mathematical Theory of Cryptography", Bell System Technical Memo MM 45-110-02, September 1, 1945.
* [2] Claude E. Shannon, "Communication Theory of Secrecy Systems", Bell System Technical Journal, vol. 28-4, pages 656–715, 1949.
* [3] "Information Theory and Entropy". Model Based Inference in the Life Sciences: A Primer on Evidence. Springer New York. 2008-01-01. pp. 51–82. doi:10.1007/978-0-387-74075-1_3. ISBN 9780387740737.

