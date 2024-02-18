# Interleaved Integrity Padding

proposed naming: "IIP" = Interleaved Integrity Padding.

## Purpose and motivation

This procedure is used to ensure the integrity of encrypted messages, without using any plaintext property (such as an HMAC).


This was motivated by patent reasons. It was strictly to be avoided to use any property derived from the plaintext.
Therefore, the usual MAC procedures Hash/HMAC/... and signatures could not be used.

## Basic idea

According to Shannon, cryptographic encryption methods have the properties [Confusion and diffusion](https://en.wikipedia.org/wiki/Confusion_and_diffusion).

For our purposes, the diffusion is of interest: each bit of the plaintext should be connected to as many bits of the ciphertext as possible,
and vice versa. Related is the [Avalanche Effect](https://en.wikipedia.org/wiki/Avalanche_effect).

This invention is based on additional protection data being appended, prepended, or inserted to the actual user data. 
This protection data can be randomly generated, fixed, or separately negotiated.

After decryption of the received message, the protection data is checked for consistency.
If the encrypted message has been changed, the protection data has also been changed by diffusion.
In this way, the integrity of a message can be checked on the basis of the protection data consistency 
without having to know the plaintext data or to form any checksums, MAC or the like on it.

Note for citations:
This procedure was invented in 2022 by Jo Wilkes, metabit. The reason for this was a request from SAFE e.V.,
for whose use the reference implementation was made on behalf of ABL GmbH.

## Continuation of the idea

A block counter can be modulated on the protection datam, so it varies per block, and the order of the blocks can be checked.
(also: protection data as a pseudo-random sequence).

Additional unused random data can be added in each case, in the first and/or following blocks, 
so that the message content is less predictable or malleable.

The block cipher used can provide additional chaining of the blocks.


## Caveats

If several data blocks are sent, at least one set of protection data must be available for each data block.

The encryption method used must always be checked for diffusion. The effectiveness of the IIP depends on the diffusion 
of the encryption method, and the avalanche effect should be as comprehensive as possible.

The protection effect depends on encryption algorithm and ratio protective data to plaintext.
Especially, the usual streaming ciphers, and operation modes for symmetric ciphers which correspond 
to streaming, do *not* exhibit diffusion. With CFB, OFB, CTR and similar modes, one can change one bit of ciphertext
and change exactly one bit of plaintext with it. This makes them unsuitable for use with IIP.
This procedure is therefore by no means independent of the rest of the cryptography, but on the contrary must be matched
with it.

(With ciphers using substitution tables, for example, it is desirable the SAC (Strict Avalanche Criterion),
or at least the non-strict Avalanche Criterion is met.)
