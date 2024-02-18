# transport format

For use of IIP in OCMF context, encrypted data, algorithm OIDs, IV and other required data is combined
into an ASN.1 byte stream. This is its structure: 

## top level

```
SEQUENCE
  OID                   format ID
  INTEGER               format version
  CONTEXT_SPECIFIC[0]   encryption layer
  CONTEXT_SPECIFIC[1]   key exchange layer
  CONTEXT_SPECIFIC[2]   key authentication layer
  OCTET STRING          encrypted data
```
## encryption layer

This layer is required. Depending on encryption algorithm and its operatio mode
additional data like IV may be required or inconsequential.

```
CONTEXT_SPECIFIC[0]     encryption layer, version 1
    SEQUENCE
        OID             procedure OID 
        CONTEXT[0]      encryption info
            OID         encryption algorithm OID          
        CONTEXT[1]      compression info, optionals
            OID         compression OID (default: NONE) 
        CONTEXT[2]      key information, optional
            INTEGER     key size, in bit
        CONTEXT[3]      padding nonce information, optional
            INTEGER     padding nonce size, in bit
        OCTET STRING    IV for encryption. required or not, depending on algorithm and operation mode.    
```


## key agreement layer

This is optional; if not provided, the encryption layer has to get keys provided by caller. 

This layer is currently used with ECDHE.

```
CONTEXT_SPECIFIC[1]     key agreement layer, version 1
    SEQUENCE
        OID             key agreement algorithm OID
        OCTET STRING    key diversification data/IV
        CONTEXT[0]      key diversification info
            OID         key diversification algorithm OID
        CONTEXT[1]      EC algorithm info
            OID         ECC crypto OID
        CONTEXT[2]      ECC curve data, optional; see IETF RFC 3279 
        CONTEXT[3]      key reference info, optional; see IETF RFC 5480
```

### key authentication layer

for later use
```
CONTEXT_SPECIFIC[2]     key authentication layer, version 1
    SEQUENCE
        OID             authentication procedure OID       
```
