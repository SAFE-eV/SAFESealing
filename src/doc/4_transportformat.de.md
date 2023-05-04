# Transportformat

Für die Verwendung im OCMF-Kontext werden verschlüsselte Daten, Algorithmenkennungen, IV und dergleichen
in eine ASN.1-Struktur gepackt. Diese ist wie folgt aufgebaut:

## Übersicht

```
SEQUENCE
  OID                   Kennung des Formates
  INTEGER               Version des Formates
  CONTEXT_SPECIFIC[0]   Verschluesselungs-Ebene
  CONTEXT_SPECIFIC[1]   Schluesselaustausch-Ebene
  CONTEXT_SPECIFIC[2]   Authentisierungs-Daten
  OCTET STRING          Verschluesselte Daten
```
## Verschlüsselungs-Ebene

Diese Ebene ist notwendig. Je nach Verschlüsselungsverfahren (RSA oder AES)
sind weitere Daten wie IV notwendig bzw. überflüssig.

```
CONTEXT_SPECIFIC[0]  Verschluesselungs-Ebene enthält in Version 1:
    SEQUENCE
        OID             Kennung des Verfahrens
        CONTEXT[0]      informationen über die Verschlüsselung
            OID         Kennung des Verschlüsselungsverfahrens          
        CONTEXT[1]      Informationen über optionale Kompression
            OID         Kennung des Kompressionsverfahrens (default: NONE) 
        CONTEXT[2]      optionale Angabe der Schlüsselgröße
            INTEGER     Schlüsselgröße, in bit
        CONTEXT[3]      optionale Angabe der Nonce-Größe (in Version 1 nicht genutzt)
            INTEGER     Nonce-Größe, in bit        
        OCTET STRING    IV des symmetrischen Verschlüsselungsverfahrens (kann z.B. bei RSA und AES/ECB weggelassen werden)   
```


## Schlüsselaustausch-Ebene

Diese ist optional; ist sie nicht vorhanden, so muß für die Verschlüsselungsebene
das Schlüsselmaterial bereits vorhanden sein.

Diese Ebene wird bislang nur für ECDHE verwendet.

```
CONTEXT_SPECIFIC[1]  Schluesselabgleich-Ebene enthält in Version 1:
    SEQUENCE
        OID             Kennung des Keyagreement-Verfahrens
        OCTET STRING    Schlüsseldiversifikationsdaten
        CONTEXT[0]      
            OID         Schlüsseldiversifikationsalgorithmus
        CONTEXT[1]      EC-Verfahren (optional, mit default )
            OID         Kennung der EC
        CONTEXT[2]      EC-Kurve (optional, kein default); siehe IETF RFC 3279 
        CONTEXT[3]      Schlüsselreferenzen (optional, kein default) ; siehe IETF RFC 5480
```

### Authentizitäts-Ebene

Ebene für spätere Verwendung
```
CONTEXT_SPECIFIC[2]  Absender-Authentizitäts-Ebene; in Version 1 ungenutzt.
    SEQUENCE
        OID             Kennung des Verfahrens       
```
