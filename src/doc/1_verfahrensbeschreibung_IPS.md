# Integrity Padding Signature

Vorgeschlagenes Kürzel: "IPS" = Integrity Padding Signature.

Dies ist eine Weiterentwicklung des IIP = Interleaved Integrity Padding.

## Zweck und Motivation

Diese Verfahren dienen dazu, die Integrität von verschlüsselten Nachrichten sicherzustellen,
ohne ein Merkmal der Nachricht (wie z.B. eine HMAC) zu verwenden.

Der Bedarf hierfür wurde durch patentrechtliche Gründe geschaffen. Es war strikt zu vermeiden, eine wie auch immer
abgeleitete Eigenschaft der Nutzdaten (Plaintext) zu verwenden; daher durften die üblichen MAC-Verfahren Hash/HMAC/...
nicht zur Anwendung kommen.

## Grundidee IIP

Kryptographische Verschlüsselungsverfahren weisen nach Shannon die Eigenschaften
[Confusion and diffusion](https://en.wikipedia.org/wiki/Confusion_and_diffusion) auf.

Für unsere Zwecke interessant ist hierbei die Diffusion: jedes Bit des Plaintexts soll mit möglichst vielen Bits
im Ciphertext verbunden sein, und umgekehrt. Verwandt ist der [Avalanche Effect](https://en.wikipedia.org/wiki/Avalanche_effect)

Diese Erfindung basiert darauf, daß den eigentlichen Nutzdaten zusätzliche Schutzdaten mitgegeben werden. Diese können
zufällig erzeugt, festgelegt, oder separat ausgehandelt sein.

Nach Entschlüsselung der empfangenen Nachricht werden die Schutzdaten auf ihre Konsistenz geprüft.
Sollte die verschlüsselte Nachricht verändert worden sein, so sind durch Diffusion auch die Schutzdaten verändert worden.
So kann man anhand der Schutzdaten die Integrität einer Nachricht prüfen, ohne die Nutzdaten zu kennen oder darüber
irgendwelche Prüfsummen zu bilden.

Hinweis für Zitate:
Erfunden wurde dieses Verfahren 2022 von Jo Wilkes, metabit. Anlass war ein Wunsch des SAFE e.V.,
für dessen Gebrauch die Referenzimplementierung im Auftrag der ABL GmbH angefertigt wurde.

## Grundidee IPS

IPS wurde von der formalen Beweisbarkeit her angegangen; Ziel ist EUF-CMA-Sicherheit.
(EUF-CMA: „existentially unforgeable under chosen-message attacks“)

Aufbauend darauf, daß RSA-FDH als EUF-CMA-sicher angesehen wird, werden Verfahren und Beweis so aufgebaut,
daß sie ebenfalls in Ableitung daraus diese Eigenschaft(en) erhalten - ohne daß dabei Hashes u.a. zum Einsatz kämen.

Statt eines "Full Domain Hash" (FDH) werden in Anlehnung zum bereits beschriebenen und implementierten IIP
Schutzdaten und Nutzdaten zusammengefügt, mittels mehrfacher AES-CBC-Verschlüsselung verflochten, und dann einmalig
mit RSA in Signatur-Richtung verarbeitet (Verschlüsselung mit private key, Entschlüsselung mit public key).

Die solchermaßen verschlüsselte Nachricht kann dann nicht gefälscht/verfälscht werden, ohne daß der Angreifer zugleich
in der Lage sein muß/sein müßte, RSA generell zu "knacken".
