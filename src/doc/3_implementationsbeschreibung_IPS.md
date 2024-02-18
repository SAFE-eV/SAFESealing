# Implementation des IPS-Verfahrens für praktischen Gebrauch

## Anforderungen

Pro zu verarbeitende Nachricht wird benötigt:

* einmalig "plain RSA" mit der gewählten Schlüsselgröße, Verschlüsselungsaufruf mit private Key.
* dreimal AES-CBC über die gesamte vorbereitete (gepaddete) Nachricht.

Benötigte Kryptographie-Funktionalität:

* "RSA/ECB/NoPadding"
* "AES/CBC/NoPadding"
* Erzeugung sicherer Zufallszahlen

Auf die Eigenheiten gewisser RSA-Implementationen wurde Rücksicht genommen.

## Ausformung des Verfahrens für die Praxis

### Signieren

1. Berechnungen
   1. Die zu verwendenden Zahlwerte werden ermittelt: Blockgrößen des asymmetrischen (RSA) und symmetrischen (AES)-Verfahrens,
      Größe der abzusichernden Nachricht, Konstanten; alles in Byte umgerechnet.
   2. Darauf basierend werden Berechnungen vorgenommen zu Anzahl der Blöcke im symmetrischen und asymmetrischen Verfahren;
      daraus wiederum die Größe des benötigten Puffers.

Für RSA-Eigenheiten speziell wird der Puffer zwei byte größer gewählt; in der weiteren Verarbeitung werden diese Bytes
jedoch ignoriert (per start-offset), außer im RSA-Schritt, wo sie ausdrücklich erwähnt werden.

Der hier beschreibene Ablauf geht von in-place-Verarbeitung aus, d.h. der jeweilige Output geht an denselben offset,
wie der zugehörige Input. Bedingung hierfür ist, daß Input und Output jeweils gleich groß sind.

2. Vorbereitung
   1. Es werden drei Schlüssel für das symmetrische Verfahren erzeugt; die zugehörigen Initialisierungsvektoren IV
      sind mit Konstanten belegt.
   2. Der Puffer wird alloziert.
   3. Es wird ein nonce mit Zufallsdaten erzeugt; dessen Länge ist darauf abgestimmt,
      mit den beiden nachfolgenden unsigned int wiederum einen "inner block" zu ergeben.

3. Padding.
   Der Puffer (ab dem start-offset 2) wird nach folgendem Schema befüllt:
   1. virtuelle Aufteilung in Blöcke der "outer Blocks" des asymmetrischen Verfahrens; Blockzähler hierzu beginnend bei 0.
   2. Konstante Kennung ("Magic ID"), Länge entsprechend Größe der "inner blocks" der symmetrischen Verschlüsselung.
   3. Nonce.
   4. Länge der gesamten Plaintext/Payload-Nachricht; Darstellung als 4 byte unsigned big-endian integer.
   5. Blockzähler, siehe oben. Darstellung als 4 byte unsigned big-endian integer.
   6. Ausschnitt des Plaintextes bis zur Grenze des "outer Blocks".

Beim letzten Block sind nach Ende des Plaintextes ggf. nicht definierte Bytes mit 0x00 zu füllen,
sofern nicht bereits bei Initialisierung des Puffers geschehen.

Das Konzept "Schutzdaten" wird hier zusammengesetzt aus

- der festen Konstanten Kennung,
- dem pro Nachricht unterschiedlichen nonce,
- der Längenangabe, welche zudem zwischen den Blöcken einer Nachricht identisch sein muß (und anderen Bedingungen genügen),
- dem Blockzähler, welcher zudem der Reihenfolge der Blöcke einer Nachricht entsprechen muß.

All diese Schutzdaten werden mit den Nutzdaten (dem jeweiligen Ausschnitt des Plaintextes) mittels AES, AES, Umkehrung,
AES mehrfach verflochten.

4. Der Pufferinhalt wird symmetrisch mit dem ersten Schlüssel verschlüsselt: AES-CBC-NoPadding(key1,IV1)
5. Der Pufferinhalt wird symmetrisch mit dem zweiten Schlüssel verschlüsselt: AES-CBC-NoPadding(key2,IV2)
6. Der Pufferinhalt wird in der Reihenfolge umgekehrt, und zwar in Blockgröße der symmetrischen Verschlüsselung
7. Der Pufferinhalt wird symmetrisch mit dem dritten Schlüssel verschlüsselt: AES-CBC-NoPadding(key3,IV3)

8. Der Pufferinhalt wird asymmetrisch mit dem privaten asymmetrischen Schlüssel verschlüsselt.
   1. in die beiden zusätzlichen Bytes vor dem regulären puffer werden konstante Werte geschrieben.
   2. dort beginnend, wird mit RSA-ECB-NoPadding(privateKey) verschlüsselt.
      Das heißt, es werden die beiden vorangestellten bytes, und die ersten (RSABlockgröße-2) bytes des
      zuvor bearbeiteten Puffers der RSA-encrypt-Funktion zur Verarbeitung übergeben.

9. Das gesamte Resultat stellt zusammen mit den drei symmetrischen Schlüsseln als Bündel das Chiffrat dar, welches
   zu übermitteln ist.

### Entschlüsseln und Prüfen

Auch hier wird von in-place-Verarbeitung ausgegangen; die Allokation des Resultatpuffers findet erst verzögert statt.

1. Berechnungen
   1. Ermittlung der Blockgrößen von asymmetrischem und symmetrischen Verfahren
   2. Prüfung, ob die übergebenen Schlüssel und Datenlänge damit zusammenpassen.
      Die Länge des ciphertextes -2 muß ohne Rest durch die Blockgrößen teilbar sein;
      oder anders gesagt, Teilen der Ciphertext-Länge durch die Blockgrößen muß Rest 2 ergeben.
   3. Anzahl der "outer blocks" des asymmetrischen Verfahrens durch Division ermitteln.

2. Entschlüsselung
   1. asymmetrische Entschlüsselungs-Funktion durchführen vom absoluten ciphertext-Anfang (offset 0) aus.
      RSA-ECB-NoPadding(publicKey).
      Die ersten beiden Bytes werden ignoriert; die weitere Verarbeitung beginnt bei offset 2.
      An dieser Stelle können bereits Veränderungen des ciphertextes dazu führen, daß die RSA-Funktion Fehler
      meldet. Diese sind als erwarteter Erkennungs-Fall zu behandeln: Ablehnung der Eingabe als manipuliert.
   2. symmetrische Entschlüsselung mit key3, IV3: AES-CBC-NoPadding(key3,IV3)
   3. Der Pufferinhalt wird in der Reihenfolge umgekehrt, und zwar in Blockgröße der symmetrischen Verschlüsselung
   4. symmetrische Entschlüsselung mit key2, IV2: AES-CBC-NoPadding(key2,IV2)
   5. symmetrische Entschlüsselung mit key1, IV1: AES-CBC-NoPadding(key1,IV1)

3. Prüfung und Extraktion
   1. Der nunmehr entschlüsselte Pufferinhalt ist in Blöcke der zum asymmetrischen Verfahren passenden Größe zu teilen,
      daraus resultiert ein Blockzähler.
   2. Schleife, pro solchem Block:
      1. Prüfung, ob die Kennung ("Magic ID") exakt den Erwartungen entspricht.
         Ähnlich IIP wird hier erkannt, wenn Abweichungen vorliegen sollten.
      2. Überspringen der Zufallsbytes.
      3. Auslesen der Plaintext-Länge. Beim ersten Block ist hier noch kein Vergleichswert bekannt;
         bei allen folgenden Blöcken wird geprüft, ob die Werte jeweils identisch sind.
         Zusätzlich wird die Plausibilität des ersten Wertes geprüft.
      4. Auslesen der Blocknummer, Vergleich mit dem Blockzähler. Diese müssen ebenfalls übereinstimmen.
      5. Verwendung der Payload/plaintext-Daten bis zum Ende des jeweiligen "outer blocks".

Die Extraktion des Plaintextes und die Puffer-Allokation dafür kann entweder während der Prüfungs-Schleife,
oder nachträglich geschehen. Falls letzeres, kann die Prüffunktion den Längenwert zurückgeben; falls ersteres,
den bereits extrahierten Plaintext.

### Aufbau

##### Version 2

Die zu verschlüsselnde Nachricht wird zusammengesetzt aus:

* κ: Security parameter
* N : RSA modulus
* e: public RSA exponent
* d: private RSA exponent
* sk: secret signing key
* vk: public verification key
* C κ : Constant for security parameter κ
* l: block length of the (ideal) cipher
* n: length parameter denoting the number of blocks to be used.
* o: key length of the ideal cipher
* M: message space
* k: key
* r: random nonce
* ⊥: special error symbol
* m: message, plaintext
* |m|: bit length of |m|, presumptive during unpadding
* m i : i-th block of i, not necessarily of length l
* n �� : length parameter denoting the number of blocks of m for the first padding step (i.e. number of
  blocks of “RSA block length”)
* m � : processed message / plaintext (after first step of the padding before encryption)
* m � i , i-th block of m� , of “RSA block length” (during padding) resp. IC block length l (during unpadding)
* i: counter
* c: Encryption of m � under k using SKE (second padding step)
* ci : blocks of c of length l
* n � : number of blocks of c.
* c n 1 : First l(κ) − 16 bits of c n
* c n 2 : Last 16 bits of c n
* c � 1 : First part of third padding step of RSA block length (RSA −1 will be applied to this part)
* • c � 2 : Second part of third padding step (will be sent out-of-band)
* t: temporary variable for the presumptive length of m during unpadding encoded as bits
* v: temporary variable during unpadding where the reconstructed message is stored
* ε: the empty word
* t � : temporary variable for the recovered length in each “RSA-length block”
* u � : temporary variable for the recovered index in each “RSA-length block”
* |v|: Length of unpadded message
* σ: (presumptive) signature
* σ � : RSA−1 (c � 1 )

Ck | r | (|m|) | i | m[i]

@TODO

##### Version 1

Die zu verschlüsselnde Nachricht wird zusammengesetzt aus:

`( I | R0 | P | Mlen ) | ( P_i M_i )+ | (P_i M_i R1)* | (P_i | R2)*`

| Zeichen | Bedeutung                                                                     |
|---------|-------------------------------------------------------------------------------|
| P       | padding nonce für dieses padding ("inner nonce")                              |
| Mlen    | message length, länge des eigentlichen Inhalts                                |
| I       | "magic ID" - ggf. gekürzt, so daß stets ein R0 vorhanden ist.                 |
| R0      | Zufallsdaten, um stets im ersten Block ungenutzen Zufall zu haben             |
| P_i     | abgeleitete padding werte an Position "i"                                     |
| M_i     | Abschnitt Nummer "i" der Nutzdaten                                            |
| +       | Wiederholung des Musters (mindestens ein Mal), Datenblöcke mit steigendem i   |
| *       | letzter Block wird abhängig vom "Rest" nach Aufteilung der Nutzdaten gebildet |
| R1      | optionales padding im letzten Datenblock auf Blockgröße des Ciphers           |
| R2      | Zufallsdaten zum Auffüllen zur Blockgrenze, falls trailing block nötig        |

In obiger Notation sind jeweils die in () gestellten Teile in ihrer Länge auf die Blockgröße des
Verschlüsselungsverfahrens abgestimmt.

Die Größe von P_i + M_i muß exakt der Blockgröße des Verschlüsselungsverfahrens entsprechen;
in der Praxis wird die Größe von M_i aus dieser abzüglich der Größe von P_i berechnet.

(Im Rahmen dieses Dokumentes wird _i geschrieben; wo entsprechende Formatierung verfügbar ist, soll dies mit einem
tiefergestellten i dargestellt werden.)

Wenn die Aufteilung der Nutzdaten nicht genau aufgeht, also für R1 ein Platz ist,
wird als letzter Block (P_i M_i R1) geschrieben. Geht die Aufteilung der
Nutzdaten jedoch genau auf und die Länge eines solchen R1 wäre 0
(anders gesagt: ist die Länge vom letzten M_i == 0), dann wird der Block (P_i | R2) angehangen.
So endet die gepaddete Sequenz in jedem Fall auf Zufallsdaten.

In obiger Darstellung wird, wie bei Kryptographie üblich, das Zeichen "|" als Symbol für Verkettung verwendet.
Daher steht es für die Darstellung der Alternative (entweder "(P_i M_i R1)" oder "(P_i | R2)") nicht zur Verfügung.

#### Darstellung für Implementation

Einer Nachricht **M** mit einer Länge von **M_len** bytes ist mit IIP zu verarbeiten.
Zudem ist als Input notwendig, die Blockgröße des Verschlüsselungsverfahrens zu kennen, diese sei **CB_len**.

( Die Nachricht "M" wird hier auch als Payload oder "Plaintext" bezeichnet, im Kontrast zum "Ciphertext" nach Verschlüsselung.)

Die Nachricht muß in mehrere aufeinanderfolgende Datenblöcke aufgeteilt werden, welche dann jeweils verschlüsselt werden.
Die Länge dieser Blöcke CB_len hängt von Algorithmus und Schlüsselgröße ab.
Beispielsweise beträgt bei RSA 2048 bit diese Blockgröße 255 byte
(2048/8=256; da das MSB stets gesetzt sein muß, wird von Implementationen das oberste Byte belegt/gesperrt).

Folgende Typen von Datenblöcken werden erzeugt:

1. der Headerblock, der stets als erstes gesendet wird;
2. "mittlere" Datenblöcke, wenn noch weitere Datenblöcke folgen.
3. ein letzter Datenblock in der Variante, wenn nach den Nutzdaten noch Platz übrig war;
4. ein letzter Datenblock in der Variante, wenn die Nutzdaten ohne Rest in den vorigen Block gepasst haben.

Es gibt nur einen letzten Datenblock, wobei abhängig von der Nachrichtenlänge entweder Typ 3 oder Typ 4 verwendet wird.

Der erste Block setzt sich wie folgt zusammen:

1. eine feste Bytefolge **I**
2. Zufallsdaten **R0**
3. die Länge der verpackten Nutzdaten **M_len**
4. der initiale Padding Nonce **P**

Die feste Bytefolge **I** dient als Magic ID mit Versionsnummer, auch um vorweg die zu verwendenden Konstanten bestimmen
zu können. Diese Konstanten sind insbesondere Repräsentationsgrößen: wieviele Bytes **M_len** und **P** groß sind.
In Version 1 gelten folgende Werte:

| Kennung | Länge  | Wert                             |
|---------|--------|----------------------------------|
| I       | 8 (-x) | 3e 7a b1 7C 5A FE E4 10          |
| M_len   | 4      | Payload=Plaintext-Länge, in byte |
| P       | 4      | zufällig erzeugter Startwert     |

Zwischen I und M_len wird mit Zufallswerten R0 aufgefüllt, so daß insgesamt die Blockgröße CB_len entsteht.
Für den Fall, daß die Blockgröße so klein sein sollte, daß zuwenig Platz ist, wird I gekürzt, jedoch auf nicht weniger
als 3 byte. Mindestens ein Zufallsbyte R0 wird dem ersten Block immer mitgegeben.

Im ersten Block werden keine Plaintext-Daten untergebracht, da P hier zum ersten Mal erscheint - es gibt noch keinen
Vergleichswert, zu dem eine Abweichung auffallen könnte. Nutzdaten im ersten Block wären ungeschützt.

In jedem nachfolgenden Datenblock werden Schutzdaten Pi und Nutzdaten kombiniert; im letzten zusätzlich noch Zufallswerte.
Da für die Schutzdaten jeweils länge(P) bytes benötigt werden, bleiben jeweils CB_len - sizeof(P) nutzbare Bytes pro Block.

Daraus läßt sich die Anzahl benötigter Blöcke berechnen: Anzahl Plaintextbytes dividiert durch Anzahl nutzbare Bytes,
aufgerundet; und falls die Division mit Rest 0 aufgehen sollte, noch ein Block extra.

Hieraus wiederum kann die Anzahl Bytes im Zielpuffer berechnet, und dessen Größe vorab geprüft - oder der Puffer passend
bereitgestellt werden.

Die Nutzdaten werden nun aufgeteilt in Abschnitte der Länge "nutzbare bytes"; die Blöcke werden befüllt mit dem jeweils
aktuellen Padding Pi und dem jeweiligen Abschnitt der Nutzdaten. (Blocktyp 2)

Das Padding Pi wird in Version 1 nicht einfach wiederholt, sondern als vorzeichenloser Integer mit Wraparound betrachtet
und pro Block hochgezählt. Auf diese Weise ist ein "inneres Chaining" vorhanden, durch welches Vertauschung von Blöcken
erkannt werden würde. (Spätere Versionen können Pseudozufalls-Datenströme verwenden, welche kryptanalytisch schwerer
vorherzusagen sind.)

Wenn die Aufteilung der Nutzdaten mit den Blöcken nicht komplett aufging, so sind im letzten Block noch freie Bytes
vorhanden; diese werden mit Zufallsdaten aufgefüllt (Blocktyp 3).

Sollte die Aufteilung jedoch glatt aufgegangen sein, wird ein weiterer Block angefügt, welcher außer dem nächsten Pi nur
Zufallsdaten enthält (Blocktyp 4).
So endet die zu verschlüsselnde Nachricht stets auf nicht genutzte Zufallsdaten.

Die so gepaddete Nachricht ist nun mit dem gewählten Verschlüsselungsalgorithmus zu verschlüsseln.
Dabei ist darauf zu achten, daß dessen korrekte Variante gewählt wird. Ein weiteres Padding ist nicht nötig;
bei den operation modes (chaining) ist sehr darauf zu achten, daß diese die Sicherheit des Verfahrens nicht gefährden.

### RSA

Die Verwendung mit RSA findet wie zuvor beschrieben statt; die gepaddeten blocks werden mit "plain" RSA verschlüsselt.

NB: Die gängigen Implementierungen verwenden auch bei RSA/ECB/NoPadding mindestens 1 byte für eigene Zwecke;
bei keysize 2048 bit = 256 byte sind also nur 255 byte pro Block verfügbar.
Ein äußeres Chaining ist möglich, jedoch nicht notwendig.

Bei RSA sind RSA/ECB/NoPadding und RSA/CBC/NoPadding zulässig; für die Referenzimplementierung wird RSA/ECB/NoPadding
verwendet.

--------

### EC

Eine Verwendung mit ECC direkt scheint möglich, aber für die praktische Verwendung durch Integratoren nicht angeraten.
Günstiger für Integration und Prüfung ist es, von etablierten Verfahren auszugehen.
Daher wurde ECDHE gewählt, um mittels EC auf ephemeral keys für symmetrische Verschlüsselung zu kommen.

### symmetrische Kryptographie
#### Chaining / Operation Mode
# Benennung

Der vorgeschlagene Name für dieses Verfahren im Kontext kryptographischer Algortihmen
lautet "IIP" = Interleaved Integrity Padding.

Es handelt sich dabei sowohl um ein Padding als auch ein Chaining.
"AES/ECB/IIP" und "AES/CBC/IIP" sind mögliche Benennungen von Algorithmen; bei diesen wird aber nicht ausgedrückt,
daß auch IIP ein Chaining vornimmt.

-----

## Verwendung in OCMF

Es wird der eichrechtlich relevante Teil der Nachricht gekapselt und mit diesem Verfahren verschlüsselt.

Im unverschlüsselten Teil der Nachricht finden sich Informationen über den Absender, aus welchen dessen Public Key
gefolgert werden kann (lookup), und ein nonce für die key diversification.

Absender (Ladestation mit Zähler) und Empfänger (Transparenz-Software oder Server-Backend) haben vor, und außerhalb
der Anwendung dieses Verfahrens ihre asymmetrischen Schlüsselpaare generiert und deren public keys ausgetauscht.

Für die Schlüsselableitung des symmetrischen Schlüssels wird ein möglichst einmaliger Zugabewert benötigt; dieser kann
aus der Paginierung, oder aus einem beliebigen anderen monoton steigendem Zähler stammen. Zufallswerte mit breiter
Streuung sind möglich, tragen aber das Risiko einer Kollision/Wiederverwendung desselben symmetrischen ephemeral keys.

-----

# Implementation

## Ablauf

Um einen Datensatz zu prüfen, müssen zunächst die verschüsselten Daten entschlüsselt werden.
Die entschlüsselten Daten werden dann mittels der Prüfung dieses Verfahrens auf Integrität geprüft.

### Padding und Verschlüsselung

Verschlüsselungsfunktion auf Absenderseite wird mit den zu verschlüsselnden Daten aufgerufen.

Der Absender erzeugt folgende Zufallswerte:

* einen "inneren nonce" (padding-nonce). Im aktuellen Verfahren ist dieser als 32 bit (4 Byte) groß definiert.
* falls vom Algorithmus benötigt, einen IV ("äußerer nonce")
* falls key agreement genutzt, einen Zähler- oder Zufallswert für die Schlüsselableitung.

Die Blockgröße des Verschlüsselungsverfahrens muß bekannt sein oder aus dessen Schlüsselgröße gefolgert werden.

RSA: Der Absender-Code erzeugt aus Nutzdaten und "innerem nonce" die zu verschlüsselnde Nachricht. (Details in eigenem Abschnitt.)

Der Private Key des Absenders wird sodann zur Verschlüsselung verwendet. (Mit dem zugehörigen Public Key kann auf
Empfängerseite dann die Identität des Absenders geprüft werden.) Zusätzliches Chaining oder Padding ist nicht nötig,
da IIP beides bereitstellt. Daher ist RSA/ECB/NoPadding die passende hier verwendete Form des Algorithmus'.

RSA/CBC ist möglich, der hierfür benötigte IV auch in Code und Format vorgesehen.

Von anderen Operation modes/chainings ist nachdrücklich abzuraten.

ECDHE+AES: Der Absender berechnet aus Public key des Empfängers, eigenem Private key, und dem Zufallswert für die Schlüsselableitung
eine Anzahl Bytes, welche als "ephemeral key" / Einmalschlüssel für das symmetrische Verschlüsselungsverfahren dienen.
Hierbei wird bereits das symmetrische Verschlüsselungsverfahren als Bitstrom-Generator eingesetzt, um gute Schlüsselqualität
und flexible Schlüssellänge zu erreichen; andernfalls wäre die Größe des symmetrischen Schlüssels an die Größe des
asymmetrischen Schlüssels gekoppelt.

Dann erzeugt der Absender aus Nutzdaten und "innerem nonce" die zu verschlüsselnde Nachricht. (Details in eigenem Abschnitt.)

Die symmetrische Verschlüsselung wird mit dem ephemeral key, dem generierten IV, und den gepaddeten Daten aufgerufen.

Auf Senderseite werden die verschlüsselten Daten nun zusammen mit dem IV und dem Wert für die Schlüsselableitung dem
allgemeineren Code für Formatierung in einer OCMF-Nachricht übergeben.

Nota Bene: der "innere nonce" verlässt die Verschlüsselungsfunktion nicht.

### Entschlüsselung und Prüfung

Allgemein:
Die Blockgröße des Verschlüsselungsverfahrens muß bekannt sein oder aus dessen Schlüsselgröße gefolgert werden.

RSA: Auf Empfängerseite wird zunächst der public key des Absenders ermittelt, sowie ein ggf. benötiger IV extrahiert.
Dann wird mit dem public key der verschlüsselte ciphertext entschlüsselt.

ECDHE+AES: Auf Empfängerseite wird zunächst der public key des Absenders ermittelt, sowie IV und Wert für Schlüsselableitung extrahiert.
Dann werden diese drei zusammen mit den verschlüsselten daten (ciphertext) und dem private key des Empfängers zur Verarbeitung übergeben.
Zunächst wird mittels ECDHE aus public key des Absenders, private Key des Empfängers, und Wert für Schlüsselableitung der
verwendete symmetrische Schlüssel abgeleitet.
Dieser wird sodann verwendet, um zusammen mit dem IV die verschlüsselten Daten zu entschlüsseln.

Allgemein weiter:

Die entschlüsselten Daten werden dann wie folgt auf Integrität geprüft:

Die Daten werden von Anfang bis Ende gelesen; dabei wird geprüft

1. Die einleitende Kennung ("magic ID") muß einer der erwarteten Werte sein. (u.a. Versionsunterscheidung)
2. Der "innere nonce"/padding-nonce wird übernommen und temporär für die Dauer des Prüfungsvorgangs lokal gespeichert.
3. Die Länge der nachfolgenden Nutzdaten wird gelesen.
4. Die Anzahl der erwarteten weiteren Blöcke wird berechnet, rechnerische Plausiblitätsprüfungen vorgenommen.
5. Die Datenblöcke werden der Reihe nach durchgegangen, das jeweilige padding-nonce-exemplar mit dem erwarteten Wert verglichen.
6. Im letzten Block, welcher auf die Datenblöcke folgt, wird noch einmal der ursprüngliche padding-nonce erwartet.
7. Gegebenenfalls den letzten Nutzdaten nachfolgende Zufallsdaten werden ignoriert.

Wird bei Schritten 1,4,5, oder 6 eine Abweichung festgestellt, so ist die Integrität der Nachricht verletzt worden
und es wird ein Fehler zurückgemeldet.
Sind alle Prüfungen erfolgreich verlaufen, gilt die Integrität der Nachricht als gesichert
und die rekombinierten Nutzdaten aus den Datenblöcken können für die weitere Verarbeitung weitergegeben werden.

#### Authentizität

Das IIP-Verfahren dient der Integritätsprüfung.
Die Authentizität, also die Identität des Absenders, muß auf anderem Wege ermittelt werden.

Bei direkter Verschlüsselung kann die Kenntnis des jeweiligen Private Key/Secret Key verwendet werden,
um die Authentizität zu prüfen: wird bei Entschlüsselung nicht der korrespondierende Schlüssel verwendet,
schlagen Entschlüsselung und/oder Prüfung fehl.

Wird hierbei asymmetrische Kryptographie verwendet, so ist auch unwesentlich,
ob der Private Key des Empfängers korrekt geheimgehalten wurde, oder einem Angreifer bekannt ist:
Bei unidirektionaler Kommunikation geht es um die Identität des Absenders, und dieser hält seinen Private Key geheim.

Werden jedoch symmetrische Schlüssel verwendet, so bedeutet deren Kompromittierung,
daß die Authentizität nicht mehr geprüft werden kann. Hierauf ist insbesondere zu achten,
wenn (z.B. mittels ECDHE) ein Key Agreement durchgeführt wird: der Ephemeral Key wird von beiden Seiten identisch
konstruiert, so daß Inhaber des einen oder anderen Private Keys selbst gültige Nachrichten verfassen können.
Bei diesem Szenario hängt also die Authentizität von der Geheimhaltung aller Private keys ab.

### Kompression

Eine Inhaltskompression ist vorgesehen; diese dürfte insbesondere bei Textdaten als Plaintext nützlich sein.

### Implementationsdetails generell

- Alle Zahlwerte werden Big-Endian gespeichert: das Wichtigste zuerst. (Network Byte Order, konsistent mit kryptographischen Funktionen, ASN.1-Repräsentation usw.)
- Es wird immer mindestens ein ungenutztes Zufallsbyte in den ersten Block gelegt; falls nötig, wird hierfür die MagicID
  gekürzt.
- Die MagicID lautet 0x3E7AB1705AFEE410.

Für alle bislang definierten Versionen gilt weiter:

- Als Größe des "inneren nonce" wird 32 bit (4 byte) gewählt. Damit bleiben bei üblicher symmetrischer Verschlüsselung pro Datenblock 12 byte für Nutzdaten; das Padding vergrößert dann seine
  Eingabedaten um etwas mehr als 25%.
- Als Größenangabe im Block wird 32 bit verwendet; damit ist eine Nutzdatengröße bis knapp 4 GB möglich.

### Version 1

Version 1 verwendet RSA.

- Wird ohne Key Agreement verschlüsselt, es kommt RSA zum Einsatz.

### Version 2

Version 2 ermöglicht ECDHE und AES.

- Wird mit Key Agreement verschlüsselt, es kommt ECHDE zum Einsatz. Die verwendete Kurve ist dabei flexibel; secp256r1 sollte jedoch stets möglich sein.
- Als symmetrisches Verschlüsselungsverfahren wird derzeit AES verwendet, mit AES-256 als default.


