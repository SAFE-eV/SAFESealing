# Interleaved Integrity Padding

Vorgeschlagenes Kürzel: "IIP" = Interleaved Integrity Padding.

## Zweck und Motivation

Dieses Verfahren dient dazu, die Integrität von verschlüsselten Nachrichten sicherzustellen,
ohne ein Merkmal der Nachricht (wie z.B. eine HMAC) zu verwenden.

Der Bedarf hierfür wurde durch patentrechtliche Gründe geschaffen. Es war strikt zu vermeiden, eine wie auch immer 
abgeleitete Eigenschaft der Nutzdaten (Plaintext) zu verwenden; daher durften die üblichen MAC-Verfahren Hash/HMAC/... 
nicht zur Anwendung kommen.

## Grundidee

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


## Fortsetzung der Idee

Ein Blockzähler kann auf die Schutzdaten aufmoduliert werden, so daß diese pro Block variieren und die Reihenfolge
der Blöcke geprüft werden kann. (auch: Schutzdaten als Pseudozufalls-sequenz)

Es können zusätzlich jeweils nicht genutzte Zufallsdaten hinzugefügt werden, in dem ersten und/oder folgenden Blöcken,
damit die Nachrichteninhalte weniger vorhersehbar bzw. formbar (malleable) sind.

Der verwendete Blockcipher kann eine zusätzliche Verkettung der Blöcke bereitstellen.

## Caveat

Werden mehrere Datenblöcke versendet, muß je Datenblock mindestens ein Satz Schutzdaten vorhanden sein.

Das eingesetzte Verschlüsselungsverfahren ist grundsätzlich auf seine Diffusion zu prüfen. Die Wirksamkeit des IIP ist
von der Diffusion des Verschlüsselungsverfahrens abhängig, und der Avalanche Effect sollte möglichst umfassend sein.

Die Schutzwirkung hängt von Verschlüsselungsalgorithmus und Verhältnis Schutzdaten zu Nutzdaten ab.
Insbesondere ist zu beachten: Die üblichen Streaming Ciphers, und die Operation Modes für symmetrische Ciphers
welche streaming entsprechen, weisen *keine* Diffusion auf. Bei CFB, OFB, CTR und ähnlichen Modi kann man ein Bit 
des Ciphertexts ändern und exakt ein Bit des Plaintexts damit ändern. Das macht sie für Verwendung mit IIP untauglich.
Dieses Verfahren ist also keineswegs unabhängig von der übrigen Kryptographie, sondern im Gegenteil mit dieser genau
abzustimmen.

(Bei Verfahren mit substitution tables ist beispielsweise wünschenswert, daß die verwendete Verschlüsselungsfunktion 
das SAC (Strict Avalanche Criterion) erfüllt; zumindest aber sollte das nicht-strikte Avalanche Criterion erfüllt sein.)


