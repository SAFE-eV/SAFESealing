
Die vorliegende Implementierung ist in Schichten aufgebaut.

# Komponenten
Reihenfolge bottom-up:
* IntegrityPaddingWithNonceForSymmetricCiphers - padded Rohdaten; Kern des Verfahrens 
* SymmetricEncryptionWithIntegrityPadding - verschlüsselt gepaddete Rohdaten symmetrisch 
* RSAWithIntegrityPadding - verschlüsselt gepaddete Rohdaten mit RSA asymmetrisch

Diese Klassen sind der Kern der Implementation.
Sie stellen Verschlüsselung mit Integritätssicherung ohne Verwendung einer MAC bereit.

Nächste Ebene:
* ECHDHEWithIntegrityPadding - führt ECHDE durch, verschlüsselt dann gepaddete Rohdaten symmetrisch

Die dabei verwendeten/erzeugten Daten zu Einmalkennung für ECHDE, symmetrischem IV, verschlüsselten Daten usw.
werden gebündelt:

* TransportFormatConverter - wandelt das Datentupel nach und von ASN.1-Transportformat
* SAFESealSealer - bündelt den gesamten Vorgang. Dies ist die Klasse, welche Anwender verwenden sollten.

Folgende Klassen haben unterstützende Funktion:

* SharedConstants enthält vor allem die Algorithmen-kennungen, aber auch feste Werte für Version, Nonce-Größe u.a.m.
* AlgorithmSpec - Parametrisierung eines Algorithmus, Abstraktion mit Größenangaben u.a.m.
* AlgorithmSpecCollection - Tabelle zum Nachschlagen unterstützter Algorithmen und ihrer Parameter.
* CryptoFactory - liefert zu AlgorithmSpec ausführbare Instanzen. Kapselt java.security.Provider. 

* CryptoSettingsStruct - Struktur zum Bündeln der Kennungen der verwendeten Algorithmen
* InternalTransportTuple - Struktur zum Bündeln der verwendeten Daten
* SharedCode enthält kleine Codefragmente, welche wiederverwendet werden
* ByteIntegerConversion enthält weitere Codefragmente zur Wiederverwendung


# Ablauf Prüfung und Entsiegelung
Für eine Top-Down-Analyse ist also der Ablauf der Prüfung und Entsiegelung wie folgt:
1. Aufsetzen der Umgebung (Crypto-Bibliothek, Algorithmen); Bereitstellung der Schlüssel
2. Zunächst ist das versiegelte Format mittels des TransportFormatConverter in ein InternalTransportTuple umzuwandeln,
3. Die dort angegebenen Algorithmen sind mit den verfügbaren/akzeptierten abgleichen und Instanzen bereitstellen
4. Dann ist mittels ECHDHEWithIntegrityPadding aus den asymmetrischen Schlüsseln und Diversifikationsdaten der ephemeral key errechnet.
5. Mit diesem wird dann in SymmetricEncryptionWithIntegrityPadding die Entschlüsselung durchgeführt.
6. Die entschlüsselten Rohdaten werden vom ECHDHEWithIntegrityPadding auf Integrität geprüft.
7. Wird diese Prüfung mit positivem Ergebnis abgeschlossen, werden die Nutzdaten an den Aufrufer übergeben;
   andernfalls wird das Verfahren mit Fehler abgebrochen.


