# Projektwege NKSA

Konzeptvorschlag, wie das Lehrmittel für den Projektunterricht der Neuen Kantonsschule Aarau
(«Wie schreibe ich eine Abschlussarbeit?», Ausgabe 2026/27) in eine Plattform überführt werden kann:
Workflowpfade für PU Gym, PU im Akzentfach, Maturarbeit, SAR und FMA, Werkstatt-Werkzeuge,
Wissensbasis und KI-Begleitung.

Die Präsentation ist eine einzelne statische Seite: [`index.html`](index.html), veröffentlicht über GitHub Pages.

## Zugangscode

Die veröffentlichte `index.html` enthält den Inhalt nur verschlüsselt (AES-GCM). Er wird erst im Browser
nach Eingabe des Zugangscodes entschlüsselt. Die unverschlüsselte Quelle liegt nicht im Repository.

Neue Version erzeugen:

```sh
ZUGANGSCODE=... node tools/schuetzen.mjs quelle.html index.html
```
