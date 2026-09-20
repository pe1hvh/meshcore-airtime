# meshcore-airtime

*Nederlands · [English version](README.en.md)*

Meetgereedschap voor zendtijd en padgedrag in een [MeshCore](https://meshcore.co.uk/)
LoRa-mesh. Bedoeld voor één terugkerende discussie: *"die twee repeaters zitten
elkaar in de weg, ze herhalen elkaars berichten en vervuilen de mesh."*

Die bewering is meetbaar. Dit gereedschap meet hem.

## Twee gereedschappen, in deze volgorde

**`meshcore_toa_report.py` — waar gaat de zendtijd heen?**
Telt alle ontvangen pakketten, rekent per pakket de LoRa-zendtijd uit en zet
dat af per payload type, route type, hopcount of laatste hop. Dit is de eerste
stap: het laat zien of er überhaupt een airtime-probleem is en waar het zit.

**`meshcore_pair_report.py` — doen twee specifieke repeaters dubbel werk?**
Dedupliceert op pakketniveau en kijkt per pakket of twee genoemde repeaters
elkaar aanvullen (serieel) of hetzelfde werk doen (parallel). Dit is de tweede
stap, voor als de eerste een verdenking oplevert.

**`meshcore_req_report.py` — wie produceert het verzoekverkeer?**
Rekent REQ, RESPONSE, ANON_REQ en PATH toe aan de node die ze verstuurde, en
laat zien of dat verkeer geconcentreerd is bij een paar tools of verspreid over
gewone gebruikers.

Alle drie lezen dezelfde bron, hebben geen dependencies buiten de standaardlibrary
en leiden alles af uit `raw_payload` — het volledige pakket inclusief header —
in plaats van uit velden die de gui er zelf van maakt.

---

## Het onderscheid dat de hele discussie bepaalt

Repeaters die elkaars floodverkeer doorgeven is **geen fout** — het is hoe flood
routing werkt. De vraag is niet *of* ze elkaars pakketten herhalen, maar *hoe*.

**Serieel.** Beide repeaters staan in hetzelfde pad, direct na elkaar: `A → B`.
B heeft de uitzending van A opgepikt en verder gedragen. Dat is geen
verspilling maar bereikverlenging — precies waar een tweede repeater voor staat.

**Parallel.** Hetzelfde pakket komt bij dezelfde ontvanger binnen via twee
verschillende paden: één met A en zonder B, één met B en zonder A. Beide
repeaters hebben dat pakket dus onafhankelijk de lucht in gedaan, naar hetzelfde
ontvangstpunt. Dít is de dubbeling waar de klacht over gaat, en alleen dit
kost zendtijd zonder iets terug te geven.

Zonder dat onderscheid meet je niets. Twee repeaters die keurig samenwerken,
komen in een naïeve telling net zo vaak "samen in een pad" voor als twee die
dubbel werk doen.

## Waarom je een placebo-venster nodig hebt

Een voor/na-meting rond een instellingswijziging zegt pas iets als je weet
hoeveel het cijfer vanzelf al schommelt. In de metingen waarvoor dit
gereedschap is geschreven bleek het parallelpercentage tussen twee
opeenvolgende vensters van twee dagen, zónder enige wijziging ertussen,
al 6,5 procentpunt te verspringen. Een gemeten "verbetering" van 3 punten
betekent in dat licht niets.

Draai dus altijd eerst twee vensters die allebei vóór de wijziging liggen:

```bash
# ruisniveau bepalen: twee vensters van 48 uur, niets veranderd ertussen
python3 meshcore_pair_report.py rxlog.jsonl \
    --a 5dac --a-name WKC --b 4ffc --b-name WKC-L --min-hash-size 2 \
    --since 2026-09-12T18:00 --until 2026-09-16T18:00 \
    --split 2026-09-14T18:00

# en dan pas de echte voor/na
python3 meshcore_pair_report.py rxlog.jsonl \
    --a 5dac --a-name WKC --b 4ffc --b-name WKC-L --min-hash-size 2 \
    --since 2026-09-16T18:00 --split 2026-09-18T18:00
```

Het verschil uit de eerste run is de lat waar de tweede overheen moet.

## meshcore_toa_report.py — zendtijd per payload type

```bash
python3 meshcore_toa_report.py                      # default: ~/.meshcore-gui/archive/_dev_*_rxlog.jsonl
python3 meshcore_toa_report.py LOG --verify         # eerst de aannames narekenen
python3 meshcore_toa_report.py LOG --flood-only --hops
python3 meshcore_toa_report.py LOG --via-name WKC-L --by-last-hop
python3 meshcore_toa_report.py LOG --since 2026-09-01 --csv airtime.csv
```

De uitvoer is een tabel met per payload type het aantal pakketten, de bytes, de
berekende zendtijd, het aandeel daarin en de gemiddelde tijd per pakket. Daaronder
de verdeling over de vier MeshCore route types en de kanaalbezetting zoals die op
dit ontvangstpunt is waargenomen.

Nuttige schakelaars:

| optie | betekenis |
| --- | --- |
| `--verify` | rekent de aannames over het logformaat na op je eigen data en stopt |
| `--flood-only` | alleen TRANSPORT_FLOOD en FLOOD: wat een repeater daadwerkelijk herhaalt |
| `--route` | beperk tot één MeshCore route type |
| `--via` / `--via-name` / `--via-pos` | alleen verkeer dat via een bepaalde node liep |
| `--by-last-hop` | tabel per laatste hop in plaats van per payload type |
| `--hops` | verdeling naar hopcount, inclusief wat een `flood.max`-begrenzing zou schelen |
| `--per-day` | dagtotalen, handig om de dekking van je log te controleren |

### Waarom `--verify` er is

Het script leidt alles af uit de ruwe bytes, maar controleert dat tegen de
velden die de gui erbij zet: `packet_len` tegen de werkelijke lengte, de
payload-type-bits tegen `packet_type_num`, de padlengtebyte tegen het aantal
hops. Wijkt er iets af — nieuwe firmware, gewijzigde gui — dan meldt het dat
in plaats van stil door te rekenen met verkeerde cijfers. Draai het één keer
op je eigen log voordat je de uitkomsten ergens gebruikt.

### Een val in het logformaat

Het veld `route_type` in de meshcore-gui rxlog is **niet** het MeshCore route
type. Het staat op `D` zodra er een pad in het pakket zit en op `F` als het pad
leeg is. Het echte route type zit in bits 0-1 van de header. Wie op dat gui-veld
filtert, telt flood-verkeer met een pad als "direct" en komt tot verkeerde
conclusies over de verhouding flood/direct. `--flood-only` werkt op de header.

### Wat de eerste meting hiermee opleverde

Op een mesh in Overijssel, ruim 192.000 pakketten:

* 95,5% van het verkeer is flood (84,1% TRANSPORT_FLOOD, 11,4% FLOOD),
  4,5% DIRECT
* REQ, RESPONSE, ANON_REQ en PATH samen bijna de helft van alle pakketten:
  geautomatiseerd gepraat van tooling, niet mensen die berichten sturen
* ADVERT is de duurste pakketsoort per stuk (ruim 450 ms) maar slechts 5% van
  de zendtijd — adverts zijn zelden het probleem
* kanaalbezetting zoals ontvangen: 0,32%

Dat laatste getal relativeert de meeste airtime-discussies meteen. Meet het
voordat je erover discussieert.

### Twee dingen die het onderschat

**Dubbeltelling.** Draai je over logs van meerdere ontvangers, dan wordt een
pakket dat beide hoorden twee keer geteld. De uitvoer waarschuwt daarvoor.

**DIRECT-verkeer.** Een vast ontvangstpunt hoort alle floods in bereik, maar
van routed verkeer alleen wat toevallig langs die positie loopt. Het aandeel
DIRECT is daardoor systematisch te laag. Trek dus geen conclusies over de
verhouding flood/direct op basis van één ontvanger.

## meshcore_req_report.py — wie produceert het verzoekverkeer?

In de eerste meting bleek bijna de helft van alle pakketten REQ, RESPONSE,
ANON_REQ en PATH te zijn. De verleiding is dan te zeggen: "dat is
geautomatiseerd verkeer van tooling". Dat is een vermoeden, geen meting.

Dit script maakt er een meting van. Het leest de bron- en bestemmingshash uit
de payload (`[dest 1][src 1][MAC 2]` voor REQ, RESPONSE, TXT_MSG en PATH; bij
ANON_REQ de volledige afzenderpubkey) en telt per node. Nodenamen haalt het uit
de ADVERT-pakketten in hetzelfde log, dus je hoeft geen contactenlijst aan te
leveren.

```bash
python3 meshcore_req_report.py rxlog.jsonl --targets
python3 meshcore_req_report.py rxlog.jsonl --top 30 --csv bronnen.csv
```

De uitslag staat in de concentratietabel. Komt meer dan 60% van alle REQ van de
top 3 bronnen, dan is het inderdaad een paar pollende tools. Is het verdeeld
over tientallen nodes, dan is het gewoon gebruik en houdt de bewering geen
stand.

Wat het niet kan: ACK, GRP_TXT en GRP_DATA dragen geen afzender en zijn dus aan
geen node toe te rekenen. En RESPONSE is bij een vast ontvangstpunt
ondervertegenwoordigd, omdat gericht verkeer alleen wordt gehoord als het
langskomt.

## meshcore_pair_report.py — serieel of parallel?

Eerst uitzoeken welke pad-hash bij welke repeater hoort:

```bash
python3 meshcore_pair_report.py rxlog.jsonl --list-hashes 40
```

De hash van een node is de eerste byte (of twee, of drie) van zijn publieke
sleutel. Dan de analyse:

```bash
python3 meshcore_pair_report.py rxlog.jsonl \
    --a 5dac --a-name WKC \
    --b 4ffc --b-name WKC-L \
    --min-hash-size 2 --csv paren.csv
```

Belangrijkste opties:

| optie | betekenis |
| --- | --- |
| `--a` / `--b` | pad-hash van beide repeaters, hex, 1 tot 3 bytes |
| `--min-hash-size N` | negeer kopieën met kortere pad-hashes (zie hieronder) |
| `--split TIJD` | splits in een venster voor en na, met vergelijking |
| `--since` / `--until` | begrens de meetperiode (ISO, UTC) |
| `--per-observer` | analyseer elke waarnemer apart in plaats van samengevoegd |
| `--all-routes` | ook DIRECT-verkeer meetellen (default: alleen flood) |
| `--sf` `--bw` `--cr` | radioparameters voor de zendtijdberekening |
| `--csv` | per uniek pakket een regel wegschrijven |

### Waarom `--min-hash-size 2` meestal nodig is

Met eenbyte-pad-hashes zijn er 254 bruikbare ID's. In een mesh van enige omvang
delen meerdere nodes dezelfde eerste byte van hun publieke sleutel, en dan telt
een analyse op één byte verkeer van een andere node mee. In de dataset waarvoor
dit is geschreven botste een repeater met een bot in dezelfde regio, goed voor
een factor vier in de uitkomst.

Het script waarschuwt als er op één byte is vergeleken. Neem die waarschuwing
serieus en draai opnieuw met `--min-hash-size 2`.

## Invoer

Elke bron waarin het **ruwe pakket** staat werkt:

* rx-logs van meshcore-gui (`~/.meshcore-gui/archive/*_rxlog.jsonl`)
* MQTT-dumps van [meshcoretomqtt](https://github.com/Andrew-a-g/meshcoretomqtt) —
  **topic `meshcore/raw`**, niet `meshcore/packets`: dat laatste bevat wel de
  pakket-hash maar geen pad, en dan is er niets te analyseren
* kale hex, één pakket per regel (`mosquitto_sub -t meshcore/raw`)

JSON-lines en een JSON-array worden allebei gelezen; het veld met de hex wordt
gezocht, ook een niveau of drie diep. Overrulen kan met `--field` en
`--time-field`.

Het pakket wordt ontleed volgens de
[officiële structuur](https://docs.meshcore.io/packet_format/):
`[header][transport_codes(4, optioneel)][path_length][path][payload]`, met het
hopaantal in bits 0-5 van `path_length` en de hash-grootte min 1 in bits 6-7.

Kopieën van hetzelfde pakket worden herkend aan payloadtype plus payload bytes —
het pad groeit immers per hop, de payload niet. Dat is niet de hash die de
firmware zelf voor duplicate suppression gebruikt, maar een eigen sleutel met
hetzelfde effect.

## Grenzen van de methode

Lees dit voordat je ergens een cijfer uit dit gereedschap neerlegt.

* **Je meet wat jouw ontvangers hoorden.** Uitzendingen buiten bereik ontbreken.
  De parallelcijfers zijn dus een ondergrens, en ze zeggen niets over de
  situatie rond een repeater die je zelf niet ontvangt.
* **Dedupliceert je ontvangende node vóór het loggen, dan zie je parallelle
  kopieën helemaal niet.** Het cijfer komt dan op nul uit; dat is geen bewijs
  van onschuld maar een blinde vlek.
* **Controleer de dekking van je logbestand,** niet alleen de tijdspanne. Een
  archief dat op papier vijf maanden beslaat maar in werkelijkheid dertien
  dagen aan records bevat, levert onzinnige gemiddelden per uur.
* **Analyseer per waarnemer, niet over alle rx-logs tegelijk.** Pool je twee
  ontvangers, dan telt een pakket dat ze allebei hoorden dubbel, en kan "beide
  repeaters betrokken" ontstaan doordat de ene waarnemer het via A hoorde en de
  andere via B — terwijl geen van beiden dubbeling zag. Gebruik
  `--per-observer`. Parallelle dubbeling is per definitie iets wat één
  ontvangstpunt waarneemt.
* **DIRECT-verkeer wordt ondergeteld** bij een vast ontvangstpunt: floods hoor
  je allemaal, routed verkeer alleen als het toevallig langs je loopt.

## Instellingen die er echt toe doen

Als de meting parallelle dubbeling laat zien, staan de knoppen in de
[CLI-documentatie](https://docs.meshcore.io/cli_commands/):

* `rxdelay` (experimenteel) — zwak ontvangen kopieën gaan in een wachtrij zodat
  sterk ontvangen paden voorrang krijgen; tegen de tijd dat de zwakke ontvanger
  aan de beurt is, is het pakket vaak al doorgegeven en wordt zijn kopie als
  duplicaat onderdrukt. Leunt op SNR-verschil: horen twee repeaters elkaar even
  sterk, dan valt er weinig te prioriteren.
* `txdelay` — schaalt het willekeurige venster tegen gelijktijdig zenden.
* `flood.max.unscoped` — begrenst ongescopet floodverkeer zonder lokale
  berichten te blokkeren.
* `loop.detect` — tegen echte loops door afwijkende firmware; helpt niet tegen
  deze vorm van redundantie.

## Licentie

MIT — zie [LICENSE](LICENSE). Gebruiken, aanpassen, hergebruiken en doorgeven
mag, ook commercieel; de enige voorwaarde is dat de copyrightregel meegaat.

73 de PE1HVH
