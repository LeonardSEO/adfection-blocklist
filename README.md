# AdFection blocklist

DNS blocklist voor de infrastructuur achter **AdFection**: zero-click spyware die via gerichte advertenties wordt afgeleverd. Bevat domeinen van Discover-Tech (Controlium, MyDSP, NOAS servers, ID syncing), Candiru / Integrity Labs, Bindecy en Intelos.

Gebaseerd op:

* Citizen Lab Report 195, [Exposing AdFection](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/) (15 oktober 2026)
* Confiant, [ADINT: weaponized ad tech for zero-click spyware](https://blog.confiant.com/p/adint-weaponized-ad-tech-for-zero-click-spyware-and-mass-identity-vacuuming)
* Recorded Future Insikt Group, [CTA-2025-0805](https://assets.recordedfuture.com/content/dam/insikt-report-pdfs/2025/cta-2025-0805.pdf) (Candiru infrastructuur)

## Lijsten

Alle bestanden staan in `lists/`. Kies het formaat van je resolver:

| Bestand | Voor |
| --- | --- |
| `adblock.txt` | AdGuard Home, uBlock Origin, NextDNS, Pi-hole v6 (blokkeert ook subdomeinen) |
| `domains.txt` | Pi-hole, Technitium, pfBlockerNG, elke plain domain lijst |
| `hosts.txt` | `/etc/hosts`, Windows hosts, oudere Pi-hole |
| `dnsmasq.conf` | dnsmasq, OpenWrt |
| `unbound.conf` | Unbound, OPNsense, pfSense |
| `rpz.zone` | BIND, PowerDNS, Knot (Response Policy Zone) |
| `domains-<categorie>.txt` | Alleen `candiru`, `discover-tech`, `bindecy` of `intelos` |

Abonneren via de raw URL, bijvoorbeeld:

```
https://raw.githubusercontent.com/<gebruiker>/adfection-blocklist/main/lists/adblock.txt
```

## Hoe het werkt

```
sources/*.txt  ─┐
                ├─> scripts/build.py ─> lists/*
candidates/approved.txt ─┘                ▲
                                          │ handmatige review
scripts/discover.py ─> candidates/candidates-YYYYMMDD.txt
```

* **`sources/`** bevat per publicatie de domeinen, letterlijk zoals gepubliceerd, met categorie en toelichting.
* **`allowlist.txt`** voorkomt dat gedeelde platforms (cloudfront.net, azure.com, herokuapp.com) of legitieme partijen per ongeluk geblokkeerd worden.
* **`scripts/discover.py`** zoekt gerelateerde domeinen via passieve, publieke bronnen:
  1. crt.sh: subdomeinen uit Certificate Transparency logs
  2. urlscan.io: hosts die de tracking pixel scripts of bekende domeinen laden
  3. DNS over HTTPS: CNAME's of IP's die overeenkomen met de Discover-Tech AWS load balancer
  4. Censys (optioneel): hosts met het Bindecy `cupid-ca` certificaat of de speedtest body hash
* Kandidaten worden **nooit automatisch** geblokkeerd. Je reviewt ze en zet wat klopt in `candidates/approved.txt`.

## Lokaal draaien

```bash
python3 scripts/discover.py          # zoekt kandidaten
python3 scripts/build.py             # bouwt alle lijsten
```

Alleen Python 3.10+ standaardbibliotheek, geen dependencies.

Optionele API keys (als environment variable of GitHub secret):

* `CENSYS_API_ID` en `CENSYS_API_SECRET` voor de Censys pivot
* `URLSCAN_API_KEY` voor hogere urlscan limieten

## GitHub Actions

`.github/workflows/update.yml` bouwt de lijsten bij elke wijziging en draait elke maandag een discovery run. Als er nieuwe kandidaten zijn, wordt automatisch een issue aangemaakt om te reviewen.

## Bekende beperkingen

* Citizen Lab vond 305 Candiru validator domeinen via een fingerprint, maar heeft die lijst niet gepubliceerd. Deze repo bevat de 108 domeinen die Recorded Future wel publiceerde plus wat in de rapporten zelf staat.
* Candiru draait veel op CloudFront. Losse `dxxxx.cloudfront.net` hosts staan erin, maar `cloudfront.net` zelf blokkeren kan uiteraard niet.
* Het blokkeren van deze domeinen stopt bekende infrastructuur. Het vervangt geen updates van je browser en besturingssysteem, die de onderliggende exploits dichten.

## Bijdragen

Nieuw domein? Voeg het toe aan het juiste bestand in `sources/` met een bronvermelding, of aan `candidates/approved.txt` met de reden. Open een pull request.

## Licentie

De lijsten zijn afgeleid van publicaties van Citizen Lab (CC BY-NC-SA 4.0), Confiant en Recorded Future, en worden gedeeld onder **CC BY-NC-SA 4.0**. De scripts vallen onder de MIT licentie.
