# AdFection blocklist

DNS blocklist voor de infrastructuur achter **AdFection**: zero-click spyware die via gerichte advertenties wordt afgeleverd. Bevat domeinen van Discover-Tech (Controlium, MyDSP, NOAS servers, ID syncing), Candiru / Integrity Labs, Bindecy en Intelos.

Gebaseerd op:

* Citizen Lab Report 195, [Exposing AdFection](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/) (15 oktober 2026)
* Confiant, [ADINT: weaponized ad tech for zero-click spyware](https://blog.confiant.com/p/adint-weaponized-ad-tech-for-zero-click-spyware-and-mass-identity-vacuuming)
* Recorded Future Insikt Group, [CTA-2025-0805](https://assets.recordedfuture.com/content/dam/insikt-report-pdfs/2025/cta-2025-0805.pdf) (Candiru infrastructuur)

## Lijsten

Opgezet in de stijl van [Hagezi DNS blocklists](https://github.com/hagezi/dns-blocklists): een map per formaat, wildcard compressie (subdomeinen die al door een parent geblokkeerd worden vallen weg) en headers met `Title`, `Version`, `Last modified`, `Expires` en `Number of entries`, zodat AdGuard Home en uBlock automatisch updaten.

Kies **Full** voor alles, of een losse actor lijst. Kies het formaat van je resolver. De `Domains` en `Hosts` varianten bevatten de volledige set inclusief subdomeinen, omdat die formaten geen wildcards ondersteunen.

<!-- LISTS:START -->

Totaal: **182** domeinen, **154** na wildcard compressie.

### AdFection Full

Alle bekende infrastructuur: Discover-Tech, Candiru, Bindecy, Intelos

| Formaat | Voor | Link |
| --- | --- | --- |
| Adblock | AdGuard, AdGuard Home, uBlock Origin, Pi-hole v6, NextDNS | [adblock/adfection.txt](lists/adblock/adfection.txt) |
| DNSMasq | dnsmasq, OpenWrt, Pi-hole (dnsmasq.d) | [dnsmasq/adfection.txt](lists/dnsmasq/adfection.txt) |
| Wildcard | Wildcard domains (root dekt subdomeinen), Technitium, Blocky | [wildcard/adfection-onlydomains.txt](lists/wildcard/adfection-onlydomains.txt) |
| Asterisk Wildcard | *.domain syntax, pfBlockerNG, Blocky, Diversion | [wildcard/adfection.txt](lists/wildcard/adfection.txt) |
| Domains | Pi-hole, plain lijsten, volledige set incl. subdomeinen | [domains/adfection.txt](lists/domains/adfection.txt) |
| Hosts | /etc/hosts, Windows, oudere Pi-hole | [hosts/adfection.txt](lists/hosts/adfection.txt) |
| RPZ | BIND, PowerDNS, Knot, Technitium | [rpz/adfection.txt](lists/rpz/adfection.txt) |
| Unbound | Unbound, OPNsense, pfSense | [unbound/adfection.txt](lists/unbound/adfection.txt) |

### AdFection Candiru

Candiru / Integrity Labs validator, C&C en delivery servers

| Formaat | Voor | Link |
| --- | --- | --- |
| Adblock | AdGuard, AdGuard Home, uBlock Origin, Pi-hole v6, NextDNS | [adblock/adfection-candiru.txt](lists/adblock/adfection-candiru.txt) |
| DNSMasq | dnsmasq, OpenWrt, Pi-hole (dnsmasq.d) | [dnsmasq/adfection-candiru.txt](lists/dnsmasq/adfection-candiru.txt) |
| Wildcard | Wildcard domains (root dekt subdomeinen), Technitium, Blocky | [wildcard/adfection-candiru-onlydomains.txt](lists/wildcard/adfection-candiru-onlydomains.txt) |
| Asterisk Wildcard | *.domain syntax, pfBlockerNG, Blocky, Diversion | [wildcard/adfection-candiru.txt](lists/wildcard/adfection-candiru.txt) |
| Domains | Pi-hole, plain lijsten, volledige set incl. subdomeinen | [domains/adfection-candiru.txt](lists/domains/adfection-candiru.txt) |
| Hosts | /etc/hosts, Windows, oudere Pi-hole | [hosts/adfection-candiru.txt](lists/hosts/adfection-candiru.txt) |
| RPZ | BIND, PowerDNS, Knot, Technitium | [rpz/adfection-candiru.txt](lists/rpz/adfection-candiru.txt) |
| Unbound | Unbound, OPNsense, pfSense | [unbound/adfection-candiru.txt](lists/unbound/adfection-candiru.txt) |

### AdFection Discover-Tech

Controlium, MyDSP, NOAS servers en ID syncing

| Formaat | Voor | Link |
| --- | --- | --- |
| Adblock | AdGuard, AdGuard Home, uBlock Origin, Pi-hole v6, NextDNS | [adblock/adfection-discover-tech.txt](lists/adblock/adfection-discover-tech.txt) |
| DNSMasq | dnsmasq, OpenWrt, Pi-hole (dnsmasq.d) | [dnsmasq/adfection-discover-tech.txt](lists/dnsmasq/adfection-discover-tech.txt) |
| Wildcard | Wildcard domains (root dekt subdomeinen), Technitium, Blocky | [wildcard/adfection-discover-tech-onlydomains.txt](lists/wildcard/adfection-discover-tech-onlydomains.txt) |
| Asterisk Wildcard | *.domain syntax, pfBlockerNG, Blocky, Diversion | [wildcard/adfection-discover-tech.txt](lists/wildcard/adfection-discover-tech.txt) |
| Domains | Pi-hole, plain lijsten, volledige set incl. subdomeinen | [domains/adfection-discover-tech.txt](lists/domains/adfection-discover-tech.txt) |
| Hosts | /etc/hosts, Windows, oudere Pi-hole | [hosts/adfection-discover-tech.txt](lists/hosts/adfection-discover-tech.txt) |
| RPZ | BIND, PowerDNS, Knot, Technitium | [rpz/adfection-discover-tech.txt](lists/rpz/adfection-discover-tech.txt) |
| Unbound | Unbound, OPNsense, pfSense | [unbound/adfection-discover-tech.txt](lists/unbound/adfection-discover-tech.txt) |

### AdFection Bindecy

Bindecy spyware infrastructuur

| Formaat | Voor | Link |
| --- | --- | --- |
| Adblock | AdGuard, AdGuard Home, uBlock Origin, Pi-hole v6, NextDNS | [adblock/adfection-bindecy.txt](lists/adblock/adfection-bindecy.txt) |
| DNSMasq | dnsmasq, OpenWrt, Pi-hole (dnsmasq.d) | [dnsmasq/adfection-bindecy.txt](lists/dnsmasq/adfection-bindecy.txt) |
| Wildcard | Wildcard domains (root dekt subdomeinen), Technitium, Blocky | [wildcard/adfection-bindecy-onlydomains.txt](lists/wildcard/adfection-bindecy-onlydomains.txt) |
| Asterisk Wildcard | *.domain syntax, pfBlockerNG, Blocky, Diversion | [wildcard/adfection-bindecy.txt](lists/wildcard/adfection-bindecy.txt) |
| Domains | Pi-hole, plain lijsten, volledige set incl. subdomeinen | [domains/adfection-bindecy.txt](lists/domains/adfection-bindecy.txt) |
| Hosts | /etc/hosts, Windows, oudere Pi-hole | [hosts/adfection-bindecy.txt](lists/hosts/adfection-bindecy.txt) |
| RPZ | BIND, PowerDNS, Knot, Technitium | [rpz/adfection-bindecy.txt](lists/rpz/adfection-bindecy.txt) |
| Unbound | Unbound, OPNsense, pfSense | [unbound/adfection-bindecy.txt](lists/unbound/adfection-bindecy.txt) |

### AdFection Intelos

Intelos ADINT infrastructuur

| Formaat | Voor | Link |
| --- | --- | --- |
| Adblock | AdGuard, AdGuard Home, uBlock Origin, Pi-hole v6, NextDNS | [adblock/adfection-intelos.txt](lists/adblock/adfection-intelos.txt) |
| DNSMasq | dnsmasq, OpenWrt, Pi-hole (dnsmasq.d) | [dnsmasq/adfection-intelos.txt](lists/dnsmasq/adfection-intelos.txt) |
| Wildcard | Wildcard domains (root dekt subdomeinen), Technitium, Blocky | [wildcard/adfection-intelos-onlydomains.txt](lists/wildcard/adfection-intelos-onlydomains.txt) |
| Asterisk Wildcard | *.domain syntax, pfBlockerNG, Blocky, Diversion | [wildcard/adfection-intelos.txt](lists/wildcard/adfection-intelos.txt) |
| Domains | Pi-hole, plain lijsten, volledige set incl. subdomeinen | [domains/adfection-intelos.txt](lists/domains/adfection-intelos.txt) |
| Hosts | /etc/hosts, Windows, oudere Pi-hole | [hosts/adfection-intelos.txt](lists/hosts/adfection-intelos.txt) |
| RPZ | BIND, PowerDNS, Knot, Technitium | [rpz/adfection-intelos.txt](lists/rpz/adfection-intelos.txt) |
| Unbound | Unbound, OPNsense, pfSense | [unbound/adfection-intelos.txt](lists/unbound/adfection-intelos.txt) |

<!-- LISTS:END -->

## Hoe het werkt

```
sources/*.txt  ─┐
                ├─> scripts/build.py ─> lists/<formaat>/adfection*.txt
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
