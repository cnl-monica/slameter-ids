# bmIDS

## Informácie o projekte
---------------------
* **Verzia**: 2.3
* **Stav**: vyvíjaný
* **Autori**:        
    *  **Martin Ujlaky**
    *  **Ladislav Berta**
* Licencia: GNU GPLv3
* Implemetačné prostredie:
    * **openjdk-6-jre-headless**


## Systémové požiadavky
---------------------
* **Operačný systém:** Linux
* **Hardvér:**
  * procesor: Intel Pentium III 1GHz alebo ekvivalent
  * pamäť: 512MB
  * diskový priestor: 100MB
  * ostatné: sieťová karta 100 Mbit/s
* **Databáza:**
  * PostgreSQL 9.0 a vyššia
  * tabuľky pre zaznamenanie kritickej prevádky db_script.sql
* **Webový server:**
  * podľa požiadaviek webSLA

## Závislosti
---------------
* Exportér
* Kolektor
* ACPapi

## Iné
----------------
Spustenie bmIDS je možné po dodržaní postupnosti kolektor > exportér > bmIDS.

## Preklad zdrojových kódov
------------------
1. nainštalovať vývojárské prostredie NetBeans v7.0.1 a vyššie
2. pridáť v NetBeans -e repozitár pre bmIDSanalyzer
3. kliknúť pravým tlačidlom myši na projekt a vybrať možnosť preložiť zdrojové súbory (NetBeans uloží spustiteľný súbor v priečinku dist pracovného priečinka programu)

## Návod na inštaláciu
-----------------------
Aplikácia bmIDSanalyzer je závislá na exportovacom a zhromažďovacom procese. Preto je potrebné najprv nainštalovať exportér na server kde bude sledovaná sieťová prevádzka. Tiež je potrebná inštalácia kolektora JXColl verzie 3.9, ktorá bude slúžiť ako zdroj údajov pre bmIDSanalyzer. Kolektor vyžaduje aj inštaláciu databázy.

Súbory ktoré budú potrebné k inštalácii kolektora, databázy a aplikácie bmIDSanalyzer je možné stiahnuť zadaním príkazu do príkaového riadku:

```bash
sudo git clone https://git.cnl.sk/ladislav.berta/bmIDSv2-3.git -c http.sslVerify=false
```

V prípade ak git nie je nainštalovaný, treba ho nainštalovať príkazom:

```bash
sudo apt-get install git
```

Výsledkom bude adresár bmIDSv2-3 ktorý bude obsahovať aplikáciu bmIDSanalyzer a k nemu potrebné súbory, aplikáciu kolektora (deb ballíček) a skripty pre vytvorenie tabuliek v databáze.

V nasledujúcich krokoch je popísaný postup pre:
1. Inštalovanie exportéra mybeem.
2. Inštalovanie databázy PostgreSQL
3. Inštalácia databázy, ktorá je potrebná pre kolektor a aplikáciu bmIDSanalyzer v režime učenia.
4. Inštalácia samotného JXColl
5. Inštalácia samotnej aplikácie bmIDSanalyzer a webovej aplikácie nástroja bmIDS.

## 1. Inštalácia mybeem
------------------------------
Priama inštalácia deb balíčka je možná podľa nasledujúceho postupu (zdroj: mybeem):
Pozn.: v prípade manuálnej inštalácie sa treba pozrieť na stránku mybeem, ktorá obsahuje všetky potrebné informácie vrátane postupov inštalácie.

#### 1. Pre úspešnú inštaláciu programu mybeem je potrebný jeho inštalačný deb balíček. Inštalácia sa prevedie nainštalovaním deb balíčka do systému. Pre úspešnú inštaláciu je potrebné mať v systéme nainštalované knižnice:

```bash
sudo apt-get install libpcap-dev libxml2-dev libssl-dev libsctp-dev libsctp-dev libssl0.9.8 libsctp-dev libxml2-utils gawk gcc autoconf build-essential libtool
```
#### 2. Stiahnúť balík nDPI verzie 1.5.2:
```bash
wget https://git.cnl.sk/monica/slameter_exporter/raw/master/lib/nDPI_1.5.2.tar.gz --no-check-certificate
```
#### 3. Postup inštalácie balíka nDPI verzie 1.5.2:
```bash
sudo su
tar zxvf nDPI_1.5.2.tar.gz
cd nDPI
sh autogen.sh
make
make install
echo "export LD_LIBRARY_PATH=\"/usr/local/lib:$LD_LIBRARY_PATH\"" >> ~/.bashrc
```
#### 4. Stiahnutie zdrojových kódov:
```bash
wget https://git.cnl.sk/monica/slameter_exporter/repository/archive.tar.gz --no-check-certificate
```
#### 5. Vykonanie prekladu:
```bash
tar zxvf archive.tar.gz
cd slameter_exporter.git/src/mybeem
make
```
#### 6. Spustenie programu:
```bash
sudo ./beem -c config.xml
```

Po úspešnom nainštalovaní exportéra je potrebné nainštalovať kolektor a databázu podľa postupu uvedeného nižšie.


## 2. Inštalácia PostgreSQL a Javy pod Ubuntu 14.04
------------------------------
Nainštalovať PostgreSQL 9.2, Java 7 a ďalšie potrebné balíky:
```bash
sudo apt-get update
```

```bash
sudo apt-get install postgresql libpq-dev postgresql-contrib openjdk-7-jre-headless lksctp-tools
```

Nastaviť Javu 7 ako defaultný Java interpréter. Po zadaní nasledovného príkazy vyberieme správnu verziu Javy (7). Nastavenú verziu možno overiť príkazom ```bash java -version ```:

```bash
sudo update-alternatives --config java
```

## 3. Inštalácia databázy
-------------------------------
Zo svojho používateľského konta nastavíme heslo pre používateľa postgres príkazom 

```bash
sudo passwd postgres
```

Pomocou nasledujúcich príkazov, vykonáme zmenu hesla pre databázu
V tomto kroku sa prepneme na používateľa postgres

```bash
su postgres
```

Pre vstup do databázy použijeme nasledujúci príkaz

```bash
psql
```

Upravíme používateľa postgres, pričom namiesto password si zvolíme ľubovoľne heslo.

```bash
alter user postgres with encrypted password 'password';
```

Ukončíme prácu s databázou

```bash
\q
```

Odhlásime sa ako používateľ postgres, čím sa dostaneme späť do svojho vlastného používateľského konta 

```bash
exit
```

Nasledovne stiahneme skripty, pre vytvorenie tabuliek
Vytvoríme si priečinok pre uloženie skriptov potrebných k optimalizácii databázy
Vojdeme do vnútra daného priečinka a zadáme príkaz pre stiahnutie potrebných súborov:

```bash
sudo git clone https://git.cnl.sk/ladislav.berta/bmIDSv2-3.git -c http.sslVerify=false
```

ak git nie je nainštalovaný, je potrebné ho nainštalovať vykonaním príkazu:

```bash
sudo apt-get install git
```

Teraz sa presunieme do stiahnutého priečinka.

```bash
cd bmIDSv2-3/3_6_db_install
```

Zistíme úplnú cestu k priečinku. K tomu použije príkaz:

```bash
pwd
```

Následne cestu skopírujeme.
Otvoríme súbor bmdbScript.sh pre editáciu obsahu pomocou nasledujúceho príkazu. Hneď na začiatku v súbore je premenná path, do ktorej priradíme skopírovanú cestu z predchádzajuceho kroku.

```bash
sudo vim bmdbScript.sh
```

V ďalšom kroku spustíme súbor bmdbScript.sh, po spustení ktorého su vytvorené tabuľky a potrebné vzťahy 

```bash
sh bmdbScript.sh
```

Následne je potrebné zadať tieto údaje :
Administrative postgres user name -defaultne je nastavené na postgres 
Database server ip address/host - IP adresa servera kde je vytvorená databáza 
Password for user postgres - heslo ktoré sme zadali v kroku 1. 
Password for user bm: bm 
Prihlásenie do databázy ako používateľ bm realizujeme tak, že sa prepneme na konto postgres a zadáme nasledujúci príkaz pričom IP je adresa počítača na ktorom beží databáza, prípadne localhost ak beží lokálne.

```bash
psql -h IP -U bm -d bmdb
```

## 4. Inštalácia samotného JXColl
Nastaviť prístupové práva pre pripojenie na databázu:
pripojiť sa na databázu ako user postgres a nastaviť ľubovoľné heslo:

```bash
sudo -u postgres psql     
ALTER USER postgres WITH ENCRYPTED PASSWORD 'password';
\q
```

Keď je to potrebné, tak nastaviť privilégia v súbore ```bash /etc/postgresql/9.2/main/pg_hba.conf ```. Na úvod sekcie ipv4 pridáme riadok, kde v poli IP_ADDRESSES uvedieme adresy alebo rozsah adries, z ktorých sa na databázu pripájajú kolektor a analyzéry.

```bash
host    bmdb, bmdwh    bm,bmro    IP_ADDRESSES    md5 
```

Nakonfigurovať rozhrania, na ktorých má DB počúvať na prichádzajúce pripojenia v súbore ```bash /etc/postgresql/9.2/main/postgresql.conf ```. Predvolené nastavenie je localhost. V sekcii "Connections and authentication" zadať adresy rozhraní oddelené čiarkou, alebo zadať '*', čo povolí pripojenie odkiaľkoľvek.
Vojdeme do už stiahnutého priečinka bmIDSv2-3, kde sa nachádza DEB balík pre inštaláciu JXColl

```bash
cd bmIDSv2-3
```

Spustíme stiahnutý DEB balík pomocou príkazu

```bash
sudo dpkg -i jxcoll_3.9_i386.deb
```

Po inštalácii DEB balíka je nutné vytvoriť databázovú štruktúru nástroja JXColl. a to spustením skriptu pomocou príkazu

```bash
sh /usr/lib/jxcoll/bmdbScripts/bmdbScript.sh
```

Nastaviť konfiguračný súbor ```bash /etc/jxcoll/jxcoll_config.xml ```. Najmä databázové pripojenie a protokol na počúvanie pre IPFIX správy. V súbore jxcoll_config.xml je potrebné overiť či je zapnuté posielanie údajov cez ACP (V sekcii acp, pri acp transfer má byť hodnota yes).
Po úspešnom nainštalovaní aplikácie kolektora sa presunieme do adresára kde sa nachádza spustiteľný jar súbor.

```bash
cd /usr/lib/jxcoll
```

Ak sa už nachádzame v priečinku jxcoll, aplikáciu JXColl je možné spustiť príkazom.

```bash
java -jar jxcoll.jar
```


## 5. bmIDS analyzer
Aplikácia bmIDSanalyzer má byť inštalovaná na serveri kde je nainštalovaná webová aplikácia nástroja SLAmeter. Pre úspešnú inštaláciu v operačnom systéme Ubuntu je potrebné vykonať:
Najprv je potrebné nainštalovať redis.

```bash
apt-get install redis-server
```
Stiahnuť inštalačný súbor z GIT
```bash
sudo git clone https://git.cnl.sk/ladislav.berta/bmIDSv2-3.git -c http.sslVerify=false
```
ak git nie je nainštalovaný, je potrebné ho nainštalovať vykonaním príkazu:
```bash
sudo apt-get install git
```
výsledkom bude adresár bmIDSv2-3, následne treba vojsť do adresára
```bash
cd bmIDSv2-3
```
rozbaliť súbor
```bash
sudo tar -xzvf bmIDS.tar.gz
```
výsledkom čoho bude adresárová štruktúra so spustiteľným .jar súborom a konfiguračnými súbormi
následne vojdeme do adresára
```bash
cd bmIDS 
```
v priečinku sa nachádza konfiguračný súbor config.xml, v ktorom je potrebné nastaviť najmä IP adresu kde beží kolektor, port, IP adresu databázy bmdb, port, a ďašie potrebné údaje.
program je konzolová aplikácia, ktorú je možné spustiť príkazom
```bash
java -jar bmIDSanalyzer.jar 
```
voliteľné parametre sú:
* konfiguračný súbor (prevolené config.xml) - je potrebné správne nastavenie hodnôt, IP adresa a port na ktorom beží kolektor
* parameter -l (spustí režim učenia)



## BmIDS web
----------------------------
Webová aplikácia sa neinštaluje, ale je potrebné ju nasadiť na web server. Postup nasadenia webovej aplikácie SLAmeter je opísaný v Inštalácia webSLA. Po úspešnom nasadení bude aplikácia ids prístupná na adrese inštalovaného servera.

## Použitie programu
---------------------
Pred spustením samotnej analyzujúcej aplikácie bmIDSanalyzer, je potrebné najprv spustit exportovací a zhromažďovací proces, pričom je potrebné dodžať postupnosť spustení. Postup je nasledovný:
Na serveri kde je nainštalovaný kolektor, treba spustiť zhromažďovací proces (JXColl):
```bash
cd /usr/lib/jxcoll
java -jar jxcoll.jar
```
Spustiť exportovací proces (MyBeem):
```bash
sudo mybeem
```
Po spustení zhromažďovacieho a exportovacieho procesu je možné spustenie analyzéra bmIDS na serveri kde je nainštalovaný. Aplikácia bmIDS analyzer je konzolová aplikácia a spustiť ju môžeme príkazom:
```bash
java -jar bmIDSanalyzer.jar 
```
voliteľné parametre sú:
* konfiguračný súbor (prevolené config.xml)
* parameter -l (spustí režim učenia)

Pred spustením detekcie je potrebné ešte spustiť Inštalácia kolektor a exportér, zároveň je potrebné spustiť databázový server s odpovedajúcou databázou v ktorej sa nachádzajú historické záznamy potrebné pre režim učenia a aj databázový server do ktorej sa ukladajú údaje o podozrivej prevádzke.