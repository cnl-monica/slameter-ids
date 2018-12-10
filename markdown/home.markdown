# bmIDS
-----------------
Program bmIDS predstavuje systém pre detekciu narušenia v počítačovej sieti. Jeho úlohou je spracovať údaje o prebiehajúcej komunikácii v sieti, vyhodnotiť prevádzku podľa vopred určených pravidiel a následne určiť mieru pravdepodobnosti prebiehajúceho útoku, resp. signalizovať anomálie. Zdrojom údajov pre systém bmIDS sú nástroje exportér (mybeem) a kolektor (JXColl), ktoré poskytuje informácie o komunikácii v sieti vo formáte správ protokolu IPFIX. Na prenos týchto správ v reálnom čase slúži aplikačné rozhranie ACP. Na vyhodnotenie prevádzky a detekciu jednotlivých útokov bmIDS používa fuzzy subsystémy.

Systém pozostáva z dvoch aplikácii. BmIDSanalyzer je konzolová aplikácia, ktorá sa spustí na serveri a neustále vyhodnocuje prevádzku v počítačovej sieti. Záznamy o kritickej prevádzke sa zapisujú a uchovávajú v databáze. Aplikácia zároveň môže odosielať údaje o vyhodnotenej prevádzke ďalšej aplikácii, ktorá beží na webovom serveri. Aplikácia ids je súčasťou webovej aplikácie SLAmeter, a umožňuje administrátorovi aktívne sledovať prevádzku a tiež zobraziť údaje o podozrivej prevádzke vo webovom prostredí.

V aktuálnej verzii programu je detekovateľných 6 typov útokov.
* Port Scan - skenovanie portov
* Syn Flood - záplava SYN príznakmi
* Udp Flood - záplava UDP paketmi
* RST Flood - záplava paketmi TCP protokolu s príznakom RST
* TTL Expiry Flood - záplava paketmi ICMP protokolu typu Time exceeded - vypršal čas
* FIN Flood - záplava paketmi TCP protokolu s príznakom FIN

Systém **[bmIDS](https://git.cnl.sk/monica/slameter_ids/wikis/bmIDS)**.
