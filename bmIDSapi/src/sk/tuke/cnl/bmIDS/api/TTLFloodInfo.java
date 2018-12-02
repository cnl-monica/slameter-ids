/*  Copyright (2013) Ladislav Berta
 *  This file is part of bmIDSanalyzer.
 *  bmIDSanylyzer is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  bmIDSanalyzer is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with bmIDSanalyzer.  If not, see <http://www.gnu.org/licenses/>.
 *
 *             Fakulta Elektrotechniky a informatiky
 *               Technicka univerzita v Kosiciach
 *
 *              Systemy pre detekciu narusenia sieti
 *                      Bakalarska praca
 *
 *  Veduci BP:        Ing. Miroslav Biňas, PhD.
 *  Konzultant BP:    Ing. Adrián Pekár
 *
 *  Autor:            Ladislav Berta
 *
 *  Zdrojove texty:
 *  Subor: TTLFloodInfo.java
 */
package sk.tuke.cnl.bmIDS.api;

import java.util.Date;

/**
 * Predstavuje údaje o výstupoch detekcie útoku typu TTL expiry Flood.
 * @author Ladislav Berta
 */
public class TTLFloodInfo implements TrafficInfo {

    private Date time;
    private int ttlCount;
    private double attackProbability;
    private int maxTtlCount;

    /**
     * Konštruktor pre nastavenie naučenej hornej hranice sledovanej charakteristiky útoku typu TTL expiry Flood.
     * @param maxTtlCount sledovanej charakteristiky útoku typu TTL expiry Flood
     */
    public TTLFloodInfo(int maxTtlCount) {
        this.maxTtlCount = maxTtlCount;
    }

    /**
     * Konštruktor pre nastavenie údajov o výstupoch detekcie útoku typu TTL expiry Flood.
     * @param time čas vyhodnotenia
     * @param synCount hodnota sledovanej charakteristiky
     * @param attackProbability pravdepodobnosť útoku
     */
    public TTLFloodInfo(Date time, int ttlCount, double attackProbability) {
        this.time = time;
        this.ttlCount = ttlCount;
        this.attackProbability = attackProbability;
    }

    /**
     * Vráti pravdepodobnosť útoku typu TTL expiry Flood.
     * @return pravdepodobnosť útoku typu TTL expiry Flood
     */
    public double getAttackProbability() {
        return attackProbability;
    }

    /**
     * Vráti hornú hranicu sledovanej charakteristiky útoku typu TTL expiry Flood.
     * @return horná hranica sledovanej charakteristiky útoku typu TTL expiry Flood
     */
    public int getMaxTtlCount() {
        return maxTtlCount;
    }

    /**
     * Vráti hodnotu sledovanej charakteristiky útoku typu TTL expiry Flood..
     * @return hodnota sledovanej charakteristiky útoku typu TTL expiry Flood
     */
    public int getTtlCount() {
        return ttlCount;
    }

    /**
     * Vráti čas vyhodnotenia prevádzky voči útoku typu TTL expiry Flood.
     * @return čas vyhodnotenia prevádzky voči útoku typu TTL expiry Flood
     */
    public Date getTime() {
        return time;
    }
}
