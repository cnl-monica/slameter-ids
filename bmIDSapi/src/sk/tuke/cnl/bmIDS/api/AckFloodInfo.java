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
 *  Subor: AckFloodInfo.java
 */
package sk.tuke.cnl.bmIDS.api;

import java.util.Date;

/**
 * Predstavuje údaje o výstupoch detekcie útoku typu ACK Flood.
 * @author Ladislav Berta
 */
public class AckFloodInfo implements TrafficInfo {

    private Date time;
    private int ackCount;
    private double attackProbability;
    private int maxAckCount;

    /**
     * Konštruktor pre nastavenie naučenej hornej hranice sledovanej charakteristiky útoku typu ACK Flood.
     * @param maxAckCount sledovanej charakteristiky útoku typu ACK Flood
     */
    public AckFloodInfo(int maxAckCount) {
        this.maxAckCount = maxAckCount;
    }

    /**
     * Konštruktor pre nastavenie údajov o výstupoch detekcie útoku typu ACK Flood.
     * @param time čas vyhodnotenia
     * @param ackCount hodnota sledovanej charakteristiky
     * @param attackProbability pravdepodobnosť útoku
     */
    public AckFloodInfo(Date time, int ackCount, double attackProbability) {
        this.time = time;
        this.ackCount = ackCount;
        this.attackProbability = attackProbability;
    }

    /**
     * Vráti pravdepodobnosť útoku typu ACK Flood.
     * @return pravdepodobnosť útoku typu ACK Flood
     */
    public double getAttackProbability() {
        return attackProbability;
    }

    /**
     * Vráti hornú hranicu sledovanej charakteristiky útoku typu ACK Flood.
     * @return horná hranica sledovanej charakteristiky útoku typu ACK Flood
     */
    public int getMaxAckCount() {
        return maxAckCount;
    }

    /**
     * Vráti hodnotu sledovanej charakteristiky útoku typu ACK Flood..
     * @return hodnota sledovanej charakteristiky útoku typu ACK Flood
     */
    public int getAckCount() {
        return ackCount;
    }

    /**
     * Vráti čas vyhodnotenia prevádzky voči útoku typu ACK Flood.
     * @return čas vyhodnotenia prevádzky voči útoku typu ACK Flood
     */
    public Date getTime() {
        return time;
    }
}
