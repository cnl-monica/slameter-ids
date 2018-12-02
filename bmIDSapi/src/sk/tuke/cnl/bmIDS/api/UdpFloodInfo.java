/*  Copyright (2012) Martin Ujlaky.
 *  This file is part of bmIDSapi.
 *  bmIDSapi is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  bmIDSapi is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with bmIDSapi.  If not, see <http://www.gnu.org/licenses/>.
 *
 *                Fakulta Elektrotechniky a informatiky
 *                  Technicka univerzita v Kosiciach
 *
 *  System bmIDS pre detekciu narusenia v pocitacovych sietach
 *                      Diplomova praca
 *
 *  Veduci DP:        Ing. Juraj Giertl, PhD.
 *  Konzultanti DP:   Ing. Martin Reves
 *
 *  Diplomant:        Bc. Martin Ujlaky
 *
 *  Zdrojove texty:
 *  Subor: UdpFloodInfo.java
 */
package sk.tuke.cnl.bmIDS.api;

import java.util.Date;

/**
 * Predstavuje údaje o výstupoch detekcie útoku typu UDP Flood.
 * @author Martin Ujlaky
 */
public class UdpFloodInfo implements TrafficInfo {

    private Date time;
    private int packetCount;
    private double attackProbability;
    private int maxPacketCount;

    /**
     * Konštruktor pre nastavenie naučenej hornej hranice sledovanej charakteristiky útoku typu UDP Flood.
     * @param maxPacketCount sledovanej charakteristiky útoku typu UDP Flood
     */
    public UdpFloodInfo(int maxPacketCount) {
        this.maxPacketCount = maxPacketCount;
    }

    /**
     * Konštruktor pre nastavenie údajov o výstupoch detekcie útoku typu UDP Flood.
     * @param time čas vyhodnotenia
     * @param packetCount hodnota sledovanej charakteristiky
     * @param attackProbability pravdepodobnosť útoku
     */
    public UdpFloodInfo(Date time, int packetCount, double probability) {
        this.time = time;
        this.packetCount = packetCount;
        this.attackProbability = probability;
    }

    /**
     * Vráti pravdepodobnosť útoku typu UDP Flood.
     * @return pravdepodobnosť útoku typu UDP Flood
     */
    public double getAttackProbability() {
        return attackProbability;
    }

    /**
     * Vráti hornú hranicu sledovanej charakteristiky útoku typu UDP Flood.
     * @return horná hranica sledovanej charakteristiky útoku typu UDP Flood
     */
    public int getMaxPacketCount() {
        return maxPacketCount;
    }

    /**
     * Vráti hodnotu sledovanej charakteristiky útoku typu UDP Flood.
     * @return hodnota sledovanej charakteristiky útoku typu UDP Flood
     */
    public int getPacketCount() {
        return packetCount;
    }

    /**
     * Vráti čas vyhodnotenia prevádzky voči útoku typu UDP Flood.
     * @return čas vyhodnotenia prevádzky voči útoku typu UDP Flood
     */
    public Date getTime() {
        return time;
    }
}
