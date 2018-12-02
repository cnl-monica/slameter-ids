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
 *  Subor: SynFloodInfo.java
 */
package sk.tuke.cnl.bmIDS.api;

import java.util.Date;

/**
 * Predstavuje údaje o výstupoch detekcie útoku typu SYN Flood.
 * @author Martin Ujlaky
 */
public class SynFloodInfo implements TrafficInfo {

    private Date time;
    private int synCount;
    private double attackProbability;
    private int maxSynCount;

    /**
     * Konštruktor pre nastavenie naučenej hornej hranice sledovanej charakteristiky útoku typu SYN Flood.
     * @param maxSynCount sledovanej charakteristiky útoku typu SYN Flood
     */
    public SynFloodInfo(int maxSynCount) {
        this.maxSynCount = maxSynCount;
    }

    /**
     * Konštruktor pre nastavenie údajov o výstupoch detekcie útoku typu SYN Flood.
     * @param time čas vyhodnotenia
     * @param synCount hodnota sledovanej charakteristiky
     * @param attackProbability pravdepodobnosť útoku
     */
    public SynFloodInfo(Date time, int synCount, double attackProbability) {
        this.time = time;
        this.synCount = synCount;
        this.attackProbability = attackProbability;
    }

    /**
     * Vráti pravdepodobnosť útoku typu SYN Flood.
     * @return pravdepodobnosť útoku typu SYN Flood
     */
    public double getAttackProbability() {
        return attackProbability;
    }

    /**
     * Vráti hornú hranicu sledovanej charakteristiky útoku typu SYN Flood.
     * @return horná hranica sledovanej charakteristiky útoku typu SYN Flood
     */
    public int getMaxSynCount() {
        return maxSynCount;
    }

    /**
     * Vráti hodnotu sledovanej charakteristiky útoku typu SYN Flood..
     * @return hodnota sledovanej charakteristiky útoku typu SYN Flood
     */
    public int getSynCount() {
        return synCount;
    }

    /**
     * Vráti čas vyhodnotenia prevádzky voči útoku typu SYN Flood.
     * @return čas vyhodnotenia prevádzky voči útoku typu SYN Flood
     */
    public Date getTime() {
        return time;
    }
}
