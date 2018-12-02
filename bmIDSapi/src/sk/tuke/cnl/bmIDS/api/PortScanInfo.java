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
 *  Subor: PortScanInfo.java
 */
package sk.tuke.cnl.bmIDS.api;

import java.util.Date;

/**
 * Predstavuje údaje o výstupoch detekcie útoku typu Port Scan.
 * @author Martin Ujlaky
 */
public class PortScanInfo implements TrafficInfo {

    private Date time;
    private int flowCount;
    private double attackProbability;
    private int maxFlowCount;

    /**
     * Konštruktor pre nastavenie naučenej hornej hranice sledovanej charakteristiky útoku typu Port Scan.
     * @param maxFlowCount sledovanej charakteristiky útoku typu Port Scan
     */
    public PortScanInfo(int maxFlowCount) {
        this.maxFlowCount = maxFlowCount;
    }

    /**
     * Konštruktor pre nastavenie údajov o výstupoch detekcie útoku typu Port Scan.
     * @param time čas vyhodnotenia
     * @param flowCount hodnota sledovanej charakteristiky
     * @param attackProbability pravdepodobnosť útoku
     */
    public PortScanInfo(Date time, int flowCount, double probability) {
        this.time = time;
        this.flowCount = flowCount;
        this.attackProbability = probability;
    }

    /**
     * Vráti pravdepodobnosť útoku typu Port Scan.
     * @return pravdepodobnosť útoku typu Port Scan
     */
    public double getAttackProbability() {
        return attackProbability;
    }

    /**
     * Vráti hornú hranicu sledovanej charakteristiky útoku typu Port Scan.
     * @return horná hranica sledovanej charakteristiky útoku typu Port Scan
     */
    public int getFlowCount() {
        return flowCount;
    }

    /**
     * Vráti hodnotu sledovanej charakteristiky útoku typu Port Scan.
     * @return hodnota sledovanej charakteristiky útoku typu Port Scan
     */
    public int getMaxFlowCount() {
        return maxFlowCount;
    }

    /**
     * Vráti čas vyhodnotenia prevádzky voči útoku typu Port Scan.
     * @return čas vyhodnotenia prevádzky voči útoku typu Port Scan
     */
    public Date getTime() {
        return time;
    }
}
