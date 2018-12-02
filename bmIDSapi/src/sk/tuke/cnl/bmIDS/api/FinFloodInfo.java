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
 *  Subor: FinFloodInfo.java
 */
package sk.tuke.cnl.bmIDS.api;

import java.util.Date;

/**
 * Predstavuje údaje o výstupoch detekcie útoku typu FIN Flood.
 * @author Ladislav Berta
 */
public class FinFloodInfo implements TrafficInfo {

    private Date time;
    private int finCount;
    private double attackProbability;
    private int maxFinCount;

    /**
     * Konštruktor pre nastavenie naučenej hornej hranice sledovanej charakteristiky útoku typu FIN Flood.
     * @param maxFinCount sledovanej charakteristiky útoku typu FIN Flood
     */
    public FinFloodInfo(int maxFinCount) {
        this.maxFinCount = maxFinCount;
    }

    /**
     * Konštruktor pre nastavenie údajov o výstupoch detekcie útoku typu FIN Flood.
     * @param time čas vyhodnotenia
     * @param finCount hodnota sledovanej charakteristiky
     * @param attackProbability pravdepodobnosť útoku
     */
    public FinFloodInfo(Date time, int finCount, double attackProbability) {
        this.time = time;
        this.finCount = finCount;
        this.attackProbability = attackProbability;
    }

    /**
     * Vráti pravdepodobnosť útoku typu FIN Flood.
     * @return pravdepodobnosť útoku typu FIN Flood
     */
    public double getAttackProbability() {
        return attackProbability;
    }

    /**
     * Vráti hornú hranicu sledovanej charakteristiky útoku typu FIN Flood.
     * @return horná hranica sledovanej charakteristiky útoku typu FIN Flood
     */
    public int getMaxFinCount() {
        return maxFinCount;
    }

    /**
     * Vráti hodnotu sledovanej charakteristiky útoku typu FIN Flood..
     * @return hodnota sledovanej charakteristiky útoku typu FIN Flood
     */
    public int getFinCount() {
        return finCount;
    }

    /**
     * Vráti čas vyhodnotenia prevádzky voči útoku typu FIN Flood.
     * @return čas vyhodnotenia prevádzky voči útoku typu FIN Flood
     */
    public Date getTime() {
        return time;
    }
}
