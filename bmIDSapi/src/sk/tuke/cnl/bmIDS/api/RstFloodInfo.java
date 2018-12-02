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
 *  Subor: RstFloodInfo.java
 */
package sk.tuke.cnl.bmIDS.api;

import java.util.Date;

/**
 * Predstavuje údaje o výstupoch detekcie útoku typu RST Flood.
 * @author Ladislav Berta
 */
public class RstFloodInfo implements TrafficInfo {

    private Date time;
    private int rstCount;
    private double attackProbability;
    private int maxRstCount;

    /**
     * Konštruktor pre nastavenie naučenej hornej hranice sledovanej charakteristiky útoku typu RST Flood.
     * @param maxRstCount sledovanej charakteristiky útoku typu RST Flood
     */
    public RstFloodInfo(int maxRstCount) {
        this.maxRstCount = maxRstCount;
    }

    /**
     * Konštruktor pre nastavenie údajov o výstupoch detekcie útoku typu RST Flood.
     * @param time čas vyhodnotenia
     * @param synCount hodnota sledovanej charakteristiky
     * @param attackProbability pravdepodobnosť útoku
     */
    public RstFloodInfo(Date time, int rstCount, double attackProbability) {
        this.time = time;
        this.rstCount = rstCount;
        this.attackProbability = attackProbability;
    }

    /**
     * Vráti pravdepodobnosť útoku typu RST Flood.
     * @return pravdepodobnosť útoku typu RST Flood
     */
    public double getAttackProbability() {
        return attackProbability;
    }

    /**
     * Vráti hornú hranicu sledovanej charakteristiky útoku typu RST Flood.
     * @return horná hranica sledovanej charakteristiky útoku typu RST Flood
     */
    public int getMaxRstCount() {
        return maxRstCount;
    }

    /**
     * Vráti hodnotu sledovanej charakteristiky útoku typu RST Flood..
     * @return hodnota sledovanej charakteristiky útoku typu RST Flood
     */
    public int getRstCount() {
        return rstCount;
    }

    /**
     * Vráti čas vyhodnotenia prevádzky voči útoku typu RST Flood.
     * @return čas vyhodnotenia prevádzky voči útoku typu RST Flood
     */
    public Date getTime() {
        return time;
    }
}
