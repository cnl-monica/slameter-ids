/*  Copyright © 2013 MONICA Research Group / TUKE.
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
 *  Subor: FinFloodSignTraffic.java
 */
package sk.tuke.cnl.bmIDS.traffic;

import sk.tuke.cnl.bmIDS.IPFlow;

/**
 * Prevádzka roztriedená podľa charakteristík útoku typu FIN Flood. 
 * @author Ladislav Berta
 */
public class FinFloodSignTraffic {

    private long id;
    private int obsPoint;
    private String srcIP;
    private String destIP;
    private int destPort;
    private int finCount;
    private long sinceMilis;
    private long tillMilis;
    private double attackProbability = 0;
    private boolean firstEdit = true;

    /**
     * Vytvorí objekt prevádzky podľa charakteristík útoku typu FIN Flood.
     * @param obsPoint
     * @param sourceIP
     * @param destIP
     * @param destPort
     * @param finCount
     * @param sinceMilis    
     * @param tillMilis 
     */
    public FinFloodSignTraffic(int obsPoint, String sourceIP, String destIP, int destPort, int finCount, long since, long till) {
        this.obsPoint = obsPoint;
        this.srcIP = sourceIP;
        this.destIP = destIP;
        this.destPort = destPort;
        this.finCount = finCount;
        this.sinceMilis = since;
        this.tillMilis = since + till;
    }

    public String getSrcIP() {
        return srcIP;
    }

    public String getDestIP() {
        return destIP;
    }

    public int getDestPort() {
        return destPort;
    }

    public int getObsPoint() {
        return obsPoint;
    }

    public int getFinCount() {
        return finCount;
    }

    public long getSinceMilis() {
        return sinceMilis;
    }

    public long getTillMilis() {
        return tillMilis;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public double getAttackProbability() {
        return attackProbability;
    }

    public void setAttackProbability(double attackProbability) {
        this.attackProbability = attackProbability;
    }

    /**
     * Upraví charakteristiky prevádzky podľa hodnôt nového toku.
     * @param currentIPFlow nový tok
     * @return počet FIN príznakov v zatriedenej prevádzke 
     */
    public int edit(IPFlow currentIPFlow) {
        finCount += currentIPFlow.getFinCount();

        if (firstEdit) {
            tillMilis = currentIPFlow.getEndTimeMilis();
            firstEdit = false;

        } else {
            if (tillMilis < currentIPFlow.getEndTimeMilis()) {
                tillMilis = currentIPFlow.getEndTimeMilis();
            }
        }

        return finCount;
    }

    public void update(FinFloodSignTraffic maxTraffic, double probability) {
        if (tillMilis < maxTraffic.getTillMilis()) {
            tillMilis = maxTraffic.getTillMilis();
        }
        finCount += maxTraffic.getFinCount();
        attackProbability = (attackProbability + probability) / 2;

    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof IPFlow) {
            IPFlow ipFlow = (IPFlow) obj;
            if (ipFlow.getDestIP().equals(destIP) && ipFlow.getDestPort() == destPort && ipFlow.getObsPoint() == obsPoint && ipFlow.getSourceIP().equals(srcIP)) {
                return true;
            } else {
                return false;
            }
        } else if (obj instanceof FinFloodSignTraffic) {
            FinFloodSignTraffic traffic = (FinFloodSignTraffic) obj;
            if (traffic.getDestIP().equals(destIP) && traffic.getDestPort() == destPort && traffic.getObsPoint() == obsPoint && traffic.getSrcIP().equals(srcIP)) {
                return true;
            } else {
                return false;
            }
        } else {
            System.out.println("Objekt, ktory ma byt porovnany je nespravneho typu");
            return false;
        }
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 37 * hash + this.obsPoint;
        hash = 37 * hash + (this.destIP != null ? this.destIP.hashCode() : 0);
        hash = 37 * hash + this.destPort;
        return hash;
    }
}
