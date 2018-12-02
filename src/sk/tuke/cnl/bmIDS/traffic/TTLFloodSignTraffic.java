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
 *  Subor: TTLFloodSignTraffic.java
 */
package sk.tuke.cnl.bmIDS.traffic;

import java.util.LinkedList;
import sk.tuke.cnl.bmIDS.IPFlow;

/**
 * Prevádzka roztriedená podľa charakteristík útoku typu TTL expiry Flood. 
 * @author Ladislav Berta
 */
public class TTLFloodSignTraffic {

    private long id;
    private int obsPoint;
    private String srcIP;
    private String destIP;
    private LinkedList<Integer> destPortList;
    private long ttlCount;
    private long sinceMilis;
    private long tillMilis;
    private double attackProbability = 0;
    private boolean firstEdit = true;

    /**
     * Vytvorí objekt prevádzky podľa charakteristík útoku typu TTL expiry Flood.
     * @param obsPoint
     * @param sourceIP
     * @param destIP
     * @param destPort
     * @param ttlCount
     * @param sinceMilis    
     * @param tillMilis
     */
    public TTLFloodSignTraffic(int obsPoint, String sourceIP, String destIP, int destPort, long ttlCount, long since, long till) {
        this.destPortList = new LinkedList<Integer>();
        this.obsPoint = obsPoint;
        this.destIP = destIP;
        this.srcIP = sourceIP;
        this.destPortList.add(destPort);
        this.ttlCount = ttlCount;
        this.sinceMilis = since;
        this.tillMilis = since + till;
    }

    public String getDestIP() {
        return destIP;
    }

    public String getSrcIP() {
        return srcIP;
    }

    public LinkedList<Integer> getDestPortList() {
        return destPortList;
    }

    public int getObsPoint() {
        return obsPoint;
    }

    public long getTtlCount() {
        return ttlCount;
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
     * @return počet ICMP paketov (typ=11, kod=0) v zatriedenej prevádzke 
     */
    public long edit(IPFlow currentIPFlow) {
        ttlCount += currentIPFlow.getTtlCount();

        if (firstEdit) {
            tillMilis = currentIPFlow.getEndTimeMilis();
            firstEdit = false;

        } else {
            if (tillMilis < currentIPFlow.getEndTimeMilis()) {
                tillMilis = currentIPFlow.getEndTimeMilis();
            }
        }

        if (!destPortList.contains(currentIPFlow.getDestPort())) {
            destPortList.add(currentIPFlow.getDestPort());
        }

        return ttlCount;
    }

    public void update(TTLFloodSignTraffic traffic, double probability) {
        if (tillMilis < traffic.getTillMilis()) {
            tillMilis = traffic.getTillMilis();
        }
        ttlCount += traffic.getTtlCount();
        attackProbability = (attackProbability + probability) / 2;

        for (int destPort : traffic.getDestPortList()) {
            if (!destPortList.contains(destPort)) {
                destPortList.add(destPort);
            }
        }
    }

    @Override
    public boolean equals(Object obj) {
        //
        if (obj instanceof IPFlow) {
            IPFlow ipFlow = (IPFlow) obj;
            if (ipFlow.getDestIP().equals(destIP) && ipFlow.getSourceIP().equals(srcIP) && ipFlow.getObsPoint() == obsPoint) {
                return true;
            } else {
                return false;
            }
        } else if (obj instanceof TTLFloodSignTraffic) {
            TTLFloodSignTraffic traffic = (TTLFloodSignTraffic) obj;
            if (traffic.getDestIP().equals(destIP) && traffic.getSrcIP().equals(srcIP) && traffic.getObsPoint() == obsPoint) {
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
        return hash;
    }
}
