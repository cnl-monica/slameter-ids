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
 *  Subor: PortScanSignTraffic.java
 */
package sk.tuke.cnl.bmIDS.traffic;

import java.util.ArrayList;
import sk.tuke.cnl.bmIDS.IPFlow;

/**
 * Prevádzka roztriedená podľa charakteristík útoku typu Port Scan. 
 * @author Martin Ujlaky
 */
public class PortScanSignTraffic {

    private long id;
    private int obsPoint;
    private String sourceIP;
    private String destIP;
    private ArrayList<Integer> destPortList = new ArrayList<Integer>();
    private int flowCount;
    private long sinceMilis;
    private long tillMilis;
    private double attackProbability = 0;
    private boolean firstEdit = true;

    /**
     * Vytvorí objekt prevádzky podľa charakteristík útoku typu Port Scan.
     * @param obsPoint
     * @param sourceIP
     * @param destIP
     * @param destPort
     * @param since
     * @param till 
     */
    public PortScanSignTraffic(int obsPoint, String sourceIP, String destIP, int destPort, long since, long till) {
        this.obsPoint = obsPoint;
        this.sourceIP = sourceIP;
        this.destIP = destIP;
        this.flowCount = 1;
        this.sinceMilis = since;
        this.tillMilis = since + till;
        destPortList.add(destPort);
    }

    /**
     * Upraví charakteristiky prevádzky podľa hodnôt nového toku.
     * @param currentIPFlow nový tok
     * @return počet tokov v zatriedenej prevádzke 
     */
    public int edit(IPFlow currentIPFlow) {
        if (!destPortList.contains(currentIPFlow.getDestPort())) {
            destPortList.add(currentIPFlow.getDestPort());
            flowCount++;

            if (firstEdit) {
                tillMilis = currentIPFlow.getEndTimeMilis();
                firstEdit = false;

            } else {
                if (tillMilis < currentIPFlow.getEndTimeMilis()) {
                    tillMilis = currentIPFlow.getEndTimeMilis();
                }
            }
        }
        return flowCount;
    }

    public String getDestIP() {
        return destIP;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public int getObsPoint() {
        return obsPoint;
    }

    public int getFlowCount() {
        return flowCount;
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

    public void update(PortScanSignTraffic maxTraffic, double probability) {
        if (tillMilis < maxTraffic.getTillMilis()) {
            tillMilis = maxTraffic.getTillMilis();
        }
        flowCount += maxTraffic.getFlowCount();
        if (attackProbability == 0) {
            attackProbability = probability;
        } else {
            attackProbability = (attackProbability + probability) / 2;
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof IPFlow) {
            IPFlow ipFlow = (IPFlow) obj;
            if (ipFlow.getSourceIP().equals(sourceIP) && ipFlow.getDestIP().equals(destIP) && ipFlow.getObsPoint() == obsPoint) {
                return true;
            } else {
                return false;
            }
        } else if (obj instanceof PortScanSignTraffic) {
            PortScanSignTraffic traffic = (PortScanSignTraffic) obj;
            if (traffic.getSourceIP().equals(sourceIP) && traffic.getDestIP().equals(destIP) && traffic.getObsPoint() == obsPoint) {
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
        hash = 37 * hash + (this.sourceIP != null ? this.sourceIP.hashCode() : 0);
        hash = 37 * hash + (this.destIP != null ? this.destIP.hashCode() : 0);
        return hash;
    }
}