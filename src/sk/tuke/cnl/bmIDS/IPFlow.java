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
 *  Subor: IPFlow.java
 */
package sk.tuke.cnl.bmIDS;

/**
 * Predstavuje IP tok a obsahuje elementy zo šablóny .
 * @author Martin Ujlaky
 */
public class IPFlow {

    private int obsPoint;
    private int fer;
    private String sourceIP;
    private String destIP;
    private int sourcePort;
    private int destPort;
    private double octetCount;
    private long packetCount;
    private long startTimeMilis;
    private long endTimeMilis;
    private int protocol;
    private int synCount;
    private int rstCount;
    private int ackCount;
    private int finCount;
    //private long ttlCount; //*
    private int icmpType;
    private int icmpCode;
    //private long flowId;
    private String flowId;
    /**
     * Vytvorí prázdny objekt IP toku.
     */
    public IPFlow() {
        obsPoint = 0;
        fer = 0;
        sourceIP = "";
        destIP = "";
        sourcePort = 0;
        destPort = 0;
        octetCount = 0;
        packetCount = 0;
        startTimeMilis = 0;
        endTimeMilis = 0;
        protocol = 0;
        synCount = 0;
        rstCount = 0;
        ackCount = 0;   //* ack flood
        finCount = 0;
        //ttlCount = 0;
        icmpType = 0;
        icmpCode = 0;
        //flowId = 0;
        flowId = "";
    }

    /**
     * Vytvorí objekt toku s konkretnými hodnotami informačných elementov.
     * @param obsPoint pozorovací bod
     * @param fer príčina reportovania toku
     * @param sIP zdrojová IP adresa toku
     * @param dIP cieľová IP adresa toku
     * @param sPort zdrojový port toku
     * @param dPort cieľový port toku
     * @param octetCount počet oktetov toku
     * @param packetCount počet paketov toku
     * @param startTime začiatočný čas toku
     * @param endTime koncový čas toku
     * @param protocol protokol paketov v toku
     * @param synCount počet paketov so SYN príznakom v toku
     * @param rstCount počet paketov s RST príznakom v toku
     * @param ackCount počet paketov s ACK príznakom v toku
     * @param finCount počet paketov s FIN príznakom v toku
     * @param ttlCount počet paketov toku
     * @param icmpType typ ICMP paketu v toku
     * @param icmpCode kod ICMP paketu v toku
     * @param flowId identifikátor toku
     */
    public IPFlow(int obsPoint, int fer, String sIP, String dIP, int sPort, int dPort, double octetCount, long packetCount, long startTime, long endTime, int protocol, int synCount, int rstCount, int ackCount, int finCount, int icmpType, int icmpCode, String flowId) { //long flowId) {
        this.obsPoint = obsPoint;
        this.fer = fer;
        this.sourceIP = sIP;
        this.destIP = dIP;
        this.sourcePort = sPort;
        this.destPort = dPort;
        this.octetCount = octetCount;
        this.packetCount = packetCount;
        this.startTimeMilis = startTime;
        this.endTimeMilis = endTime;
        this.protocol = protocol;
        this.synCount = synCount;
        this.rstCount = rstCount;
        this.ackCount = ackCount;
        this.finCount = finCount;
        this.icmpType = icmpType;
        this.icmpCode = icmpCode;
        //this.ttlCount = packetCount;    // TTL expiry flood
        this.flowId = flowId;
    }

    public String getDestIP() {
        return destIP;
    }

    public void setDestIP(String destIP) {
        this.destIP = destIP;
    }

    public int getDestPort() {
        return destPort;
    }

    public void setDestPort(int destPort) {
        this.destPort = destPort;
    }

    public long getEndTimeMilis() {
        return endTimeMilis;
    }

    public void setEndTimeMilis(long endTimeMilis) {
        this.endTimeMilis = endTimeMilis;
    }

    public int getFer() {
        return fer;
    }

    public void setFer(int fer) {
        this.fer = fer;
    }

    public int getIcmpType() {
        return icmpType;
    }

    public void setIcmpType(int icmpType) {
        this.icmpType = icmpType;
    }
    
    public int getIcmpCode() {
        return icmpCode;
    }

    public void setIcmpCode(int icmpCode) { // pre utok TTL expiry flood
        this.icmpCode = icmpCode;
    }
   
    public int getObsPoint() {
        return obsPoint;
    }

    public void setObsPoint(int obsPoint) {
        this.obsPoint = obsPoint;
    }

    public double getOctetCount() {
        return octetCount;
    }

    public void setOctetCount(double octetCount) {
        this.octetCount = octetCount;
    }

    public long getPacketCount() {
        return packetCount;
    }

    public void setPacketCount(long packetCount) {
        this.packetCount = packetCount;
    }
    
    public long getTtlCount() {
        return packetCount;
    }
    
    public void setTtlCount(long ttlCount) {
        this.packetCount = ttlCount;
    }
    
    public int getProtocol() {
        return protocol;
    }

    public void setProtocol(int protocol) {
        this.protocol = protocol;
    }

    public int getRstCount() {
        return rstCount;
    }

    public void setRstCount(int rstCount) {
        this.rstCount = rstCount;
    }

    public int getAckCount() {
        return ackCount;
    }

    public void setAckCount(int ackCount) {
        this.ackCount = ackCount;
    }
    
    public int getFinCount() {
        return finCount;
    }

    public void setFinCount(int finCount) {
        this.finCount = finCount;
    }
    
    public String getSourceIP() {
        return sourceIP;
    }

    public void setSourceIP(String sourceIP) {
        this.sourceIP = sourceIP;
    }

    public int getSourcePort() {
        return sourcePort;
    }

    public void setSourcePort(int sourcePort) {
        this.sourcePort = sourcePort;
    }

    public long getStartTimeMilis() {
        return startTimeMilis;
    }

    public void setStartTimeMilis(long startTimeMilis) {
        this.startTimeMilis = startTimeMilis;
    }

    public int getSynCount() {
        return synCount;
    }

    public void setSynCount(int synCount) {
        this.synCount = synCount;
    }

//    public long getFlowId() {
//        return flowId;
//    }
    
    public String getFlowId() {
        return flowId;
    }

//    public void setFlowId(long flowId) {
//        this.flowId
//    }
    
    public void setFlowId(String flowId) {
        this.flowId = flowId;
    }
}
