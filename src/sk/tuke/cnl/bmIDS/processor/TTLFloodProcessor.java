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
 *  Subor: TTLFloodProcessor.java
 */
package sk.tuke.cnl.bmIDS.processor;

import java.util.LinkedList;
import sk.tuke.cnl.bmIDS.Config;
import sk.tuke.cnl.bmIDS.Constants;
import sk.tuke.cnl.bmIDS.IPFlow;
import sk.tuke.cnl.bmIDS.detector.TTLFloodDetector;
import sk.tuke.cnl.bmIDS.traffic.TTLFloodSignTraffic;

/**
 * Vlákno pre spracovanie tokov podľa charakteristík útoku typu TTL expiry Flood.
 * @author Ladislav Berta
 */
public class TTLFloodProcessor extends TrafficProcessor {

    /** Aktuálny tok.*/
    private IPFlow currentIPFlow;
    /** Čas vyhodnotenia.*/
    private long evalTime = 0;
    /** Čas spracovavania tokov po vyhodnotenie.*/
    private long activeTimeout = 5000;
    /** Zoznam roztriedenej prevádzky podľa útoku typu TTL expiry Flood.*/
    private LinkedList<TTLFloodSignTraffic> ttlFSignTrafficList = new LinkedList<TTLFloodSignTraffic>();
    /** Zoznam aktívných tokov.*/
    private LinkedList<IPFlow> activeFlowList = new LinkedList<IPFlow>();
    /** Detektor útoku typu TTL expiry Flood.*/
    private TTLFloodDetector ttlFloodDetector;
    /** Aktuálny mód programu.*/
    private int mode;
    /**Hranicny pocet ICMP paketov (typ=11, kod=0) ziskany zo standardnej prevadzky*/
    private long maxTtlCount;

    /**
     * Konštruktor pre režim učenia.
     */
    public TTLFloodProcessor() {
        this.mode = Constants.LEARN_MODE;
    }

    /**
     * Konštruktor pre režim detekcie.
     * @param detector 
     */
    public TTLFloodProcessor(TTLFloodDetector ttlFloodDetector) {
        super();
        this.ttlFloodDetector = ttlFloodDetector;
        this.mode = Constants.DETECTION_MODE;
        this.maxTtlCount = Config.tfMaxTtlCount / 3 * 5;
    }

    /**
     * Spusti prijímanie a spracovanie tokov.
     */
    @Override
    public void run() {
        System.out.println(this + ": ready to accept IPFlow informations.");
        while (!isInterrupted()) {
            processTraffic();
        }
    }

//    /**
//     * Spracováva prevádzku podľa charakteristík útoku typu TTL expiry Flood.
//     */
//        private void processTraffic() {
//        if (!super.isIPFlowFifoEmpty()) {
//            currentIPFlow = super.popIPFlowFromFifo();
//
//            if (currentIPFlow.getProtocol() != 1 || currentIPFlow.getIcmpType() != 11 || currentIPFlow.getIcmpCode() != 0) {
//                return;
//            }
//            if (evalTime == 0) {
//                evalTime = currentIPFlow.getEndTimeMilis() + activeTimeout;
//            }
//            if (currentIPFlow.getEndTimeMilis() < evalTime) {
//                classifyTraffic();
//            } else {
//                evaluateTraffic(Constants.NORMAL_EVAL);
//            }
//        } else {
//            try {
//                //System.out.println(this + ": cakam, prazdne fifo");
//                Thread.sleep(50);
//            } catch (InterruptedException ex) {
//                interrupt();
//            }
//        }
//    }
    
        /**
     * Spracováva prevádzku podľa charakteristík útoku typu TTL expiry Flood.
     */
        private void processTraffic() {
        if (!super.isIPFlowFifoEmpty()) {
            currentIPFlow = super.popIPFlowFromFifo();

            if (currentIPFlow.getProtocol() != 1 || currentIPFlow.getIcmpType() != 11 || currentIPFlow.getIcmpCode() != 0) {
                return;
            }
            if (currentIPFlow.getFer() != 1) {
                if (currentIPFlow.getFer() == 2) {
                    if (activeFlowList.size() < 10) {
                        activeFlowList.add(currentIPFlow);
                    } else {
                        activeFlowList.removeFirst();
                        activeFlowList.add(currentIPFlow);
                    }
                }
                //return;
            }
//            System.out.println(this + "Pred nastavenim casu.");
            if (evalTime == 0) {
//                System.out.println(this + "Nastavujem cas.");
                evalTime = currentIPFlow.getEndTimeMilis() + activeTimeout;
            }
            if (currentIPFlow.getEndTimeMilis() < evalTime) {
//                System.out.println(this + "classify trafic.");
                classifyTraffic();
            } else {
//                System.out.println(this + "EVALUATE trafic.");
                evaluateTraffic(Constants.NORMAL_EVAL);
            }
        } else {
            try {
                //System.out.println(this + ": cakam, prazdne fifo");
                Thread.sleep(50);
            } catch (InterruptedException ex) {
                interrupt();
            }
        }
    }

    /**
     * Klasifikuje IP toky podľa charakteristík útoku typu TTL expiry Flood.
     */
    private void classifyTraffic() {
        boolean newIPFlow = true;
        long ttlCount = 0;
        boolean attackBeforeEvalTime = false;

        //ak ide o tok, ktory uz bol aj skor reportovany, ten je potom dlhotrvajuci a to nas nezaujima
        if (currentIPFlow.getFer() == 1) {
            for (IPFlow activeFlow : activeFlowList) {
//                if (activeFlow.getFlowId() == currentIPFlow.getFlowId()) {
                
//                System.out.println("--------------------------------");
//                System.out.println(activeFlow.getFlowId());
//                System.out.println(currentIPFlow.getFlowId());
//                System.out.println("--------------------------------");
                
                if (activeFlow.getFlowId().equals(currentIPFlow.getFlowId())) {
                    activeFlowList.remove(activeFlow);
                    return;
                }
            }
        }

        for (TTLFloodSignTraffic ttlFSignTraffic : ttlFSignTrafficList) {
            if (ttlFSignTraffic.equals(currentIPFlow)) {
                ttlCount = ttlFSignTraffic.edit(currentIPFlow);
                if (ttlCount > maxTtlCount) {
                    attackBeforeEvalTime = true;
                }
//                System.out.println(this + ": editujem");
//                System.out.println(this + ": po editacii packetcount=" + ttlFSignTraffic.getTtlCount());
                newIPFlow = false;
                break;
            }
        }
        if (newIPFlow) {
            //System.out.println(this + ": pridavam");//*
            ttlFSignTrafficList.add(new TTLFloodSignTraffic(currentIPFlow.getObsPoint(), currentIPFlow.getSourceIP(), currentIPFlow.getDestIP(), currentIPFlow.getDestPort(), currentIPFlow.getTtlCount(), currentIPFlow.getEndTimeMilis(), activeTimeout));
        }
        //agresivne vyhodnocovanie - vtedy ked pocet paketov prekroci maximum, necaka na uplynutie timera
        if (mode == Constants.DETECTION_MODE && attackBeforeEvalTime == true && ttlFloodDetector.isWebClientConnected()) {
            evaluateTraffic(Constants.AGGRES_EVAL);//z akeho dovodu
        }
    }

    /**
     * Spúšťa vyhodnocovanie zatriedenej prevádzky podľa charakteristík útoku typu TTL expiry Flood.
     * @param reason dôvod vyhodnotenia
     */
    private void evaluateTraffic(int reason) {
        //System.out.println(this + "evaluate traffic.");
        if (reason == Constants.NORMAL_EVAL) {//time expired
            //System.out.println(this + ": starting evaluation - time reason");
            super.addIPFlowBackToFifo(currentIPFlow);
            ttlFloodDetector.evaluate(ttlFSignTrafficList, reason);
            ttlFSignTrafficList.clear();
            evalTime = 0;
            //System.out.println(this + ": skoncil som evaluate");//*
        }
        if (reason == Constants.AGGRES_EVAL) {//attack report
            //System.out.println(this + ": evaluation - attack report reason");
            ttlFloodDetector.evaluate(ttlFSignTrafficList, reason);
            ttlFSignTrafficList.clear();
            evalTime = 0;
            //System.out.println(this + ": skoncil som evaluate");//*
        }
    }

//    /**
//     * Spracuje IP tok v režime učenia.
//     * @param ipFlow IP tok z databázy v režime učenia
//     * @return maximálny počet ICMP paketov (typ=11, kod=0) po vyhodnotení, resp. 0 ak prebehlo iba spracovanie 
//     */
//    public long learn(IPFlow ipFlow) {
//        currentIPFlow = ipFlow;
//        if (currentIPFlow.getProtocol() != 1 || currentIPFlow.getIcmpType() != 11 || currentIPFlow.getIcmpCode() != 0) {
//            return 0;
//        }
//        if (evalTime == 0) {
//            evalTime = currentIPFlow.getEndTimeMilis() + activeTimeout;
//        }
//        if (currentIPFlow.getEndTimeMilis() < evalTime) {
//            //classify traffic
//            classifyTraffic();
//            return 0;
//        } else {
//            //evaluate traffic   
//            long ttlCount;
//            //maxPacketCount pre rezim ucenia - ine ako maxPacketCount pre rezim detekcie
//            long maxPacketCount = 0;
//            for (TTLFloodSignTraffic ttlFSignTraffic : ttlFSignTrafficList) {
//                ttlCount = ttlFSignTraffic.getTtlCount();
//                if (ttlCount > maxTtlCount) {
//                    maxPacketCount = ttlCount;
//                }
//            }
//            ttlFSignTrafficList.clear();
//            evalTime = 0;
//            return maxPacketCount;
//        }
//    }
    
    /**
     * Spracuje IP tok v režime učenia.
     * @param ipFlow IP tok z databázy v režime učenia
     * @return maximálny počet ICMP paketov (typ=11, kod=0) po vyhodnotení, resp. 0 ak prebehlo iba spracovanie 
     */
    public long learn(IPFlow ipFlow) {
        currentIPFlow = ipFlow;
        if (currentIPFlow.getProtocol() != 1 || currentIPFlow.getIcmpType() != 11 || currentIPFlow.getIcmpCode() != 0) {
            return 0;
        }
        if (currentIPFlow.getFer() != 1) {
            if (currentIPFlow.getFer() == 2) {
                if (activeFlowList.size() < 10) {
                    activeFlowList.add(currentIPFlow);
                } else {
                    activeFlowList.removeFirst();
                    activeFlowList.add(currentIPFlow);
                }
            }
            //return 0;
        }
        if (evalTime == 0) {
            evalTime = currentIPFlow.getEndTimeMilis() + activeTimeout;
        }
        if (currentIPFlow.getEndTimeMilis() < evalTime) {
            //classify traffic
            classifyTraffic();
            return 0;
        } else {
            //evaluate traffic   
            long ttlCount;
            //maxPacketCount pre rezim ucenia - ine ako maxPacketCount pre rezim detekcie
            long maxPacketCount = 0;
            for (TTLFloodSignTraffic ttlFSignTraffic : ttlFSignTrafficList) {
                ttlCount = ttlFSignTraffic.getTtlCount();
                if (ttlCount > maxTtlCount) {
                    maxPacketCount = ttlCount;
                }
            }
            ttlFSignTrafficList.clear();
            evalTime = 0;
            return maxPacketCount;
        }
    }
    
    @Override
    public String toString() {
        return this.getClass().getSimpleName();
    }
}
