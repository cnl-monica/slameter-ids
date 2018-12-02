///*  Copyright © 2013 MONICA Research Group / TUKE.
// *  This file is part of bmIDSanalyzer.
// *  bmIDSanylyzer is free software: you can redistribute it and/or modify
// *  it under the terms of the GNU General Public License as published by
// *  the Free Software Foundation, either version 3 of the License, or
// *  (at your option) any later version.
// *
// *  bmIDSanalyzer is distributed in the hope that it will be useful,
// *  but WITHOUT ANY WARRANTY; without even the implied warranty of
// *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// *  GNU General Public License for more details.
// *
// *  You should have received a copy of the GNU General Public License
// *  along with bmIDSanalyzer.  If not, see <http://www.gnu.org/licenses/>.
// *
// *             Fakulta Elektrotechniky a informatiky
// *               Technicka univerzita v Kosiciach
// *
// *              Systemy pre detekciu narusenia sieti
// *                      Bakalarska praca
// *
// *  Veduci BP:        Ing. Miroslav Biňas, PhD.
// *  Konzultant BP:    Ing. Adrián Pekár
// *
// *  Autor:            Ladislav Berta
// *
// *  Zdrojove texty:
// *  Subor: AckFloodProcessor.java
// */
//package sk.tuke.cnl.bmIDS.processor;
//
//import java.util.LinkedList;
//import sk.tuke.cnl.bmIDS.Config;
//import sk.tuke.cnl.bmIDS.Constants;
//import sk.tuke.cnl.bmIDS.IPFlow;
//import sk.tuke.cnl.bmIDS.detector.AckFloodDetector;
//import sk.tuke.cnl.bmIDS.traffic.AckFloodSignTraffic;
//
///**
// * Vlákno pre spracovanie tokov podľa charakteristík útoku typu ACK Flood.
// * @author Ladislav Berta
// */
//public class AckFloodProcessor extends TrafficProcessor {
//
//    /** Aktuálny tok.*/
//    private IPFlow currentIPFlow;
//    /** Čas vyhodnotenia.*/
//    private long evalTime = 0;
//    /** Čas spracovavania tokov po vyhodnotenie.*/
//    private long activeTimeout = 6000;
//    /** Zoznam roztriedenej prevádzky podľa útoku typu Ack Flood.*/
//    private LinkedList<AckFloodSignTraffic> ackFSignTrafficList = new LinkedList<AckFloodSignTraffic>();
//    /** Detektor útoku typu ACK Flood.*/
//    private AckFloodDetector ackFloodDetector;
//    /** Zoznam aktívných tokov.*/
//    private LinkedList<IPFlow> activeFlowList = new LinkedList<IPFlow>();
//    /** Aktuálny mód programu.*/
//    private int mode;
//    /**Hranicny pocet ack priznakov ziskany zo standardnej prevadzky*/
//    private int maxAckCount;
//
//    /**
//     * Konštruktor pre režim učenia.
//     */
//    public AckFloodProcessor() {
//        mode = Constants.LEARN_MODE;
//    }
//
//    /**
//     * Konštruktor pre režim detekcie.
//     * @param detector 
//     */
//    public AckFloodProcessor(AckFloodDetector ackFloodDetector) {
//        super();
//        this.ackFloodDetector = ackFloodDetector;
//        mode = Constants.DETECTION_MODE;
//        this.maxAckCount = Config.afMaxAckCount / 3 * 5;
//    }
//
//    /**
//     * Spusti prijímanie a spracovanie tokov.
//     */
//    @Override
//    public void run() {
//        System.out.println(this + ": ready to accept IPFlow informations.");
//        while (!isInterrupted()) {
//            processTraffic();
//        }
//    }
//
//    /**
//     * Spracováva prevádzku podľa charakteristík útoku typu ACK Flood.
//     */
//    private void processTraffic() {
//        if (!super.isIPFlowFifoEmpty()) {
//            currentIPFlow = super.popIPFlowFromFifo();
//
//            if (currentIPFlow.getProtocol() != 6 || currentIPFlow.getAckCount() < 1) {
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
//
//    /**
//     * Klasifikuje IP toky podľa charakteristík útoku typu ACK Flood.
//     */
//    private void classifyTraffic() {
//        boolean newIPFlow = true;
//        boolean newActiveFlow = true;
//        int ackCount = 0;
//        boolean attackBeforeEvalTime = false;
//
//        //najprv sa urci, ci bol tok reportovany ako ukonceny alebo reportovany ako aktivny
//        if (currentIPFlow.getFer() == 1) {
//            for (IPFlow activeFlow : activeFlowList) {
//                if (activeFlow.getFlowId() == currentIPFlow.getFlowId()) {
//                    currentIPFlow.setAckCount(currentIPFlow.getAckCount() - activeFlow.getAckCount());
//                    activeFlowList.remove(activeFlow);
//                    break;
//                }
//            }
//        } else if (currentIPFlow.getFer() == 2) {
//            for (IPFlow activeFlow : activeFlowList) {
////***                if (activeFlow.getFlowId() == currentIPFlow.getFlowId()) {
//                if (activeFlow.getFlowId().equals(currentIPFlow.getFlowId())) {
//                    int pom = currentIPFlow.getAckCount();
//                    currentIPFlow.setAckCount(pom - activeFlow.getAckCount());
//                    activeFlow.setAckCount(pom);
//                    newActiveFlow = false;
//                    break;
//                }
//            }
//            if (newActiveFlow) {
//                activeFlowList.add(currentIPFlow);
//            }
//        } else {
//            return;
//        }
//
//        //klasifikacia toku
//        for (AckFloodSignTraffic ackFSignTraffic : ackFSignTrafficList) {
////            if (ackFSignTraffic.equals(currentIPFlow)) {
//            if (ackFSignTraffic.equals(currentIPFlow)) {
//                ackCount = ackFSignTraffic.edit(currentIPFlow);
//                if (ackCount > maxAckCount) {
//                    attackBeforeEvalTime = true;
//                }
//                //System.out.println(this + ": editujem");
//                //System.out.println(this + ": po editacii ackpacketcount=" + ackFSignTraffic.getAckCount());
//                newIPFlow = false;
//                break;
//            }
//        }
//        if (newIPFlow) {
//           //System.out.println(this + ": pridavam");
//           ackFSignTrafficList.add(new AckFloodSignTraffic(currentIPFlow.getObsPoint(), currentIPFlow.getSourceIP(), currentIPFlow.getDestIP(), currentIPFlow.getDestPort(), currentIPFlow.getAckCount(), currentIPFlow.getEndTimeMilis(), activeTimeout));
//        }
//        //agresivne vyhodnocovanie - vtedy ked pocet paketov prekroci maximum, necaka na uplynutie timera
//        if (mode == Constants.DETECTION_MODE && attackBeforeEvalTime == true && ackFloodDetector.isWebClientConnected()) {
//            evaluateTraffic(Constants.AGGRES_EVAL);
//        }
//    }
//
//    /**
//     * Spúšťa vyhodnocovanie zatriedenej prevádzky podľa charakteristík útoku typu ACK Flood.
//     * @param reason dôvod vyhodnotenia
//     */
//    private void evaluateTraffic(int reason) {
//        if (reason == Constants.NORMAL_EVAL) {
//            //System.out.println(this + ": starting evaluation - time reason");
//            super.addIPFlowBackToFifo(currentIPFlow);
//            ackFloodDetector.evaluate(ackFSignTrafficList, reason);
//            ackFSignTrafficList.clear();
//            evalTime = 0;
//            //System.out.println(this + ": skoncil som evaluate");//*
//        }
//        if (reason == Constants.AGGRES_EVAL) {
//            //System.out.println(this + ": evaluation - attack report reason");
//            ackFloodDetector.evaluate(ackFSignTrafficList, reason);
//            ackFSignTrafficList.clear();
//            evalTime = 0;
//            //System.out.println(this + ": skoncil som agg evaluate");//*
//        }
//    }
//
//    /**
//     * Spracuje IP tok v režime učenia.
//     * @param ipFlow IP tok z databázy v režime učenia
//     * @return maximálny počet ack príznakov po vyhodnotení, resp. 0 ak prebehlo iba spracovanie 
//     */
//    public int learn(IPFlow ipFlow) {
//        currentIPFlow = ipFlow;
//        if (currentIPFlow.getProtocol() != 6 || currentIPFlow.getAckCount() < 1) {
//            return 0;
//        }
//        if (evalTime == 0) {
//            evalTime = currentIPFlow.getEndTimeMilis() + activeTimeout;
//        }
//        if (currentIPFlow.getEndTimeMilis() < evalTime) {
//            classifyTraffic();
//            return 0;
//        } else {
//            //evaluate traffic   
//            int ackCount;
//            int maxAckCount = 0;
//            for (AckFloodSignTraffic ackFSignTraffic : ackFSignTrafficList) {
//                ackCount = ackFSignTraffic.getAckCount();
//                if (ackCount > maxAckCount) {
//                    maxAckCount = ackCount;
//                }
//            }
//            ackFSignTrafficList.clear();
//            evalTime = 0;
//            return maxAckCount;
//        }
//    }
//
//    @Override
//    public String toString() {
//        return this.getClass().getSimpleName();
//    }
//}
//
