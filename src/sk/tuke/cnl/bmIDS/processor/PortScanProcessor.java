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
 *  Subor: PortScanProcessor.java
 */
package sk.tuke.cnl.bmIDS.processor;

import java.util.LinkedList;
import sk.tuke.cnl.bmIDS.Config;
import sk.tuke.cnl.bmIDS.Constants;
import sk.tuke.cnl.bmIDS.IPFlow;
import sk.tuke.cnl.bmIDS.detector.PortScanDetector;
import sk.tuke.cnl.bmIDS.traffic.PortScanSignTraffic;

/**
 * Vlákno pre spracovanie tokov podľa charakteristík útoku typu Port Scan.
 * @author Martin Ujlaky
 */
public class PortScanProcessor extends TrafficProcessor {

    /** Aktuálny tok.*/
    private IPFlow currentIPFlow;
    /** Čas vyhodnotenia.*/
    private long evalTime = 0;
    /** Čas spracovavania tokov po vyhodnotenie.*/
    private long activeTimeout = 5000;
    /** Zoznam roztriedenej prevádzky podľa útoku typu PortScan.*/
    private LinkedList<PortScanSignTraffic> psSignTrafficList = new LinkedList<PortScanSignTraffic>();
    /** Detektor útoku typu Port Scan.*/
    private PortScanDetector psDetector;
    /** Aktuálny mód programu.*/
    private int mode;
    /** Hranicny pocet tokov ziskany zo standardnej prevadzky*/
    private int maxFlowCount;

    /**
     * Konštruktor pre režim učenia.
     */
    public PortScanProcessor() {
        mode = Constants.LEARN_MODE;
    }

    /**
     * Konštruktor pre režim detekcie.
     * @param detector 
     */
    public PortScanProcessor(PortScanDetector detector) {
        super();
        this.psDetector = detector;
        //System.out.println("Som tu 002.");
        mode = Constants.DETECTION_MODE;
        this.maxFlowCount = Config.psMaxFlowCount / 3 * 5;  
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

    /**
     * Spracováva prevádzku podľa charakteristík útoku typu Port Scan.
     */
    private void processTraffic() {
        if (!super.isIPFlowFifoEmpty()) {
            currentIPFlow = super.popIPFlowFromFifo();
            if (currentIPFlow.getProtocol() != 6) {
                return;
            }
            if (evalTime == 0) {    // iba prvy krat sa spusti, a nastavi cas do ktoreho sa bude vyhodnocovat
                evalTime = currentIPFlow.getEndTimeMilis() + activeTimeout;
            } 
            if (currentIPFlow.getEndTimeMilis() < evalTime) {   // vsetky toky sa klasifikuju a zatrieduju pokial sa neprekroci cas ktory sme prvy krat nastavili
                classifyTraffic();
            } else {                                            // inak sa zacne s vyhodnocovanim
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
     * Klasifikuje IP toky podľa charakteristík útoku typu Port Scan.
     */
    private void classifyTraffic() {
        boolean newIPFlow = true;
        int flowCount = 0;
        boolean attackBeforeEvalTime = false;
        if (currentIPFlow.getFer() == 1) {
            if (currentIPFlow.getSynCount() > 0) {
                for (PortScanSignTraffic psSignTraffic : psSignTrafficList) {
                    if (psSignTraffic.equals(currentIPFlow)) {
                        flowCount = psSignTraffic.edit(currentIPFlow);
                        if (flowCount > maxFlowCount) {
                            attackBeforeEvalTime = true;
                        }
                        //System.out.println(this + ": editujem");
                        //System.out.println(this + ": po editacii packetcount=" + psSignTraffic.getPacketCount());
                        newIPFlow = false;
                        break;
                    }
                }
                if (newIPFlow) {
                    //System.out.println(this + ": pridavam");
                    psSignTrafficList.add(new PortScanSignTraffic(currentIPFlow.getObsPoint(), currentIPFlow.getSourceIP(), currentIPFlow.getDestIP(), currentIPFlow.getDestPort(), currentIPFlow.getEndTimeMilis(), activeTimeout));
                }
                //agresivne vyhodnocovanie - vtedy ked pocet paketov prekroci maximum, necaka na uplynutie timera
                if (mode == Constants.DETECTION_MODE && attackBeforeEvalTime == true && psDetector.isWebClientConnected()) {
                    evaluateTraffic(Constants.AGGRES_EVAL);
                }
            }
        }
    }

    /**
     * Spúšťa vyhodnocovanie zatriedenej prevádzky podľa charakteristík útoku typu Port Scan.
     * @param reason dôvod vyhodnotenia
     */
    private void evaluateTraffic(int reason) {
        if (reason == Constants.NORMAL_EVAL) {//time expired
            //System.out.println(this + ": starting evaluation - time reason");
            if (!psSignTrafficList.isEmpty()) {
                psDetector.evaluate(psSignTrafficList, reason);
            } else {
                psDetector.evaluateEmpty(currentIPFlow.getEndTimeMilis());
            }
            super.addIPFlowBackToFifo(currentIPFlow);
            psSignTrafficList.clear();
            evalTime = 0;   // tu sa vynuluje cas, aby sa mohol znova nastavit
            //System.out.println(this + ": skoncil som evaluate");
        }
        if (reason == Constants.AGGRES_EVAL) {//attack report
            //System.out.println(this + ": evaluation - attack report reason");
            psDetector.evaluate(psSignTrafficList, reason);
            psSignTrafficList.clear();
            evalTime = 0;
            //System.out.println(this + ": skoncil som evaluate");
        }
    }

    /**
     * Spracuje IP tok v režime učenia.
     * @param ipFlow IP tok z databázy v režime učenia
     * @return maximálny počet tokov po vyhodnotení, resp. 0 ak prebehlo iba spracovanie 
     */
    public int learn(IPFlow ipFlow) {
        currentIPFlow = ipFlow;
        if (currentIPFlow.getProtocol() != 6) {
            return 0;
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
            int flowCount;
            //maxPacketCount pre rezim ucenia - ine ako maxPacketCount pre rezim detekcie
            int maxFlowCount = 0;
            for (PortScanSignTraffic psSignTraffic : psSignTrafficList) {
                flowCount = psSignTraffic.getFlowCount();
                if (flowCount > maxFlowCount) {
                    maxFlowCount = flowCount;
                }
            }
            psSignTrafficList.clear();
            evalTime = 0;
            return maxFlowCount;
        }
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName();
    }
}
