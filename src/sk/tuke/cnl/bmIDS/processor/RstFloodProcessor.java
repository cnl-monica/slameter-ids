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
 *  Subor: RstFloodProcessor.java
 */
package sk.tuke.cnl.bmIDS.processor;

import java.util.LinkedList;
import sk.tuke.cnl.bmIDS.Config;
import sk.tuke.cnl.bmIDS.Constants;
import sk.tuke.cnl.bmIDS.IPFlow;
import sk.tuke.cnl.bmIDS.detector.RstFloodDetector;
import sk.tuke.cnl.bmIDS.traffic.RstFloodSignTraffic;

/**
 * Vlákno pre spracovanie tokov podľa charakteristík útoku typu RST Flood.
 * @author Ladislav Berta
 */
public class RstFloodProcessor extends TrafficProcessor {

    /** Aktuálny tok.*/
    private IPFlow currentIPFlow;
    /** Čas vyhodnotenia.*/
    private long evalTime = 0;
    /** Čas spracovavania tokov po vyhodnotenie.*/
    private long activeTimeout = 5000;
    /** Zoznam roztriedenej prevádzky podľa útoku typu RST Flood.*/
    private LinkedList<RstFloodSignTraffic> rstFSignTrafficList = new LinkedList<RstFloodSignTraffic>();
    /** Detektor útoku typu RST Flood.*/
    private RstFloodDetector rstFloodDetector;
    /** Zoznam aktívných tokov.*/
    private LinkedList<IPFlow> activeFlowList = new LinkedList<IPFlow>();
    /** Aktuálny mód programu.*/
    private int mode;
    /**Hranicny pocet RST priznakov ziskany zo standardnej prevadzky*/
    private int maxRstCount;

    /**
     * Konštruktor pre režim učenia.
     */
    public RstFloodProcessor() {
        mode = Constants.LEARN_MODE;
    }

    /**
     * Konštruktor pre režim detekcie.
     * @param detector 
     */
    public RstFloodProcessor(RstFloodDetector rstFloodDetector) {
        super();
        this.rstFloodDetector = rstFloodDetector;
        mode = Constants.DETECTION_MODE;
        this.maxRstCount = Config.rfMaxRstCount / 3 * 5;
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
     * Spracováva prevádzku podľa charakteristík útoku typu RST Flood.
     */
    private void processTraffic() {
        if (!super.isIPFlowFifoEmpty()) {
            currentIPFlow = super.popIPFlowFromFifo();

            if (currentIPFlow.getProtocol() != 6 || currentIPFlow.getRstCount() < 1) {
                return;
            }
            if (evalTime == 0) {
                evalTime = currentIPFlow.getEndTimeMilis() + activeTimeout;
            }
            if (currentIPFlow.getEndTimeMilis() < evalTime) {
                classifyTraffic();
            } else {
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
     * Klasifikuje IP toky podľa charakteristík útoku typu RST Flood.
     */
    private void classifyTraffic() {
        boolean newIPFlow = true;
        boolean newActiveFlow = true;
        int rstCount = 0;
        boolean attackBeforeEvalTime = false;

        //najprv sa urci, ci bol tok reportovany ako ukonceny alebo reportovany ako aktivny
        if (currentIPFlow.getFer() == 1) {
            for (IPFlow activeFlow : activeFlowList) {
                if (activeFlow.getFlowId() == currentIPFlow.getFlowId()) {
                    currentIPFlow.setRstCount(currentIPFlow.getRstCount() - activeFlow.getRstCount());
                    activeFlowList.remove(activeFlow);
                    break;
                }
            }
        } else if (currentIPFlow.getFer() == 2) {
            for (IPFlow activeFlow : activeFlowList) {
//                if (activeFlow.getFlowId() == currentIPFlow.getFlowId()) {
                if (activeFlow.getFlowId().equals(currentIPFlow.getFlowId())) {
                    int pom = currentIPFlow.getRstCount();
                    currentIPFlow.setRstCount(pom - activeFlow.getRstCount());
                    activeFlow.setRstCount(pom);
                    newActiveFlow = false;
                    break;
                }
            }
            if (newActiveFlow) {
                activeFlowList.add(currentIPFlow);
            }
        } else {
            return;
        }

        //klasifikacia toku
        for (RstFloodSignTraffic rstFSignTraffic : rstFSignTrafficList) {
//            if (rstFSignTraffic.equals(currentIPFlow)) {
            if (rstFSignTraffic.equals(currentIPFlow)) {
                rstCount = rstFSignTraffic.edit(currentIPFlow);
                if (rstCount > maxRstCount) {
                    attackBeforeEvalTime = true;
                }
                //System.out.println(this + ": editujem");
                //System.out.println(this + ": po editacii rstpacketcount=" + rstFSignTraffic.getRstCount());
                newIPFlow = false;
                break;
            }
        }
        if (newIPFlow) {
           //System.out.println(this + ": pridavam");
           rstFSignTrafficList.add(new RstFloodSignTraffic(currentIPFlow.getObsPoint(), currentIPFlow.getSourceIP(), currentIPFlow.getDestIP(), currentIPFlow.getDestPort(), currentIPFlow.getRstCount(), currentIPFlow.getEndTimeMilis(), activeTimeout));
        }
        //agresivne vyhodnocovanie - vtedy ked pocet paketov prekroci maximum, necaka na uplynutie timera
        if (mode == Constants.DETECTION_MODE && attackBeforeEvalTime == true && rstFloodDetector.isWebClientConnected()) {
            evaluateTraffic(Constants.AGGRES_EVAL);
        }
    }

    /**
     * Spúšťa vyhodnocovanie zatriedenej prevádzky podľa charakteristík útoku typu RST Flood.
     * @param reason dôvod vyhodnotenia
     */
    private void evaluateTraffic(int reason) {
        if (reason == Constants.NORMAL_EVAL) {
            //System.out.println(this + ": starting evaluation - time reason");
            super.addIPFlowBackToFifo(currentIPFlow);
            rstFloodDetector.evaluate(rstFSignTrafficList, reason);
            rstFSignTrafficList.clear();
            evalTime = 0;
            //System.out.println(this + ": skoncil som evaluate");//*
        }
        if (reason == Constants.AGGRES_EVAL) {
            //System.out.println(this + ": evaluation - attack report reason");
            rstFloodDetector.evaluate(rstFSignTrafficList, reason);
            rstFSignTrafficList.clear();
            evalTime = 0;
            //System.out.println(this + ": skoncil som agg evaluate");//*
        }
    }

    /**
     * Spracuje IP tok v režime učenia.
     * @param ipFlow IP tok z databázy v režime učenia
     * @return maximálny počet RST príznakov po vyhodnotení, resp. 0 ak prebehlo iba spracovanie 
     */
    public int learn(IPFlow ipFlow) {
        currentIPFlow = ipFlow;
        if (currentIPFlow.getProtocol() != 6 || currentIPFlow.getRstCount() < 1) {
            return 0;
        }
        if (evalTime == 0) {
            evalTime = currentIPFlow.getEndTimeMilis() + activeTimeout;
        }
        if (currentIPFlow.getEndTimeMilis() < evalTime) {
            classifyTraffic();
            return 0;
        } else {
            //evaluate traffic   
            int rstCount;
            int maxRstCount = 0;
            for (RstFloodSignTraffic rstFSignTraffic : rstFSignTrafficList) {
                rstCount = rstFSignTraffic.getRstCount();
                if (rstCount > maxRstCount) {
                    maxRstCount = rstCount;
                }
            }
            rstFSignTrafficList.clear();
            evalTime = 0;
            return maxRstCount;
        }
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName();
    }
}
