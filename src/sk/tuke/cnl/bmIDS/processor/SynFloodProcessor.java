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
 *  Subor: SynFloodProcessor.java
 */
package sk.tuke.cnl.bmIDS.processor;

import java.util.LinkedList;
import sk.tuke.cnl.bmIDS.Config;
import sk.tuke.cnl.bmIDS.Constants;
import sk.tuke.cnl.bmIDS.IPFlow;
import sk.tuke.cnl.bmIDS.detector.SynFloodDetector;
import sk.tuke.cnl.bmIDS.traffic.SynFloodSignTraffic;

/**
 * Vlákno pre spracovanie tokov podľa charakteristík útoku typu SYN Flood.
 * @author Martin Ujlaky
 */
public class SynFloodProcessor extends TrafficProcessor {

    /** Aktuálny tok.*/
    private IPFlow currentIPFlow;
    /** Čas vyhodnotenia.*/
    private long evalTime = 0;
    /** Čas spracovavania tokov po vyhodnotenie.*/
    private long activeTimeout = 5000;
    /** Zoznam roztriedenej prevádzky podľa útoku typu SYN Flood.*/
    private LinkedList<SynFloodSignTraffic> synFSignTrafficList = new LinkedList<SynFloodSignTraffic>();
    /** Detektor útoku typu SYN Flood.*/
    private SynFloodDetector synFloodDetector;
    /** Zoznam aktívných tokov.*/
    private LinkedList<IPFlow> activeFlowList = new LinkedList<IPFlow>();
    /** Aktuálny mód programu.*/
    private int mode;
    /**Hranicny pocet syn priznakov ziskany zo standardnej prevadzky*/
    private int maxSynCount;

    /**
     * Konštruktor pre režim učenia.
     */
    public SynFloodProcessor() {
        mode = Constants.LEARN_MODE;
    }

    /**
     * Konštruktor pre režim detekcie.
     * @param detector 
     */
    public SynFloodProcessor(SynFloodDetector synFloodDetector) {
        super();
        this.synFloodDetector = synFloodDetector;
        mode = Constants.DETECTION_MODE;
        this.maxSynCount = Config.sfMaxSynCount / 3 * 5;
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
     * Spracováva prevádzku podľa charakteristík útoku typu SYN Flood.
     */
    private void processTraffic() {
        if (!super.isIPFlowFifoEmpty()) {
            currentIPFlow = super.popIPFlowFromFifo();

            if (currentIPFlow.getProtocol() != 6 || currentIPFlow.getSynCount() < 1) {
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
     * Klasifikuje IP toky podľa charakteristík útoku typu SYN Flood.
     */
    private void classifyTraffic() {
        boolean newIPFlow = true;
        boolean newActiveFlow = true;
        int synCount = 0;
        boolean attackBeforeEvalTime = false;

        //najprv sa urci, ci bol tok reportovany ako ukonceny alebo reportovany ako aktivny
        if (currentIPFlow.getFer() == 1) {
            for (IPFlow activeFlow : activeFlowList) {
                if (activeFlow.getFlowId() == currentIPFlow.getFlowId()) {
                    currentIPFlow.setSynCount(currentIPFlow.getSynCount() - activeFlow.getSynCount());
                    activeFlowList.remove(activeFlow);
                    break;
                }
            }
        } else if (currentIPFlow.getFer() == 2) {
            for (IPFlow activeFlow : activeFlowList) {
//                if (activeFlow.getFlowId() == currentIPFlow.getFlowId()) {
                if (activeFlow.getFlowId().equals(currentIPFlow.getFlowId())) {
                    int pom = currentIPFlow.getSynCount();
                    currentIPFlow.setSynCount(pom - activeFlow.getSynCount());
                    activeFlow.setSynCount(pom);
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
        for (SynFloodSignTraffic synFSignTraffic : synFSignTrafficList) {
//            if (synFSignTraffic.equals(currentIPFlow)) {
            if (synFSignTraffic.equals(currentIPFlow)) {
                synCount = synFSignTraffic.edit(currentIPFlow);
                if (synCount > maxSynCount) {
                    attackBeforeEvalTime = true;
                }
                //System.out.println(this + ": editujem");
                //System.out.println(this + ": po editacii synpacketcount=" + synFSignTraffic.getSynCount());
                newIPFlow = false;
                break;
            }
        }
        if (newIPFlow) {
           //System.out.println(this + ": pridavam");
           synFSignTrafficList.add(new SynFloodSignTraffic(currentIPFlow.getObsPoint(), currentIPFlow.getSourceIP(), currentIPFlow.getDestIP(), currentIPFlow.getDestPort(), currentIPFlow.getSynCount(), currentIPFlow.getEndTimeMilis(), activeTimeout));
        }
        //agresivne vyhodnocovanie - vtedy ked pocet paketov prekroci maximum, necaka na uplynutie timera
        if (mode == Constants.DETECTION_MODE && attackBeforeEvalTime == true && synFloodDetector.isWebClientConnected()) {
            evaluateTraffic(Constants.AGGRES_EVAL);
        }
    }

    /**
     * Spúšťa vyhodnocovanie zatriedenej prevádzky podľa charakteristík útoku typu SYN Flood.
     * @param reason dôvod vyhodnotenia
     */
    private void evaluateTraffic(int reason) {
        if (reason == Constants.NORMAL_EVAL) {
            //System.out.println(this + ": starting evaluation - time reason");
            super.addIPFlowBackToFifo(currentIPFlow);
            synFloodDetector.evaluate(synFSignTrafficList, reason);
            synFSignTrafficList.clear();
            evalTime = 0;
            //System.out.println(this + ": skoncil som evaluate");//*
        }
        if (reason == Constants.AGGRES_EVAL) {
            //System.out.println(this + ": evaluation - attack report reason");
            synFloodDetector.evaluate(synFSignTrafficList, reason);
            synFSignTrafficList.clear();
            evalTime = 0;
            //System.out.println(this + ": skoncil som agg evaluate");//*
        }
    }

    /**
     * Spracuje IP tok v režime učenia.
     * @param ipFlow IP tok z databázy v režime učenia
     * @return maximálny počet syn príznakov po vyhodnotení, resp. 0 ak prebehlo iba spracovanie 
     */
    public int learn(IPFlow ipFlow) {
        currentIPFlow = ipFlow;
        if (currentIPFlow.getProtocol() != 6 || currentIPFlow.getSynCount() < 1) {
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
            int synCount;
            int maxSynCount = 0;
            for (SynFloodSignTraffic synFSignTraffic : synFSignTrafficList) {
                synCount = synFSignTraffic.getSynCount();
                if (synCount > maxSynCount) {
                    maxSynCount = synCount;
                }
            }
            synFSignTrafficList.clear();
            evalTime = 0;
            return maxSynCount;
        }
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName();
    }
}
