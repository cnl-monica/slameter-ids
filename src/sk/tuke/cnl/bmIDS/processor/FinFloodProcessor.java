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
 *  Subor: FinFloodProcessor.java
 */
package sk.tuke.cnl.bmIDS.processor;

import java.util.LinkedList;
import sk.tuke.cnl.bmIDS.Config;
import sk.tuke.cnl.bmIDS.Constants;
import sk.tuke.cnl.bmIDS.IPFlow;
import sk.tuke.cnl.bmIDS.detector.FinFloodDetector;
import sk.tuke.cnl.bmIDS.traffic.FinFloodSignTraffic;

/**
 * Vlákno pre spracovanie tokov podľa charakteristík útoku typu FIN Flood.
 * @author Ladislav Berta
 */
public class FinFloodProcessor extends TrafficProcessor {

    /** Aktuálny tok.*/
    private IPFlow currentIPFlow;
    /** Čas vyhodnotenia.*/
    private long evalTime = 0;
    /** Čas spracovavania tokov po vyhodnotenie.*/
    private long activeTimeout = 5000;
    /** Zoznam roztriedenej prevádzky podľa útoku typu FIN Flood.*/
    private LinkedList<FinFloodSignTraffic> finFSignTrafficList = new LinkedList<FinFloodSignTraffic>();
    /** Detektor útoku typu FIN Flood.*/
    private FinFloodDetector finFloodDetector;
    /** Zoznam aktívných tokov.*/
    private LinkedList<IPFlow> activeFlowList = new LinkedList<IPFlow>();
    /** Aktuálny mód programu.*/
    private int mode;
    /**Hranicny pocet FIN priznakov ziskany zo standardnej prevadzky*/
    private int maxFinCount;

    /**
     * Konštruktor pre režim učenia.
     */
    public FinFloodProcessor() {
        mode = Constants.LEARN_MODE;
    }

    /**
     * Konštruktor pre režim detekcie.
     * @param detector 
     */
    public FinFloodProcessor(FinFloodDetector finFloodDetector) {
        super();
        this.finFloodDetector = finFloodDetector;
        mode = Constants.DETECTION_MODE;
        this.maxFinCount = Config.ffMaxFinCount / 3 * 5;
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
     * Spracováva prevádzku podľa charakteristík útoku typu FIN Flood.
     */
    private void processTraffic() {
        
//        if (finFloodDetector.isSLAWebClientConnected()){
//            System.out.println(this + ": SLA web applikacia je PRIPOJENA");
//            
//            System.out.println(this + ": posielam spravu (publish) pre SLA web...");
//            finFloodDetector.odosliPreSLA();
//            
//            try{ Thread.sleep(1000);} catch (InterruptedException ex) {}
//            System.out.println(this + ": poslal som spravu (publish) pre SLA web.");
//            
//            try{ Thread.sleep(1000);} catch (InterruptedException ex) {}
//            System.out.println(this + ": zastavujem finFloodProcessor.");
//            
//            this.interrupt();
//        } else {
//            try{ Thread.sleep(1000);} catch (InterruptedException ex) {}
//            System.out.println(this + ": SLA web aplikacia je ODPOJENA");
//        }
        
        if (!super.isIPFlowFifoEmpty()) {
            currentIPFlow = super.popIPFlowFromFifo();

            if (currentIPFlow.getProtocol() != 6 || currentIPFlow.getFinCount() < 1) {
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
     * Klasifikuje IP toky podľa charakteristík útoku typu FIN Flood.
     */
    private void classifyTraffic() {
        boolean newIPFlow = true;
        int finCount = 0;
        boolean attackBeforeEvalTime = false;

        //najprv sa urci, ci bol tok reportovany ako ukonceny (aktivne toky nas nezaujimaju)
        if (currentIPFlow.getFer() == 3) {
            for (IPFlow activeFlow : activeFlowList) {
                if (activeFlow.getFlowId() == currentIPFlow.getFlowId()) {
                    currentIPFlow.setFinCount(currentIPFlow.getFinCount() - activeFlow.getFinCount());
                    activeFlowList.remove(activeFlow);
                    break;
                }
            }
        } else {
            return;
        }

        //klasifikacia toku
        for (FinFloodSignTraffic finFSignTraffic : finFSignTrafficList) {
//            if (finFSignTraffic.equals(currentIPFlow)) {
            if (finFSignTraffic.equals(currentIPFlow)) {
                finCount = finFSignTraffic.edit(currentIPFlow);
                if (finCount > maxFinCount) {
                    attackBeforeEvalTime = true;
                }
                //System.out.println(this + ": editujem");
                //System.out.println(this + ": po editacii finpacketcount=" + finFSignTraffic.getFinCount());
                newIPFlow = false;
                break;
            }
        }

        if (newIPFlow) {
           //System.out.println(this + ": pridavam");
           finFSignTrafficList.add(new FinFloodSignTraffic(currentIPFlow.getObsPoint(), currentIPFlow.getSourceIP(), currentIPFlow.getDestIP(), currentIPFlow.getDestPort(), currentIPFlow.getFinCount(), currentIPFlow.getEndTimeMilis(), activeTimeout));
        }
        //agresivne vyhodnocovanie - vtedy ked pocet paketov prekroci maximum, necaka na uplynutie timera
        if (mode == Constants.DETECTION_MODE && attackBeforeEvalTime == true && finFloodDetector.isWebClientConnected()) {
            evaluateTraffic(Constants.AGGRES_EVAL);
        }
    }

    /**
     * Spúšťa vyhodnocovanie zatriedenej prevádzky podľa charakteristík útoku typu FIN Flood.
     * @param reason dôvod vyhodnotenia
     */
    private void evaluateTraffic(int reason) {
        if (reason == Constants.NORMAL_EVAL) {
            //System.out.println(this + ": starting evaluation - time reason");
            super.addIPFlowBackToFifo(currentIPFlow);
            finFloodDetector.evaluate(finFSignTrafficList, reason);
            finFSignTrafficList.clear();
            evalTime = 0;
            //System.out.println(this + ": skoncil som evaluate");//*
        }
        if (reason == Constants.AGGRES_EVAL) {
            //System.out.println(this + ": evaluation - attack report reason");
            finFloodDetector.evaluate(finFSignTrafficList, reason);
            finFSignTrafficList.clear();
            evalTime = 0;
            //System.out.println(this + ": skoncil som agg evaluate");//*
        }
    }

    /**
     * Spracuje IP tok v režime učenia.
     * @param ipFlow IP tok z databázy v režime učenia
     * @return maximálny počet FIN príznakov po vyhodnotení, resp. 0 ak prebehlo iba spracovanie 
     */
    public int learn(IPFlow ipFlow) {
        currentIPFlow = ipFlow;
        if (currentIPFlow.getProtocol() != 6 || currentIPFlow.getFinCount() < 1) {
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
            int finCount;
            int maxFinCount = 0;
            for (FinFloodSignTraffic finFSignTraffic : finFSignTrafficList) {
                finCount = finFSignTraffic.getFinCount();
                if (finCount > maxFinCount) {
                    maxFinCount = finCount;
                }
            }
            finFSignTrafficList.clear();
            evalTime = 0;
            return maxFinCount;
        }
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName();
    }
}
