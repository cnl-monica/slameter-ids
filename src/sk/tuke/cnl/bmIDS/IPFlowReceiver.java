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
 *  Subor: IPFlowReceiver.java
 */
package sk.tuke.cnl.bmIDS;

import sk.tuke.cnl.bmIDS.processor.TrafficProcessor;
import java.io.IOException;
import java.util.ArrayList;
import sk.tuke.cnl.bm.ACPIPFIXTemplate;
import sk.tuke.cnl.bm.ACPapi.ACP;
import sk.tuke.cnl.bm.ACPapi.ACPException;
import sk.tuke.cnl.bm.Filter;
import sk.tuke.cnl.bm.InvalidFilterRuleException;

/**
 * Vlákno, ktorá zabezpečuje príjem informačných elementov od kolektora a poskytuje ich jednotlivým procesorom.
 * @author Martin Ujlaky
 */
public class IPFlowReceiver extends Thread {

    /** ACP rozhranie zabezpečujúce komunikáciu s kolektorom.*/
    private static ACP acp;
    /** Zoznam procesorov pre spracovanie tokov.*/
    private static ArrayList<TrafficProcessor> processorList;

    /**
     * Konštruktor pre nastavenie atribútov.
     * @param acp ACP rozhranie zabezpečujúce komunikáciu s kolektorom
     * @param processorList zoznam procesorov pre spracovanie tokov
     */
    public IPFlowReceiver(ACP acp, ArrayList<TrafficProcessor> processorList) {
        this.acp = acp;
        this.processorList = processorList;
    }

    /**
     * Testuje, či nie je buffer niektorého procesora plný.
     * @return true, ak je buffer niektorého procesora plná, inak false
     */
    private boolean isTrafficProcessorBufferFull() {
        for (TrafficProcessor tp : processorList) {
            if (tp.isIPFlowFifoFull()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Spušťa komunikáciu s kolektorom cez ACP a poskytuje toky jednotlivýcm procesorom pre spracovanie.
     */
    @Override
    public void run() {
        try {
                //System.out.println(this + ": cakam, prazdne fifo");
                Thread.sleep(1000);
            } catch (InterruptedException ex) {
                interrupt();
            }
        System.out.println(this + ": starts with IPFlow distribution.");
        int respondMessageType = -1;
        int length = 0;

        /* zoznam informacnych elementov, ktore budu prijimane od kolektora */
        int[] fields = {ACPIPFIXTemplate.observationPointID, ACPIPFIXTemplate.flowEndReason, ACPIPFIXTemplate.sourceIPv4Address, ACPIPFIXTemplate.destinationIPv4Address,
            ACPIPFIXTemplate.sourceTransportPort, ACPIPFIXTemplate.destinationTransportPort, ACPIPFIXTemplate.octetTotalCount, ACPIPFIXTemplate.packetTotalCount,
            152, 153, ACPIPFIXTemplate.protocolIdentifier,
            ACPIPFIXTemplate.tcpSynTotalCount, ACPIPFIXTemplate.tcpRstTotalCount, ACPIPFIXTemplate.icmpTypeIPv4, 148, ACPIPFIXTemplate.tcpAckTotalCount, ACPIPFIXTemplate.icmpCodeIPv4, ACPIPFIXTemplate.tcpFinTotalCount};
        try {
            acp.sendTemplate(fields);
            acp.sendFilter(new Filter().createSimpleFilter());
            //acp.sendTransferType(1);

            /* pokial nie je ukoncena komunikacia s kolektorom alebo ukoncena aplikacia*/
            while (!acp.isFinished() && !interrupted()) {
                /* ak nie je buffer ziadneho spracovatela plny*/
                if (!isTrafficProcessorBufferFull()) {
                    /* prijem spravy od kolektora */
                    respondMessageType = acp.getDatInStr().readInt();
                    /*rozhodnutie, ci ide o udajovu spravu alebo potvrdzovaciu spravu*/
                    switch (respondMessageType) {
                        /*ak ide o udajovu spravu*/
                        case ACP.COL_DATA_MSG:
                            IPFlow ipFlow = new IPFlow();
                            /*vsetky polozky su postupne prechadzane v cykle*/
                            for (int k = 0; k < acp.getFieldsToReadACP().length; k++) {
                                byte[] buff = new byte[60];
                                length = acp.getDatInStr().read(buff);
                                /*rozhodnutie o aky typ informacneho elementu ide*/
                                switch (k) {
                                    case 0:
                                        ipFlow.setObsPoint(Integer.parseInt(new String(buff, 0, length)));
                                        break;
                                    case 1:
                                        ipFlow.setFer(Integer.parseInt(new String(buff, 0, length)));
                                        break;
                                    case 2:
                                        ipFlow.setSourceIP(new String(buff, 0, length));
                                        break;
                                    case 3:
                                        ipFlow.setDestIP(new String(buff, 0, length));
                                        break;
                                    case 4:
                                        ipFlow.setSourcePort(Integer.parseInt(new String(buff, 0, length)));
                                        break;
                                    case 5:
                                        ipFlow.setDestPort(Integer.parseInt(new String(buff, 0, length)));
                                        break;
                                    case 6:
                                        ipFlow.setOctetCount(Long.parseLong(new String(buff, 0, length)));
                                        break;
                                    case 7:
                                        ipFlow.setPacketCount(Integer.parseInt(new String(buff, 0, length)));
                                        break;
                                    case 8:
                                        ipFlow.setStartTimeMilis(Long.parseLong(new String(buff, 0, length)));
                                        break;
                                    case 9:
                                        ipFlow.setEndTimeMilis(Long.parseLong(new String(buff, 0, length)));
                                        break;
                                    case 10:
                                        ipFlow.setProtocol(Integer.parseInt(new String(buff, 0, length)));
                                        break;
                                    case 11:
                                        ipFlow.setSynCount(Integer.parseInt(new String(buff, 0, length)));
                                        break;
                                    case 12:
                                        ipFlow.setRstCount(Integer.parseInt(new String(buff, 0, length)));
                                        break;
                                    case 13:
                                        ipFlow.setIcmpType(Integer.parseInt(new String(buff, 0, length)));
                                        break;
//                                    case 14:    
//                                        ipFlow.setFlowId(Long.parseLong(new String(buff, 0, length)));
//                                        System.out.println("Som tu 14.");
//                                        break;
                                    case 14:    
                                        ipFlow.setFlowId(new String(buff, 0, length));
                                        break;
                                    case 15:
                                        ipFlow.setAckCount(Integer.parseInt(new String(buff, 0, length)));
                                        break;
                                    case 16:
                                        ipFlow.setIcmpCode(Integer.parseInt(new String(buff, 0, length)));
                                        break;
                                    case 17:
                                        ipFlow.setFinCount(Integer.parseInt(new String(buff, 0, length)));
                                        break;
                                }
                                /*potvrdenie prijatia elementu*/
                                acp.getDatOutStr().writeInt(5);
                            }
                            System.out.println(this + ": recieved flow");
                            for (TrafficProcessor processor : processorList) {
                                processor.addIPFlowToFifo(ipFlow);
                            }
                            //System.out.println(this + ": actual flow endtime= " + ipFlow.getEndTimeMilis());
                            //System.out.println(this + ": sent flow to processors");
                            break;
                        /*ide o nie udajovu spravu*/
                        case ACP.COL_ANSWER_MSG:
                            acp.readCollectorAnswers();
                            break;
                        default:
                            System.out.println("ACP exception: Unknown message type received (" + respondMessageType + ").");
                    }
                } else {
                    System.out.println(": BUFFER FULL - waiting");
                    Thread.sleep(1000);
                }
            }

            if (!acp.isFinished()) {
                //interrupted by user
                System.out.println(this + ": recieved signal to finish communication.");
                acp.quit();
                System.out.println(this + ": communication with ACP was finished.");
            } else {
                //interrupted by kollektor - probably closed socket
            }
        } catch (ACPException ex) {
            System.out.println(this + ": problem with acp.\n" + ex.getMessage());
            acp.quit();
            stopComponents();
        } catch (InvalidFilterRuleException ex) {
            System.out.println(this + ": invalid filter.\n" + ex.getMessage());
            acp.quit();
            stopComponents();
        } catch (IOException ex) {
            System.out.println(this + ": ACP problem with reading from stream. Collector might be stopped.");
            acp.quit();
            stopComponents();
        } catch (InterruptedException ex) {
            interrupt();
        } catch (NumberFormatException ex) {
            System.out.println(this + ": ACP problem with sending ipflow elements. Reciever can not parse element.");
            acp.quit();
            stopComponents();
        }
    }

    /**
     * This method will stop bmIDS by stopping all running threads (processors and server) except itself.
     * It should be called only when there is problem with acp - collector.
     */
    private void stopComponents() {
        System.out.println("\n" + this + " is finished.");
        //stop all processors
        if (processorList != null) {
            for (TrafficProcessor processor : processorList) {
                if (processor != null && processor.isAlive()) {
                    System.out.println("Shutting down " + processor.getClass().getSimpleName() + " thread...");
                    processor.interrupt();
                    try {
                        processor.join();
                        System.out.println(processor.getClass().getSimpleName() + " is finished.");
                    } catch (InterruptedException ex) {
                        System.out.println(ex.getMessage());
                    }
                }
            }
        }
//        //stop server
//        if (Application.getServer() != null && Application.getServer().isAlive()) {
//            System.out.println("Shutting down " + Application.getServer() + " thread..");
//            try {
//                Application.getServer().getServerSocket().close();
//            } catch (IOException ex) {
//                System.out.println(ex.getMessage());;
//            }
//            try {
//                Application.getServer().join();
//                System.out.println(Application.getServer() + " is finished.");
//            } catch (InterruptedException ex) {
//                System.out.println(ex.getMessage());
//            }
//        }
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName();
    }
}