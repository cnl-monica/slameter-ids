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
 *  Subor: TrafficProcessor.java
 */
package sk.tuke.cnl.bmIDS.processor;

import sk.tuke.cnl.bmIDS.IPFlow;
import java.util.LinkedList;

/**
 * Abstraktná trieda pre všetky procesory .
 * @author Martin Ujlaky
 */
public abstract class TrafficProcessor extends Thread {

    /** Front obsahujúci IP toky prijaté od kolektora.*/
    protected LinkedList<IPFlow> ipFlowFifo;
    /** Maximálna veľkosť fronty.*/
    private int maxFifoSize;

    /**
     * Vytvorí objekt procesora.
     */
    public TrafficProcessor() {
        ipFlowFifo = new LinkedList<IPFlow>();
        maxFifoSize = 50;
    }

    /**
     * Pridá IP tok na koniec fronty.
     * @param ipFlow prijatý IP tok
     * @return prijatý IP tok
     */
    public boolean addIPFlowToFifo(IPFlow ipFlow) {
        synchronized (ipFlowFifo) {
            return ipFlowFifo.add(ipFlow);
        }
    }

    /**
     * Pridá IP tok na začiatok fronty.
     * @param ipFlow aktuálny IP tok
     */
    protected void addIPFlowBackToFifo(IPFlow ipFlow) {
        synchronized (ipFlowFifo) {
            ipFlowFifo.addFirst(ipFlow);
        }
    }

    /**
     * Vyberie IP tok zo začiatku fronty.
     * @return IP tok zo začiatku fronty
     */
    protected IPFlow popIPFlowFromFifo() {
        synchronized (ipFlowFifo) {
            return ipFlowFifo.removeFirst();
        }
    }

    /**
     * Testuje,  či je front s IP tokmi prázdny.
     * @return true, ak je front prázdny, inak false
     */
    protected boolean isIPFlowFifoEmpty() {
        synchronized (ipFlowFifo) {
            return ipFlowFifo.isEmpty();
        }
    }

    /**
     * Testuje,  či je front s IP tokmi plný.
     * @return true, ak je front plný, inak false
     */
    public boolean isIPFlowFifoFull() {
        synchronized (ipFlowFifo) {
            return (ipFlowFifo.size() > maxFifoSize);
        }
    }
}
