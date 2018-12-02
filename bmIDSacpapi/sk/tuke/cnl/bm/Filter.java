/* Copyright (C) 2013 MONICA Research Group / TUKE
*
* This file is part of JXColl.
*
* JXColl is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 3 of the License, or
* (at your option) any later version.

* JXColl is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.

* You should have received a copy of the GNU General Public License
* along with JXColl; If not, see <http://www.gnu.org/licenses/>.
*/
package sk.tuke.cnl.bm;

import java.io.Serializable;
import java.util.ArrayList;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.util.StringTokenizer;

/**
 * Trieda obsahujúca súbor fitrovačných pravidiel premávky na základe IP adresy meracieho bodu,
 * zdrojovej a cieľovej IP adresy, skupiny portov (zdrojových aj cieľových) a protokolov. Poskytuje metódy
 * na overenie či sa určitá IP adresa, port alebo protokol vyhovuje nastaveným filtrovacím kritériám.
 */
public class Filter implements Serializable {

    protected ArrayList<ByteBuffer[]> mpIP = new ArrayList<ByteBuffer[]>(10);
    protected ArrayList<ByteBuffer[]> srcIP = new ArrayList<ByteBuffer[]>(10);
    protected ArrayList<ByteBuffer[]> dstIP = new ArrayList<ByteBuffer[]>(10);
    protected ArrayList<String> mpIPStr = new ArrayList<String>(10);
    protected ArrayList<String> srcIPStr = new ArrayList<String>(10);
    protected ArrayList<String> dstIPStr = new ArrayList<String>(10);
    protected ArrayList<int[]> srcPorts = new ArrayList<int[]>(10);
    protected ArrayList<int[]> dstPorts = new ArrayList<int[]>(10);
    protected ArrayList<int[]> protocols = new ArrayList<int[]>(10);

    /**
     * Pridá IP adresu a sieťovú masku meracieho bodu.
     * @param ipStr Reťazec reprezentujúci IP adresu meracieho bodu (formát viď. {@link InetAddr#parse InetAddr.parse})
     * @throws java.lang.NullPointerException Viď. {@link InetAddr#parse InetAddr.parse}
     * @throws java.text.ParseException Viď. {@link InetAddr#parse InetAddr.parse}
     */
    public void addMP(String ipStr) throws NullPointerException, ParseException {
        StringTokenizer st = new StringTokenizer(ipStr, ",");

        try {
            while (st.hasMoreTokens()) {
                addIPRule(InetAddr.parse(st.nextToken()), mpIP, mpIPStr);
            }
        } catch (ParseException pe) {
            if (pe.getErrorOffset() == -2) {
                throw new ParseException("Invalid mp network mask.", -2);
            } else {
                throw new ParseException("Invalid mp IP address.", -1);
            }
        } //try-catch

    } //addMP()

    /**
     * Pridá IP adresu a sieťovú masku meracieho bodu.
     * @param ipStr Reťazec reprezentujúci IP adresu meracieho bodu (formát viď. {@link InetAddr#parse InetAddr.parse})
     * @throws java.lang.NullPointerException Viď. {@link InetAddr#parse InetAddr.parse}
     * @throws java.text.ParseException Viď. {@link InetAddr#parse InetAddr.parse}
     */
    public void addMP(byte[][] ip) throws NullPointerException, NumberFormatException {

        try {
            InetAddr.verify(ip);
            addIPRule(ip, mpIP, mpIPStr);
        } catch (NullPointerException npe) {
            throw new NumberFormatException("mp: " + npe.getMessage());
        } catch (NumberFormatException nfe) {
            throw new NumberFormatException("mp: " + nfe.getMessage());
        } //try-catch

    } //addMP()

    /**
     * Pridá zdrojovú IP adresu a sieťovú masku.
     * @param ipStr Reťazec reprezentujúci IP adresu (formát viď. {@link InetAddr#verify InetAddr.verify})
     * @throws java.lang.NullPointerException Viď. {@link InetAddr#parse InetAddr.parse}
     * @throws java.text.ParseException Viď. {@link InetAddr#parse InetAddr.parse}
     */
    public void addSrcIP(String ipStr) throws NullPointerException, ParseException {
        StringTokenizer st = new StringTokenizer(ipStr, ",");

        try {
            while (st.hasMoreTokens()) {
                addIPRule(InetAddr.parse(st.nextToken()), srcIP, srcIPStr);
            }
        } catch (ParseException pe) {
            if (pe.getErrorOffset() == -2) {
                throw new ParseException("Invalid source network mask.", -2);
            } else {
                throw new ParseException("Invalid source IP address.", -1);
            }
        } //try-catch

    } //addSrcIP()

    /**
     * Pridá zdrojovú IP adresu a sieťovú masku.
     * @param ip IP adresa a sieťová maska (formát viď. {@link InetAddr#verify InetAddr.verify})
     * @throws java.lang.NumberFormatException {@link InetAddr#verify InetAddr.verify}
     */
    public void addSrcIP(byte[][] ip) throws NumberFormatException {

        try {
            InetAddr.verify(ip);
            addIPRule(ip, srcIP, srcIPStr);
        } catch (NullPointerException npe) {
            throw new NumberFormatException("Source IP address: " + npe.getMessage());
        } catch (NumberFormatException nfe) {
            throw new NumberFormatException("Source IP address: " + nfe.getMessage());
        } //try-catch

    } //addSrcIP()

    /**
     * Pridá zdrojový porty.
     * @param portsStr Reťazec obsahujúci zoznam zdrojových portov (formát viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString})
     * @param sep Viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString}
     * @param rangeSep Viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString}
     * @throws java.text.ParseException Viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString}
     * @throws java.lang.NumberFormatException Viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString}
     */
    public void addSrcPorts(String portsStr, String sep, String rangeSep) throws ParseException, NumberFormatException {

        try {
            addIntervals(portsStr, sep, rangeSep, srcPorts);
        } catch (ParseException pe) {
            throw new ParseException("Source port string: " + pe.getMessage(), pe.getErrorOffset());
        } catch (NumberFormatException nfe) {
            throw new NumberFormatException("Source port string: " + nfe.getMessage());
        } //try-catch

    } //addSrcPorts()

    /**
     * Pridá cieľovú IP adresu a sieťovú masku.
     * @param ipStr Reťazec reprezentujúci IP adresu (formát viď. {@link InetAddr#verify InetAddr.verify})
     * @throws java.lang.NullPointerException Viď. {@link InetAddr#parse InetAddr.parse}
     * @throws java.text.ParseException Viď. {@link InetAddr#parse InetAddr.parse}
     */
    public void addDstIP(String ipStr) throws NullPointerException, ParseException {
        StringTokenizer st = new StringTokenizer(ipStr, ",");

        try {
            while (st.hasMoreTokens()) {
                addIPRule(InetAddr.parse(st.nextToken()), dstIP, dstIPStr);
            }
        } catch (ParseException pe) {
            if (pe.getErrorOffset() == -2) {
                throw new ParseException("Invalid destination network mask.", -2);
            } else {
                throw new ParseException("Invalid destination IP address.", -1);
            }
        } //try-catch

    } //addDstIP()

    /**
     * Pridá cieľovú IP adresu a sieťovú masku.
     * @param ip IP adresa a sieťová maska (formát viď. {@link InetAddr#verify InetAddr.verify})
     * @throws java.lang.NumberFormatException {@link InetAddr#verify InetAddr.verify}
     */
    public void addDstIP(byte[][] ip) throws NumberFormatException {

        try {
            InetAddr.verify(ip);
            addIPRule(ip, dstIP, dstIPStr);
        } catch (NullPointerException npe) {
            throw new NumberFormatException("Destination IP address: " + npe.getMessage());
        } catch (NumberFormatException nfe) {
            throw new NumberFormatException("Destination IP address: " + nfe.getMessage());
        } //try-catch

    } //addDstIP()

    /**
     * Pridá cieťový porty.
     * @param portsStr Reťazec obsahujúci zoznam cieľových portov (formát viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString})
     * @param sep Viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString}
     * @param rangeSep Viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString}
     * @throws java.text.ParseException Viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString}
     * @throws java.lang.NumberFormatException Viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString}
     */
    public void addDstPorts(String portsStr, String sep, String rangeSep) throws ParseException, NumberFormatException {

        try {
            addIntervals(portsStr, sep, rangeSep, dstPorts);
        } catch (ParseException pe) {
            throw new ParseException("Destination port string: " + pe.getMessage(), pe.getErrorOffset());
        } catch (NumberFormatException nfe) {
            throw new NumberFormatException("Destination port string: " + nfe.getMessage());
        } //try-catch

    } //addDstPorts()

    /**
     * Pridá protokoly.
     * @param protStr Reťazec obsahujúci zoznam protokolov (formát viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString})
     * @param sep Viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString}
     * @param rangeSep Viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString}
     * @throws java.text.ParseException Viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString}
     * @throws java.lang.NumberFormatException Viď. {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString}
     */
    public void addProtocols(String protStr, String sep, String rangeSep) throws ParseException, NumberFormatException {

        try {
            addIntervals(protStr, sep, rangeSep, protocols);
        } catch (ParseException pe) {
            throw new ParseException("Protocols string: " + pe.getMessage(), pe.getErrorOffset());
        } catch (NumberFormatException nfe) {
            throw new NumberFormatException("Protocols string: " + nfe.getMessage());
        } //try-catch

    } //addProtocols()

    /**
     * Vytvorí nový filter bez pravidiel.
     */
    public Filter() {
    } //Filter()

    /**
     * Vytvorí nový filter so špecifikovanými pravidlami.
     * @param filter filter obsahujúci filtračné kritária ktoré sa prenesú do vytváraného filtra
     */
    public Filter(Filter filter) {
        byte[][] ip;
        int i, j, n;

        for (i = 0      ,
            n =  filter.mpIP.size(); i < n; i++) {
      ip = new byte[2][4];
            for (j = 0; j < 4; j++) {
                ip[0][j] = filter.mpIP.get(i)[0].array()[j];
                ip[1][j] = filter.mpIP.get(i)[1].array()[j];
            } //for
            addMP(ip);
        } //for
        for (i = 0      ,
            n =  filter.srcIP.size(); i < n; i++) {
      ip = new byte[2][4];
            for (j = 0; j < 4; j++) {
                ip[0][j] = filter.srcIP.get(i)[0].array()[j];
                ip[1][j] = filter.srcIP.get(i)[1].array()[j];
            } //for
            addSrcIP(ip);
        } //for
        addIntervals(inRulesToArray(filter.srcPorts), srcPorts);
        for (i = 0      ,
            n =  filter.dstIP.size(); i < n; i++) {
      ip = new byte[2][4];
            for (j = 0; j < 4; j++) {
                ip[0][j] = filter.dstIP.get(i)[0].array()[j];
                ip[1][j] = filter.dstIP.get(i)[1].array()[j];
            } //for
            addDstIP(ip);
        } //for
        addIntervals(inRulesToArray(filter.dstPorts), dstPorts);
        addIntervals(inRulesToArray(filter.protocols), protocols);

    } //Filter()

    /**
     * Pripojí zadaný filter k existujúcemu a vykoná optimalizačné kroky:
     *   - spojenie a agregáciu pravidiel obsahujúcich IP adresy (IP adresy meracích bodov, zdrojové a cieľové IP adresy),
     *   - spojenie a združenie pravidiel obsahujúcich rozsahy (zdrojové a cieľové porty, protokoly).
     * <B>Pravidlá sú spájané a ak je niektoré pravidlo podmnožinou iného, je pohltené. Ak napríklad vo filtri neexistuje
     * filtračné kritérium pre zdrojový port, a pripájané pravidlo (to, ktoré je predané cez parameter metódy) obsahuje
     * filtračné kritérium pre zdrojový port 80, výsledné filtračné kritérium pre zdrojový port po spojení ostane prázdne,
     * (čo znamená žiadny filter a teda všetky porty), a každé takéto spojenie pre zdrojový port dopadne rovnako, pretože
     * všetky užšie kritériá sú podmnožinou tohto kritéria.</B>
     * @param filter filter obsahujúci filtračné kritériá ktoré sa spoja s existujúcimi
     */
    public void mergeFilter(Filter filter) {
        byte[][] ip;
        int i, j, n;

        for (i = 0      ,
            n =  filter.mpIP.size(); i < n; i++) {
      ip = new byte[2][4];
            for (j = 0; j < 4; j++) {
                ip[0][j] = filter.mpIP.get(i)[0].array()[j];
                ip[1][j] = filter.mpIP.get(i)[1].array()[j];
            } //for
            addMP(ip);
        } //for
        for (i = 0      ,
            n =  filter.srcIP.size(); i < n; i++) {
      ip = new byte[2][4];
            for (j = 0; j < 4; j++) {
                ip[0][j] = filter.srcIP.get(i)[0].array()[j];
                ip[1][j] = filter.srcIP.get(i)[1].array()[j];
            } //for
            addSrcIP(ip);
        } //for
        if ((srcPorts != null) && (srcPorts.size() > 0)) {
            addIntervals(inRulesToArray(filter.srcPorts), srcPorts);
        }
        for (i = 0      ,
            n =  filter.dstIP.size(); i < n; i++) {
      ip = new byte[2][4];
            for (j = 0; j < 4; j++) {
                ip[0][j] = filter.dstIP.get(i)[0].array()[j];
                ip[1][j] = filter.dstIP.get(i)[1].array()[j];
            } //for
            addDstIP(ip);
        } //for
        if ((dstPorts != null) && (dstPorts.size() > 0)) {
            addIntervals(inRulesToArray(filter.dstPorts), dstPorts);
        }
        if ((protocols != null) && (protocols.size() > 0)) {
            addIntervals(inRulesToArray(filter.protocols), protocols);
        }

    } //mergeFilter()

    /**
     * Vráti IP adresu a sieťovú masku meracieho bodu.
     * @return IP adresa a sieťová maska meracieho bodu ako ByteBuffer[2], kde [0] obsahuje <CODE>ByteBuffer</CODE> nad poľom <CODE>byte[4]</CODE>
     * pre IP adresu a [1] pre sieťovú masku
     */
    public ArrayList<ByteBuffer[]> getMP() {

        return (ArrayList<ByteBuffer[]>) mpIP.clone();

    } //getMP()

    /**
     * Vráti IP adresu a sieťovú masku meracieho bodu ako reťazec.
     * @param sep Reťazec oddeľujúci jednotlivé IP adresy
     * @return IP adresa a sieťová maska meracieho bodu (formát viď. {@link InetAddr#toString InetAddr.toString})
     */
    public String getMPString(String sep) {
        String result = "";

        for (int i = 0, n = mpIPStr.size(); i < n; i++) {
            if (i < n - 1) {
                result += mpIPStr.get(i) + sep;
            } else {
                result += mpIPStr.get(i);
            }
        }
        return result;

    } //getMPString()

    /**
     * Vráti zdrojovú IP adresu a sieťovú masku.
     * @return Zdrojová IP adresa a sieťová maska ako ByteBuffer[2], kde [0] obsahuje <CODE>ByteBuffer</CODE> nad poľom <CODE>byte[4]</CODE>
     * pre IP adresu a [1] pre sieťovú masku
     */
    public ArrayList<ByteBuffer[]> getSrcIP() {

        return (ArrayList<ByteBuffer[]>) srcIP.clone();

    } //getSrcIP()

    /**
     * Vráti zdrojovú IP adresu a sieťovú masku ako reťazec.
     * @param sep Reťazec oddeľujúci jednotlivé IP adresy
     * @return Zdrojová IP adresa a sieťová maska (formát viď. {@link InetAddr#toString InetAddr.toString})
     */
    public String getSrcIPString(String sep) {
        String result = "";

        for (int i = 0, n = srcIPStr.size(); i < n; i++) {
            if (i < n - 1) {
                result += srcIPStr.get(i) + sep;
            } else {
                result += srcIPStr.get(i);
            }
        }
        return result;

    } //getSrcIPString()

    /**
     * Vráti pole so zdrojovými portami.
     * @return Pole so zdrojovými portami (formát viď. návratová hodnota {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString})
     */
    public ArrayList<int[]> getSrcPorts() {

        return (ArrayList<int[]>) srcPorts.clone();

    } //getSrcPorts()

    /**
     * Vráti zoznam zdrojových portov ako reťazec.
     * @param sep Viď. {@link InetAddr#intervalsToString InetAddr.intervalsToString}
     * @param rangeSep Viď. {@link InetAddr#intervalsToString InetAddr.intervalsToString}
     * @return Viď. {@link InetAddr#intervalsToString InetAddr.intervalsToString}
     */
    public String getSrcPortsString(String sep, String rangeSep) {

        return InetAddr.intervalsToString(srcPorts, sep, rangeSep);

    } //getSrcPortsString()

    /**
     * Vráti cieľovú IP adresu a sieťovú masku.
     * @return Cieľová IP adresa a sieťová maska ako ByteBuffer[2], kde [0] obsahuje <CODE>ByteBuffer</CODE> nad poľom <CODE>byte[4]</CODE>
     * pre IP adresu a [1] pre sieťovú masku
     */
    public ArrayList<ByteBuffer[]> getDstIP() {

        return (ArrayList<ByteBuffer[]>) dstIP.clone();

    } //getDstIP()

    /**
     * Vráti cieľovú IP adresu a sieťovú masku ako reťazec.
     * @param sep Reťazec oddeľujúci jednotlivé IP adresy
     * @return Cieľová IP adresa a sieťová maska (formát viď. {@link InetAddr#toString InetAddr.toString})
     */
    public String getDstIPString(String sep) {
        String result = "";

        for (int i = 0, n = dstIPStr.size(); i < n; i++) {
            if (i < n - 1) {
                result += dstIPStr.get(i) + sep;
            } else {
                result += dstIPStr.get(i);
            }
        }
        return result;

    } //getDstIPString()

    /**
     * Vráti pole s cieľovými portami.
     * @return Pole s cieľovými portami (formát viď. návratová hodnota {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString})
     */
    public ArrayList<int[]> getDstPorts() {

        return (ArrayList<int[]>) dstPorts.clone();

    } //getDstPorts()

    /**
     * Vráti zoznam cieľových portov ako reťazec.
     * @param sep Viď. {@link InetAddr#intervalsToString InetAddr.intervalsToString}
     * @param rangeSep Viď. {@link InetAddr#intervalsToString InetAddr.intervalsToString}
     * @return Viď. {@link InetAddr#intervalsToString InetAddr.intervalsToString}
     */
    public String getDstPortsString(String sep, String rangeSep) {

        return InetAddr.intervalsToString(dstPorts, sep, rangeSep);

    } //getDstPortsString()

    /**
     * Vráti pole s protokolmi.
     * @return Pole s protokolmi (formát viď. návratová hodnota {@link InetAddr#parseIntervalsString InetAddr.parseIntervalsString})
     */
    public ArrayList<int[]> getProtocols() {

        return (ArrayList<int[]>) protocols.clone();

    } //getProtocols()

    /**
     * Vráti zoznam protokolov ako reťazec.
     * @param sep Viď. {@link InetAddr#intervalsToString InetAddr.intervalsToString}
     * @param rangeSep Viď. {@link InetAddr#intervalsToString InetAddr.intervalsToString}
     * @return Viď. {@link InetAddr#intervalsToString InetAddr.intervalsToString}
     */
    public String getProtocolsString(String sep, String rangeSep) {

        return InetAddr.intervalsToString(protocols, sep, rangeSep);

    } //getProtocolsString()

    /**
     * Agreguje filtračné pravidlá meracích bodov.
     */
    public void aggregateMPRules() {

        aggregateIPRules(mpIP, mpIPStr);

    } //aggregateMPRules()

    /**
     * Agreguje filtračné pravidlá zdrojových IP adries.
     */
    public void aggregateSrcIPRules() {

        aggregateIPRules(srcIP, srcIPStr);

    } //aggregateSrcIPRules()

    /**
     * Agreguje filtračné pravidlá cieľových IP adries.
     */
    public void aggregateDstIPRules() {

        aggregateIPRules(dstIP, dstIPStr);

    } //aggregateDstIPRules()

    private void addIPRule(byte[][] ip, ArrayList<ByteBuffer[]> ipList, ArrayList<String> ipStr) {
        ByteBuffer[] ipRule = new ByteBuffer[2];
        int newAddr, newMask, oldAddr, oldMask;

        ipRule[0] = ByteBuffer.wrap(ip[0]);
        ipRule[1] = ByteBuffer.wrap(ip[1]);
        ipRule[0].putInt(ipRule[0].getInt(0) & ipRule[1].getInt(0));
        if (ipList.isEmpty()) {
            ipList.add(ipRule);
            ipStr.add(InetAddr.toString(ip));
            return;
        } //if
        newAddr = ipRule[0].getInt(0);
        newMask = ipRule[1].getInt(0);
        for (int i = 0, n = ipList.size(); i < n; i++) {
            oldAddr = ipList.get(i)[0].getInt(0);
            oldMask = ipList.get(i)[1].getInt(0);
            //ak nová sieť je zhodná s existujúcou alebo je jej podsieťou (resp. ak nová IP adresa patrí do existujúcej siete)
            if (InetAddr.contains(oldAddr, oldMask, newAddr, newMask)) {
                return;
            }
            //ak existujúca IP adresa patrí do novej siete
            if (InetAddr.contains(newAddr, newMask, oldAddr, oldMask)) {
                ipList.set(i, ipRule);
                ipStr.set(i, InetAddr.toString(ip));
                //kontrola, či pridané/upravené pravidlo má vplyv na existujúce
                while (true) {
                    for (int j = 0; j < ipList.size(); j++) {
                        if (ipList.get(j) != ipRule) {
                            oldAddr = ipList.get(j)[0].getInt(0);
                            oldMask = ipList.get(j)[1].getInt(0);
                            if (InetAddr.contains(newAddr, newMask, oldAddr, oldMask)) {
                                ipList.remove(j);
                                ipStr.remove(j);
                                break;
                            } //if
                        } //if
                        if (j == ipList.size() - 1) {
                            return;
                        }
                    } //for
                } //while
            } //if
        } //for
        ipList.add(ipRule);
        ipStr.add(InetAddr.toString(ip));

    } //addIPRule()

    private void aggregateIPRules(ArrayList<ByteBuffer[]> ipList, ArrayList<String> ipStr) {
        ByteBuffer[] ipRule1, ipRule2;
        boolean changed = true;
        int i, j, n;
        int mask, masklen;

        MAIN:
        while (changed) {
            changed = false;
            for (i = 0      ,
                n = ipList.size();
                i  < n; i++) {
          ipRule1 = ipList.get(i);
          mask = ipRule1[1].getInt(0);
                if (mask == 0) {
                    continue;
                }
                masklen = InetAddr.maskToNetbits(ipRule1[1].array());
                for (j = i + 1; j < n; j++) {
                    ipRule2 = ipList.get(j);
                    //ak sú masky zhodné a nenulové
                    if (mask == ipRule2[1].getInt(0)) {
                        //ak sa adresy líšia len v sieťovom najnižšom významovom bite potom sa môžu zlúčiť
                        if (((ipRule1[0].getInt(0) & mask) ^ (ipRule2[0].getInt(0) & mask)) == (1 << (32 - masklen))) {
                            mask <<= 1;
                            ipRule1[0].putInt(0, (ipRule1[0].getInt(0) & mask));
                            ipRule1[1].putInt(0, mask);
                            ipStr.set(i, InetAddr.toString(ipRule1[0].getInt(0), mask));
                            ipList.remove(j);
                            ipStr.remove(j);
                            changed = true;
                            continue MAIN;
                        } //if
                    } //if
                } //for
            } //for
        } //while

    } //aggregateIPRules()

    private void addIntervals(String inStr, String sep, String rangeSep, ArrayList<int[]> inList) throws ParseException, NumberFormatException {

        addIntervals(InetAddr.parseIntervalsString(inStr, ",", "-", 0, 65535), inList);

    } //addIntervals()

    private void addIntervals(int[][] ins, ArrayList<int[]> inList) throws NumberFormatException {
        int[] newRange, oldRange;
        boolean add;
        int i, j, k;

        if (ins == null) {
            return;
        }
        for (i = 0; i < ins.length; i++) {
            add = true;
            for (j = 0; j < inList.size(); j++) {
                newRange = inList.get(j);
                //SKIP: ak nový interval je mimo testovaného intervalu
                if ((ins[i][1] + 1 < newRange[0]) || (ins[i][0] - 1 > newRange[1])) {
                    continue;
                }
                //DIE: ak nový interval je vo vnútri testovaného intervalu
                if ((ins[i][0] >= newRange[0]) && (ins[i][1] <= newRange[1])) {
                    add = false;
                    continue;
                } //if
                //MERGE/CONSUME: ak sa nový interval prekrýva s testovaním alebo ho pohltí
                if (((ins[i][0] <= newRange[0]) && (ins[i][1] + 1 >= newRange[0])) ||
                        ((ins[i][1] >= newRange[1]) && (ins[i][0]) - 1 <= newRange[1])) {
                    if (ins[i][0] < newRange[0]) {
                        newRange[0] = ins[i][0];
                    }
                    if (ins[i][1] > newRange[1]) {
                        newRange[1] = ins[i][1];
                    }
                    CHECK: //kontrola, či pridaný/upravený interval má vplyv na existujúce intervaly
                    while (true) {
                        for (k = 0; k < inList.size(); k++) {
                            oldRange = inList.get(k);
                            //SKIP: ak upravený interval (ten ktorý vznikol spojením) je mimo testovaného intervalu
                            if ((newRange == oldRange) || (newRange[0] - 1 > oldRange[1]) || (newRange[1] + 1 < oldRange[0])) {
                                if (k == inList.size() - 1) {
                                    break CHECK;
                                } else {
                                    continue;
                                }
                            }
                            //MERGE/CONSUME: ak sa upravený interval (ten ktorý vznikol spojením) prekrýva s testovaním alebo ho pohlcuje
                            if (((newRange[0] <= oldRange[0]) && (newRange[1] + 1 >= oldRange[0])) ||
                                    ((newRange[1] >= oldRange[1]) && (newRange[0] - 1 <= oldRange[1]))) {
                                if (oldRange[0] < newRange[0]) {
                                    newRange[0] = oldRange[0];
                                }
                                if (oldRange[1] > newRange[1]) {
                                    newRange[1] = oldRange[1];
                                }
                                inList.remove(k);
                                break;
                            } //if
                        } //for
                    } //while
                    add = false;
                } //if
            } //for
            if (add) {
                inList.add(ins[i]);
            }
        } //for

    } //addIntervals()

    private int[][] ipRulesToArray(ArrayList<ByteBuffer[]> ipRules) {
        int[][] result;
        int i, n;

        if (ipRules.isEmpty()) {
            return null;
        }
        result = new int[n = ipRules.size()][2];
        for (i = 0; i < n; i++) {
            result[i][0] = ipRules.get(i)[0].getInt(0);
            result[i][1] = ipRules.get(i)[1].getInt(0);
        } //for
        return result;

    } //ipRulesToArray()

    private int[][] inRulesToArray(ArrayList<int[]> inRules) {
        int[][] result;
        int i, n;

        if (inRules.isEmpty()) {
            return null;
        }
        result = new int[n = inRules.size()][2];
        for (i = 0; i < n; i++) {
            result[i][0] = inRules.get(i)[0];
            result[i][1] = inRules.get(i)[1];
        } //for
        return result;

    } //inRulesToArray()

    /**
     * Podľa nastavených filtračných kritérií, vytvorí {@link SimpleFilter SimpleFilter}. SimpleFilter bude poslaná Kolektoru.
     * @throws sk.tuke.cnl.bm.InvalidFilterRuleException vid {@link SimpleFilter#SimpleFilter SimpleFilter}
     * @return inštanciu objektu {@link SimpleFilter SimpleFilter}
     */
    public SimpleFilter createSimpleFilter() throws InvalidFilterRuleException {

        return new SimpleFilter(ipRulesToArray(mpIP), ipRulesToArray(srcIP), ipRulesToArray(dstIP),
                inRulesToArray(srcPorts), inRulesToArray(dstPorts), inRulesToArray(protocols));

    } //createSimpleFilter()

    //Added by Adrián Pekár
    /**
     * @AdriánPekár
     * Vytvorí filter podľa zadaných kritérií
     * @param MpIP IP Adresa meracieho bodu
     * @param SrcIP IP Adresa zdroja
     * @param SrcPort Číslo portu zdroja
     * @param DstIP Adresa cieľa
     * @param DstPort Číslo portu cieľa
     * @param Protocol Číslo protokolu
     */
    public void ACPCreateFilter(String MpIP, String SrcIP, String SrcPort, String DstIP, String DstPort, String Protocol) {
        try {
            addMP(MpIP);
            addSrcIP(SrcIP);
            addSrcPorts(SrcPort, ",", "-");
            addDstIP(DstIP);
            addDstPorts(DstPort, ",", "-");
            addProtocols(Protocol, ",", "-");
        } catch (ParseException ex) {
            System.out.println(ex.getMessage());
        } catch (NullPointerException ex) {
            System.out.println(ex.getMessage());
        }
    }//ACPCreateFilter()
    //
} //Filter
