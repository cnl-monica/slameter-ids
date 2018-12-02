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
import java.nio.ByteBuffer;

/**
 * Trieda na zoskupenie týchto filtrovacích pravidiel: IP adresy meracích bodov, zdrojové a cieľové IP adresy, zoznam
 * zdrojových a cieľových portov, zoznam protokolov. Poskytuje metódy na overenie či určitá IP adresa, port alebo protokol
 * vyhovuje týmto filtračným pravidlám.
 */
public class SimpleFilter implements Serializable {

  private static final long serialVersionUID = 1L;
    /**
   * Príznak, či je nastavený filter pre meracie body. Ak nieje, má hodnotu <CODE>0</CODE>.
   */
  public static final int MP_FLAG       = 1;
  /**
   * Príznak, či je nastavený filter pre zdrojové IP adresy. Ak nieje, má hodnotu <CODE>0</CODE>.
   */
  public static final int SRC_IP_FLAG   = 2;
  /**
   * Príznak, či je nastavený filter pre cieľové IP adresy. Ak nieje, má hodnotu <CODE>0</CODE>.
   */
  public static final int DST_IP_FLAG   = 4;
  /**
   * Príznak, či je nastavený filter pre zdrojové porty. Ak nieje, má hodnotu <CODE>0</CODE>.
   */
  public static final int SRC_PORT_FLAG = 8;
  /**
   * Príznak, či je nastavený filter pre cieľové porty. Ak nieje, má hodnotu <CODE>0</CODE>.
   */
  public static final int DST_PORT_FLAG = 16;
  /**
   * Príznak, či je nastavený filter pre protokoly. Ak nieje, má hodnotu <CODE>0</CODE>.
   */
  public static final int PROTOCOL_FLAG = 32;

  /**
   * pre i-té pravidlo platí:
   * int[i][0] - IP adresa siete (resp. hosta, ak je maska /32)
   * int[i][1] - sieťová maska
   */
  private int[][] mpIP;
  private int[][] srcIP;
  private int[][] dstIP;
  private int[][] srcPorts;
  private int[][] dstPorts;
  private int[][] protocols;

  private int flag = 0;

  /**
   * Vytvorí nový filter so zadanými filtračnými pravidlami.<br>
   * Formát <CODE>mpIP</CODE>, <CODE>srcIP</CODE> a <CODE>dstIP</CODE> pre i-té pravidlo:<br>
   * <CODE>int[i][0]</CODE> - IP adresa siete (resp. hosta, ak je maska 255.255.255.255)<br>
   * <CODE>int[i][1]</CODE> - Sieťová maska<br>
   * Formát srcPorts, dstPorts a protocols pre i-té pravidlo:<br>
   * <CODE>int[i][0]</CODE> - Spodná hranica intervalu<br>
   * <CODE>int[i][1]</CODE> - Horná hranica intervalu<br>
   * @param mpIP Pole so sieťovými adresami a maskami meracích bodov
   * @param srcIP Pole so zdrojovými sieťovými adresami a maskami
   * @param dstIP Pole s cieľovými sieťovými adresami a maskami
   * @param srcPorts Pole so zdrojovými portami
   * @param dstPorts Pole s cieľovými portami
   * @param protocols Pole s protokolmi
   * @throws sk.tuke.cnl.bm.InvalidFilterRuleException Ak niektorý zo vstupných parametrov nemá požadovaný formát
   */
  public SimpleFilter(int[][] mpIP, int[][] srcIP, int[][] dstIP, int[][] srcPorts, int[][] dstPorts, int[][] protocols) throws InvalidFilterRuleException {
    int i;

    if (mpIP != null) {
      for (i = 0; i < mpIP.length; i++)
        if (mpIP[i].length != 2)
          throw new InvalidFilterRuleException("Invalid mpIP array.");
      this.mpIP = mpIP;
      flag |= MP_FLAG;
    } //if

    if (srcIP != null) {
      for (i = 0; i < srcIP.length; i++)
        if (srcIP[i].length != 2)
          throw new InvalidFilterRuleException("Invalid srcIP array.");
      this.srcIP = srcIP;
      flag |= SRC_IP_FLAG;
    } //if

    if (dstIP != null) {
      for (i = 0; i < dstIP.length; i++)
        if (dstIP[i].length != 2)
          throw new InvalidFilterRuleException("Invalid dstIP array.");
      this.dstIP = dstIP;
      flag |= DST_IP_FLAG;
    } //if

    if (srcPorts != null) {
      for (i = 0; i < srcPorts.length; i++)
        if (srcPorts[i].length != 2)
          throw new InvalidFilterRuleException("Invalid srcPorts array.");
      this.srcPorts = srcPorts;
      flag |= SRC_PORT_FLAG;
    } //if

    if (dstPorts != null) {
      for (i = 0; i < dstPorts.length; i++)
        if (dstPorts[i].length != 2)
          throw new InvalidFilterRuleException("Invalid dstPorts array.");
      this.dstPorts = dstPorts;
      flag |= DST_PORT_FLAG;
    } //if

    if (protocols != null) {
      for (i = 0; i < protocols.length; i++)
        if (protocols[i].length != 2)
          throw new InvalidFilterRuleException("Invalid protocols array.");
      this.protocols = protocols;
      flag |= PROTOCOL_FLAG;
    } //if

  } //SimpleFilter()

  /**
   * Vráti flag súhrnný flag pre jednotlivé pravidlé filtra.
   * @return <CODE>flag</CODE> daného filtra
   */
  public int getFlag() {

    return flag;

  } //getFlag()

  /**
   * Overí, či daná IP adresa vyhovuje nastaveným kritériam filtra pre merací bod. V prípade, že je vo filtri sieťovou
   * maskou nastavená celá (pod)sieť, zistí, či adresa patrí do tejto podsiete, inak len overí, či sa IP adresy zhodujú. Ak
   * nie je vo filtri nastavená žiadna hodnota, považuje sa kritérium za splnený.
   * @param ip IP adresa meracieho bodu vo formáte byte[4], kde každý prvok poľa zodpovedá príslušnému oktetu IP adresy
   * @throws java.lang.NullPointerException Ak má vstupný parameter hodnotu <CODE>null</CODE>
   * @throws java.lang.NumberFormatException Ak má vstupný parameter neplatný počet oktetov (iné ako 4)
   * @return <CODE>false</CODE> ak sa IP adresa nezhoduje s IP adresou meracieho bodu, resp. ak nepatrí
   * do definovanej siete, inak vráti <CODE>true</CODE>
   */
  public boolean mpMatches(byte[] ip) throws NullPointerException, NumberFormatException {

    if (mpIP == null)
      return true;
    if (ip.length != 4)
      throw new NumberFormatException("Invalid number of octets in IP address.");
    for (int i = 0, n = mpIP.length; i < n; i++)
      if ((ByteBuffer.wrap(ip).getInt(0) & mpIP[i][1]) == mpIP[i][0])
        return true;
    return false;

  } //mpMatches()

  /**
   * Overí, či daná IP adresa vyhovuje nastaveným kritériam filtra pre merací bod. V prípade, že je vo filtri sieťovou
   * maskou nastavená celá (pod)sieť, zistí, či adresa patrí do tejto podsiete, inak len overí, či sa IP adresy zhodujú. Ak
   * nie je vo filtri nastavená žiadna hodnota, považuje sa kritérium za splnený.
   * @param ip IP adresa meracieho bodu
   * @return <CODE>false</CODE> ak sa IP adresa nezhoduje s IP adresou meracieho bodu, resp. ak nepatrí
   * do definovanej siete, inak vráti <CODE>true</CODE>
   */
  public boolean mpMatches(int ip) {

    if (mpIP == null)
      return true;
    for (int i = 0, n = mpIP.length; i < n; i++)
      if ((ip & mpIP[i][1]) == mpIP[i][0])
        return true;
    return false;

  } //mpMatches()

  /**
   * Overí, či daná IP adresa vyhovuje nastaveným kritériam filtra pre zdrojovú IP adresu. V prípade, že je vo filtri sieťovou
   * maskou nastavená celá (pod)sieť, zistí, či adresa patrí do tejto podsiete, inak len overí, či sa IP adresy zhodujú. Ak
   * nie je vo filtri nastavená žiadna hodnota, považuje sa kritérium za splnený.
   * @param ip Zdrojová IP adresa vo formáte byte[4], kde každý prvok poľa zodpovedá príslušnému oktetu IP adresy
   * @throws java.lang.NullPointerException Ak má vstupný parameter hodnotu <CODE>null</CODE>
   * @throws java.lang.NumberFormatException Ak mý vstupný parameter neplatný počet oktetov (iné ako 4)
   * @return <CODE>false</CODE> ak sa IP adresa nezhoduje so zdrojovou IP adresou, resp. ak nepatrí
   * do definovanej siete, inak vráti <CODE>true</CODE>
   */
  public boolean srcIPMatches(byte[] ip) throws NullPointerException, NumberFormatException {

    if (srcIP == null)
      return true;
    if (ip.length != 4)
      throw new NumberFormatException("Invalid number of octets in IP address.");
    for (int i = 0, n = srcIP.length; i < n; i++)
      if ((ByteBuffer.wrap(ip).getInt(0) & srcIP[i][1]) == srcIP[i][0])
        return true;
    return false;

  } //srcIPMatches()

  /**
   * Overí, či daná IP adresa vyhovuje nastaveným kritériam filtra pre zdrojovú IP adresu. V prípade, že je vo filtri sieťovou
   * maskou nastavená celá (pod)sieť, zistí, či adresa patrí do tejto podsiete, inak len overí, či sa IP adresy zhodujú. Ak
   * nie je vo filtri nastavená žiadna hodnota, považuje sa kritérium za splnený.
   * @param ip Zdrojová IP adresa
   * @return <CODE>false</CODE> ak sa IP adresa nezhoduje so zdrojovou IP adresou, resp. ak nepatrí
   * do definovanej siete, inak vráti <CODE>true</CODE>
   */
  public boolean srcIPMatches(int ip) {

    if (srcIP == null)
      return true;
    for (int i = 0, n = srcIP.length; i < n; i++)
      if ((ip & srcIP[i][1]) == srcIP[i][0])
        return true;
    return false;

  } //srcIPMatches()

  /**
   * Overí, či sa daný port nachádza v zozname zdrojových portov. Ak nie je vo filtri nastavená žiadna hodnota,
   * považuje sa kritérium za splnený.
   * @param port Hodnota zdrojového portu
   * @return <CODE>false</CODE> ak sa port nenachádza v zozname zdrojových portov, inak vráti <CODE>true</CODE>
   */
  public boolean srcPortMatches(int port) {

    if (srcPorts == null)
      return true;
    for (int i = 0, n = srcPorts.length; i < n; i++)
      if ((port >= srcPorts[i][0]) && (port <= srcPorts[i][1]))
        return true;
    return false;

  } //srcPortMatches()

  /**
   * Overí, či daná IP adresa vyhovuje nastaveným kritériam filtra pre cieľovú IP adresu. V prípade, že je vo filtri sieťovou
   * maskou nastavená celá (pod)sieť, zistí, či adresa patrí do tejto podsiete, inak len overí, či sa IP adresy zhodujú. Ak
   * nie je vo filtri nastavená žiadna hodnota, považuje sa kritérium za splnený.
   * @param ip Cieľová IP adresa vo formáte byte[4], kde každý prvok poľa zodpovedá príslušnému oktetu IP adresy
   * @throws java.lang.NullPointerException Ak má vstupný parameter hodnotu <CODE>null</CODE>
   * @throws java.lang.NumberFormatException Ak má vstupný parameter neplatný počet oktetov (iné ako 4)
   * @return <CODE>false</CODE> ak sa IP adresa nezhoduje s cieľovou IP adresou, resp. ak nepatrí
   * do definovanej siete, inak vráti <CODE>true</CODE>
   */
  public boolean dstIPMatches(byte[] ip) throws NullPointerException, NumberFormatException {

    if (dstIP == null)
      return true;
    if (ip.length != 4)
      throw new NumberFormatException("Invalid number of octets in IP address.");
    for (int i = 0, n = dstIP.length; i < n; i++)
      if ((ByteBuffer.wrap(ip).getInt(0) & dstIP[i][1]) == dstIP[i][0])
        return true;
    return false;

  } //dstIPMatches()

  /**
   * Overí, či daná IP adresa vyhovuje nastaveným kritériam filtra pre cieľovú IP adresu. V prípade, že je vo filtri sieťovou
   * maskou nastavená celá (pod)sieť, zistí, či adresa patrí do tejto podsiete, inak len overí, či sa IP adresy zhodujú. Ak
   * nie je vo filtri nastavená žiadna hodnota, považuje sa kritérium za splnený.
   * @param ip Cieľová IP adresa
   * @return <CODE>false</CODE> ak sa IP adresa nezhoduje s cieľovou IP adresou, resp. ak nepatrí
   * do definovanej siete, inak vráti <CODE>true</CODE>
   */
  public boolean dstIPMatches(int ip) {

    if (dstIP == null)
      return true;
    for (int i = 0, n = dstIP.length; i < n; i++)
      if ((ip & dstIP[i][1]) == dstIP[i][0])
        return true;
    return false;

  } //dstIPMatches()

  /**
   * Overí, či sa daný port nachádza v zozname zdrojových portov. Ak nie je vo filtri nastavená žiadna hodnota,
   * považuje sa kritérium za splnený.
   * @param port Hodnota cieľového portu
   * @return <CODE>false</CODE> ak sa port nenachádza v zozname cieľových portov, inak vráti <CODE>true</CODE>
   */
  public boolean dstPortMatches(int port) {

    if (dstPorts == null)
      return true;
    for (int i = 0, n = dstPorts.length; i < n; i++)
      if ((port >= dstPorts[i][0]) && (port <= dstPorts[i][1]))
        return true;
    return false;

  } //dstPortMatches()

  /**
   * Overí, či sa daný protokol nachádza v zozname protokolov. Ak nie je vo filtri nastavená žiadna hodnota,
   * považuje sa kritérium za splnený.
   * @param protocol Hodnota protokolu
   * @return <CODE>false</CODE> ak sa protokol nenachádza v zozname protokolov, inak vráti <CODE>true</CODE>
   */
  public boolean protocolMatches(int protocol) {

    if (protocols == null)
      return true;
    for (int i = 0, n = protocols.length; i < n; i++)
      if ((protocol >= protocols[i][0]) && (protocol <= protocols[i][1]))
        return true;
    return false;

  } //protocolMatches()


  /**
   * Na získanie textovej reprezentácie pravidiel nastavených vo filtri.
   * @return Všetky pravidlá filtra vo forme reťazca.
   */
  public String toString() {
    String result;
    int i;

    result = "mpIP:  ";
    if (mpIP == null)
      result += "0.0.0.0/0";
    else
      for (i = 0; i < mpIP.length; i++)
        if (i < mpIP.length - 1)
          result += InetAddr.toString(mpIP[i][0], mpIP[i][1]) + ",";
        else
          result += InetAddr.toString(mpIP[i][0], mpIP[i][1]);
    result += "\nsrcIP: ";
    if (srcIP == null)
      result += "0.0.0.0/0";
    else
      for (i = 0; i < srcIP.length; i++)
        if (i < srcIP.length - 1)
          result += InetAddr.toString(srcIP[i][0], srcIP[i][1]) + ",";
        else
          result += InetAddr.toString(srcIP[i][0], srcIP[i][1]);
    result += "\ndstIP: ";
    if (dstIP == null)
      result += "0.0.0.0/0";
    else
      for (i = 0; i < dstIP.length; i++)
        if (i < dstIP.length - 1)
          result += InetAddr.toString(dstIP[i][0], dstIP[i][1]) + ",";
        else
          result += InetAddr.toString(dstIP[i][0], dstIP[i][1]);
    result += "\nsrcPorts: ";
    result += InetAddr.intervalsToString(srcPorts,  ",", "-");
    result += "\ndstPorts: ";
    result += InetAddr.intervalsToString(dstPorts,  ",", "-");
    result += "\nprotocols: ";
    result += InetAddr.intervalsToString(protocols,  ",", "-");

    return result + "\n";

  } //toString()

}//SimpleFilter
