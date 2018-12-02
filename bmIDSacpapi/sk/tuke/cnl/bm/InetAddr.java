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


import java.text.*;
import java.util.*;
import java.nio.ByteBuffer;


/**
 * Poskytuje funkcie na prácu s IPv4 adresami a portami.
 */
public class InetAddr {

  /**
   * Overí platnosť IP adresy a jej sieťovej masky (overuje len formu, nie obsah).
   * @param addr [0][4] - IP adresa (v jednotlivých bytoch poľa sú uložené príslušné oktety IP adresy),
   * [1][4] - Sieťová maska (v jednotlivých prvkoch poľa sú uložené príslušné oktety sieťovej masky).
   * @throws java.lang.NullPointerException Ak je hodnota parametra alebo poľa s IP adresou resp. sieťovou maskou rovné <CODE>null</CODE>
   * @throws java.lang.NumberFormatException Ak parameter obsahuje viac ako dve polia (jedno pre IP adresu, druhé pre sieťovú masku), alebo dĺžka jedného z polí sa nerovná štyrom
   */
  public static void verify(byte[][] addr) throws NullPointerException, NumberFormatException {

    if (addr == null)
      throw new NullPointerException("Address value is set to null.");
    if (addr.length != 2)
      throw new NumberFormatException("Too many arrays in address (." + addr.length + ").");
    if (addr[0] == null)
      throw new NullPointerException("IP address value is set to null.");
    if (addr[1] == null)
      throw new NullPointerException("Subnet mask value is set to null.");
    if (addr[0].length != 4)
      throw new NumberFormatException("Invalid number of octets in IP address (." + addr[0].length + ").");
    if (addr[1].length != 4)
      throw new NumberFormatException("Invalid number of octets in subnet mask (." + addr[1].length + ").");

  } //verify()

  /**
   * Porovná zhodnosť dvoch IP adries.
   * @param addr1 Prvá IP adresa (Vstupný parameter {@link #verify <CODE>verify</CODE>})
   * @param addr2 Druhá IP adresa (Vstupný parameter {@link #verify <CODE>verify</CODE>})
   * @throws NullPointerException {@link #verify <CODE>verify</CODE>}
   * @throws NumberFormatException Ak je neplatný jedna z adries, alebo sa nezhodujú sieťové masky
   * @return <CODE>true</CODE> ak sa rovnajú adresy aj ich sieťové masky, <CODE>false</CODE> ak sa adresy líšia
   */
  public static boolean equals(byte[][] addr1, byte[][] addr2) throws NullPointerException, NumberFormatException {

    try {
      verify(addr1);
      verify(addr2);
      for (int i = 0; i < 4; i++) {
        if (addr1[1][i] != addr2[1][i])
          throw new NumberFormatException("Network masks differ (can't compare IP addresses with different netmasks).");
        if (addr1[0][i] != addr2[0][i])
          return false;
      } //for
      return true;
    } catch (NullPointerException npe) {
      throw npe;
    } catch (NumberFormatException nfe) {
      throw nfe;
    } //try-catch

  } //equals()

  /**
   * Prevedie reťazec s IP adresou a maskou na pole bytov.
   * @return <CODE>[0][4]</CODE> - pole obsahujúce IP adresu, <CODE>[1][4]</CODE> - pole obsahujúce sieťovú masku
   * @param addr Reťazec v tvare <I>A.B.C.D/n</I>, kde <B>A.B.C.D</B> je IP adresa a <B>n</B> je počet bitov sieťovej časti adresy.
   * časť <I>/n</I> je nepovinná a v prípade, že nebude uvedená, bude za <B>n</B> dosadená hodnota 32.
   * @throws java.lang.NumberFormatException Ak je hodnota niektorého z oktetov IP adresy mimo intervalu <CODE>[0,255]</CODE>
   * @throws java.text.ParseException Ak vstupný reťazec nemá požadovaný formát
   * @throws java.lang.NullPointerException Ak je vstupný reťazec rovné null
   */
  public static byte[][] parse(String addr) throws NullPointerException, ParseException, NumberFormatException {
    String originStr = addr;
    byte[][] result = new byte[2][];
    String s;
    int i, a;

    try {
      if ((i = addr.indexOf("/")) < 0) {
        result[1] = netbitsToMask(32);
        addr = addr + ".";
      } else {
        result[1] = netbitsToMask(addr.substring(i + 1));
        addr = addr.substring(0, i) + ".";
      } //if-else
      result[0] = new byte[4];
      i = 0;
      while (addr.length() > 0) {
        if (i > 3)
          throw new ParseException("Invalid IP address.", originStr.length() - 1);
        s = addr.substring(0, a = addr.indexOf("."));
        addr = addr.substring(a + 1);
        a = Integer.parseInt(s);
        if ((a < 0) || (a > 255))
          throw new NumberFormatException("Invalid byte value.");
        result[0][i] = (byte) (a > 127 ? a - 256 : a);
        i++;
      } //while
      if (i < 3)
        throw new ParseException("Invalid IP address.", originStr.length() - 1);
      return result;
    } catch (NullPointerException npe) {
      throw npe;
    } catch (NumberFormatException nfe) {
      throw new ParseException(nfe.getMessage(), originStr.indexOf(addr));
    } catch (StringIndexOutOfBoundsException sioobe){
      throw new ParseException("Invalid IP address.", originStr.length() - 1);
    } //try-catch

  } //parse()

  /**
   * Prevedie adresu a sieťovú masku na IP adresu vo formáte <CODE>byte[2][4]</CODE>.
   * @param addr IP adresa
   * @param mask Sieťová maska
   * @throws java.lang.NumberFormatException Ak je IP adresa alebo sieťová maska mimo intervalu
   * <CODE>[-2147483648,2147483647]</CODE>, teda mimo intervalu ktorá zahŕňa typ <CODE>int</CODE>
   * @return [0][4] - IP adresa (v jednotlivých bytoch poľa sú uložené príslušné oktety IP adresy),
   * [1][4] - Sieťová maska (v jednotlivých bytoch poľa sú uložené príslušné oktety sieťovej masky).
   */
  public static byte[][] convert(long addr, long mask) throws NumberFormatException {
    byte[][] result;
    ByteBuffer buffer = ByteBuffer.wrap(new byte[4]);
    int i;

    if ((addr < 0) || (addr > 4294967295L))
      throw new NumberFormatException("Invalid IP address.");
    if ((mask < 0) || (mask > 4294967295L))
      throw new NumberFormatException("Invalid subnet mask.");
    result = new byte[2][4];
    buffer.putInt(0, addr > 2147483647 ? (int) (addr - 4294967295L) : (int) addr);
    for (i = 0; i < 4; i++)
      result[0][i] = buffer.get(i);
    buffer.putInt(0, mask > 2147483647 ? (int) (mask - 4294967295L) : (int) mask);
    for (i = 0; i < 4; i++)
      result[1][i] = buffer.get(i);
    return result;

  } //convert()

  /**
   * Vráti IP adresu a masku ako reťazec.
   * @param addr IP adresa (Vstupný parameter {@link #verify <CODE>verify</CODE>})
   * @throws java.lang.NullPointerException {@link #verify <CODE>verify</CODE>}
   * @throws java.lang.NumberFormatException {@link #verify <CODE>verify</CODE>}
   * @return IP adresu vo formáte <I>A.B.C.D/n</I>, kde <B>A.B.C.D</B> je IP adresa a <B>n</B> je počet bitov sieťovej časti IP adresy
   */
  public static String toString(byte[][] addr) throws NullPointerException, NumberFormatException {
    String result = "";
    int i;

    try {
      verify(addr);
      for (i = 0; i < 4; i++) {
        result += addr[0][i] < 0 ? addr[0][i] + 256 : addr[0][i];
        if (i < 3)
          result += ".";
      } //for
      if (addr[1] != null)
        result += "/" + maskToNetbits(addr[1]);
      return result;
    } catch (NullPointerException npe) {
      throw npe;
    } catch (NumberFormatException nfe) {
      throw nfe;
    } //try-catch

  } //toString()

  /**
   * Vráti IP adresu a masku ako reťazec.
   * @param addr IP adresa
   * @param mask Sieťová maska
   * @return IP adresu vo formáte <I>A.B.C.D/n</I>, kde <B>A.B.C.D</B> je IP adresa a <B>n</B> je počet bitov sieťovej časti IP adresy
   */
  public static String toString(int addr, int mask) {
    String result = "";
    int i;

    for (i = 0; i < 4; i++) {
      result += (addr >>> (8*(3-i))) & 255;
      if (i < 3)
        result += ".";
    } //for
    result += "/" + maskToNetbits(mask);
    return result;

  } //toString()

  /**
   * Konvertuje číslo označujúce počet bitov sieťovej časti IP adresy na sieťovú masku.
   * @param n Počet bitov sieťovej časti IP adresy
   * @throws java.lang.NumberFormatException V prípade, že <CODE>n</CODE> je mimo intevalu <CODE>[0,32]</CODE>
   * @return Sieťovú masku, kde každý prvok poľa zodpovedá príslušnému oktetu sieťovej masky
   */
  public static byte[] netbitsToMask(int n) throws NumberFormatException {
    byte[] result = {0, 0, 0, 0};

    if ((n >= 0) && (n <=32)) {
      if (n == 0)
        return result;
      ByteBuffer.wrap(result).putInt(0, Integer.MIN_VALUE >> (n-1));
      return result;
    } else
      throw new NumberFormatException("Bad netbits count.");

  } //netbitsToMask()

  /**
   * Konvertuje číslo označujúce počet bitov sieťovej časti IP adresy na sieťovú masku.
   * @param nStr Počet bitov sieťovej časti IP adresy
   * @throws java.lang.NumberFormatException V prípade, že vstupný reťazec nie je platné číslo <CODE>int</CODE>,
   * alebo <CODE>n</CODE> je mimo intevalu <CODE>[0,32]</CODE>
   * @return Sieťovú masku, kde každý prvok poľa zodpovedá príslušnému oktetu sieťovej masky
   */
  public static byte[] netbitsToMask(String nStr) throws NumberFormatException {

    try {
      return netbitsToMask(Integer.parseInt(nStr));
    } catch (NumberFormatException nfe) {
      throw nfe;
    } //try-catch

  } //netbitsToMask()

  /**
   * Konvertuje sieťovú masku na počet bitov sieťovej časti IP adresy.
   * @param mask Sieťová maska (v jednotlivých prvkoch poľa sú uložené príslušné oktety sieťovej masky)
   * @throws java.lang.NumberFormatException Ak dĺžka vtupného poľa sa nerovná 4, alebo ak je sieťová maska
   * v neplatnom fomáte (binárna sekvencia 1 nasledovaná sekvenciou 0)
   * @return Počet bitov sieťovej časti IP adresy
   */
  public static int maskToNetbits(byte[] mask) throws NumberFormatException {
    int i, n;

    if (mask.length != 4)
      throw new NumberFormatException("Invalid subnet mask.");
    i = ByteBuffer.wrap(mask).getInt(0);
    if (i == 0)
      return 0;
    n = 0;
    while (i != 0) {
      if ((i & Integer.MIN_VALUE) != Integer.MIN_VALUE)
        throw new NumberFormatException("Invalid subnet mask.");
      n++;
      i <<= 1;
    } //while
    return n;

  } //maskToNetbits()

  /**
   * Konvertuje sieťovú masku na počet bitov sieťovej časti IP adresy.
   * @param mask Sieťová maska
   * @return Počet bitov sieťovej časti IP adresy
   */
  public static int maskToNetbits(int mask) {
    int n;

    if (mask == 0)
      return 0;
    n = 0;
    while (mask != 0) {
      if ((mask & Integer.MIN_VALUE) != Integer.MIN_VALUE)
        throw new NumberFormatException("Invalid subnet mask.");
      n++;
      mask <<= 1;
    } //while
    return n;

  } //maskToNetbits()

  /**
   * Porovná dve sieťové masky a zistí ktorá je väčšia.
   * @param mask1 prvá sieťová maska
   * @param mask2 druhá sieťová maska
   * @return -1 ak má prvá maska menej bitov ako druhá, 0 ak sú zhodné, 1 ak má prvá maska viac bitov ako druhá
   * <br><B>Netestuje sa či má maska správny formát, teda či sa jedná o sekvenciu jednotiek nasledovaní
   * sekvenciou núl. V prípade, že má maska nesprávny formát, funkcia síce vráti hodnotu -1, 0, alebo 1,
   * tá však nemá zmysel, pretože neplatné masky nemá zmysel porovnávať.</B>
   */
  public static int compareMasks(int mask1, int mask2) {

    if (mask1 == mask2)
      return 0;
    if (mask1 == 0)
      return -1;
    if (mask2 == 0)
      return 1;
    return (mask1 & Integer.MAX_VALUE) < (mask2 & Integer.MAX_VALUE) ? -1 : 1;

  } //compareMasks()

  /**
   * Prevedie reťazec s číslami portov na pole s ich hodnotami.
   * @param inStr Reťazec s číslami portov. Jednotlivé čísla a rozsahy sú oddelené reťazcom <CODE>sep</CODE>
   * a hranice rozsahov sú oddelené reťazcom <CODE>rangeSep</CODE>. Ak platí, že <CODE>sep = ","</CODE>
   * a <CODE>rangeSep = "-"</CODE>, potom platní formát vstupného reťazca je napr. <I>a,b-c,d-e,f,...</I>
   * @param sep Reťazec oddeľujúci jednotlivé porty a intervaly
   * @param rangeSep Reťazec oddeľujúci hranice rozsahov
   * @param minVal Minimálna povolená hodnota
   * @param maxVal Maximálna povolená hodnota
   * @throws java.text.ParseException Ak vstupný parameter nemý požadovaný formát
   * @throws java.lang.NumberFormatException Ak je hodnota jedného z portov mimo intervalu <CODE>[minVal,maxVal]</CODE>
   * @return Pole dvojprvkových polí s rozsahmi portov, kde v prvom prvku je spodná a v druhom horná hranica rozsahu
   * (ak sa nejedná o interval, obe hodnoty sú rovnakú).
   * <PRE>Napr. reťazec <I>20-23,25,80</I> vráti pole <CODE>int[3][2]</CODE> s hodnotami prvkov:
   * <CODE>[0][0]=20, [0][1]=23, [1][0]=25, [1][1]=25, [2][0]=80, [2][1]=80</CODE></PRE>
   */
  public static int[][] parseIntervalsString(String inStr, String sep, String rangeSep, int minVal, int maxVal) throws ParseException, NumberFormatException {
    String originStr = inStr;
    Vector<int[]> inVec = new Vector<int[]>();
    int i, j;
    String s;
    int[] pr;
    String errorStr = "";

    try {
      if (inStr.length() == 0)
        return new int[0][0];
      inStr += sep;
      while ((i = inStr.indexOf(sep)) > -1) {
        s = inStr.substring(0, i);
        if ((j = s.indexOf(rangeSep)) == -1) {
          errorStr = "Invalid port number.";
          pr = new int[2];
          if (((pr[0] = Integer.valueOf(s)) < minVal) || (pr[0] > maxVal))
            throw new NumberFormatException("Invalid port value.");
          pr[1] = pr[0];
        } else {
          errorStr = "Invalid port range.";
          pr = new int[2];
          if (((pr[0] = Integer.valueOf(s.substring(0, j).replace(" ", ""))) < minVal) || (pr[0] > maxVal) ||
                  ((pr[1] = Integer.valueOf(s.substring(j + 1).replace(" ", ""))) < minVal) || (pr[1] > maxVal))
            throw new NumberFormatException("Invalid port value.");
        } //if-else
        if (!inVec.contains(pr))
          inVec.add(pr);
        inStr = inStr.substring(i + 1);
      } //while
      Iterator it;
      int[][] ins = new int[inVec.size()][2];
      for (it = inVec.iterator(), i = 0; it.hasNext(); i++) {
        ins[i][0] = (pr = (int[])it.next())[0];
        ins[i][1] = pr[1];
      } //for
      return ins;
    } catch (NumberFormatException e) {
      throw new ParseException(errorStr, originStr.indexOf(inStr.substring(0, inStr.length() - 1)));
    } //try-catch

  } //parseIntervalsString

  /**
   * Vráti zoznam portov ako reťazec.
   * @param inList Porty a rozsahy, ktoré sa majú previesť na reťazec
   * @param sep Reťazec oddeľujúci jednotlivé porty a intervaly
   * @param rangeSep Reťazec oddeľujúci hranice rozsahov
   * @return Reťazec reprezentujúci textovú formu zoznamu portov, kde jednotlivé porty a intervaly sú oddelené reťazcom
   * <CODE>sep</CODE> a hranice rozsahov sú oddelené reťazcom <CODE>rangeSep</CODE>
   */
  public static String intervalsToString(ArrayList<int[]> inList, String sep, String rangeSep) {
    String result = "";
    int[] range;

    if ((inList == null) || (inList.isEmpty()))
      return result;
    for (int i = 0, n = inList.size(); i < n; i++) {
      range = inList.get(i);
      if (range[0] == range[1])
        result += range[0];
      else
        result += range[0] + rangeSep + range[1];
      if (i < n - 1)
        result += sep;
    } //for
    return result;

  } //intervalsToString()

  /**
   * Vráti zoznam portov ako reťazec.
   * @param inList Porty a rozsahy, ktoré sa majú previesť na reťazec
   * @param sep Reťazec oddeľujúci jednotlivé porty a intervaly
   * @param rangeSep Reťazec oddeľujúci hranice rozsahov
   * @return Reťazec reprezentujúci textovú formu zoznamu portov, kde jednotlivé porty a intervaly sú oddelené reťazcom
   * <CODE>sep</CODE> a hranice rozsahov sú oddelenú reťazcom <CODE>rangeSep</CODE>
   */
  public static String intervalsToString(int[][] inList, String sep, String rangeSep) {
    String result = "";

    if (inList == null)
      return result;
    for (int i = 0; i < inList.length; i++) {
      if (inList[i][0] == inList[i][1])
        result += inList[i][0];
      else
        result += inList[i][0] + rangeSep + inList[i][1];
      if (i < inList.length - 1)
        result += sep;
    } //for
    return result;

  } //intervalsToString()

  /**
   * Testuje, či prvá IP adresa patrí do siete, ktorú definuje druhá IP adresa.
   * @param addr1 Prvá IP adresa
   * @param mask1 Maska prvej IP adresy
   * @param addr2 Druhá IP adresa
   * @param mask2 Maska druhej IP adresy
   * @return <CODE>true</CODE> prvá IP adresa patrí do siete, ktorá definuje druhá IP adresa alebo je s ňou zhodný, inak <CODE>false</CODE>
   */
  public static boolean contains(int addr1, int mask1, int addr2, int mask2) {

    if ((compareMasks(mask1, mask2) <= 0) && ((addr2 & mask1) == addr1))
      return true;
    else
      return false;

  } //contains()

  /**
   * Vráti n-tú mocninu čísla 2.
   * @param n Ktorá mocnina čísla 2 sa má vypočítať
   * @return n-tú mocninu čísla 2
   */
  private static byte pow2(int n) {
    int i = 1;

    for (int j = 0; j < n; j++)
      i *= 2;
    return (byte) (i > 127 ? i - 256 : i);

  } //pow2

} //InetAddr
