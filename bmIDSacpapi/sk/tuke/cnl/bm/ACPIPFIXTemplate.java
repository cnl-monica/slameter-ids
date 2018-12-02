/*Copyright (C) 2013 MONICA Research Group / TUKE
 * 
 * This file is part of JXColl v.3.
 *
 * JXColl v.3 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.

 * JXColl v.3 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with JXColl v.3; If not, see <http://www.gnu.org/licenses/>.
 *
 *              Fakulta Elektrotechniky a informatiky
 *                  Technicka univerzita v Kosiciach
 *
 *  Monitorovanie prevádzkových parametrov siete v reálnom čase
 *                          Bakalárska práca
 *
 *  Veduci DP:        Ing. Juraj Giertl, PhD.
 *  Konzultanti DP:   Ing. Martin Reves
 *
 *  Bakalarant:       Adrián Pekár
 *
 *  Optimalizoval:  Pavol Beňko 
 *  Rok          :  2013
 * 
 *  Zdrojove texty:
 *  Subor: ACPIPFIXTemplate.java
 */



package sk.tuke.cnl.bm;

/**
 *
 * @author Adrián Pekár
 */
public class ACPIPFIXTemplate {

    //element IDs supported be beem
    public static final int protocolIdentifier = 4;
    public static final int ipClassOfService = 5;
    public static final int sourceTransportPort = 7;
    public static final int sourceIPv4Address = 8;
    public static final int destinationTransportPort = 11;
    public static final int destinationIPv4Address = 12;
    public static final int flowEndSysUpTime = 21;
    public static final int flowStartSysUpTime = 22;
    //public static final int sourceIPv6Address = 27;
    //public static final int destinationIPv6Address = 28;
    public static final int icmpTypeCodeIPv4 = 32;
    public static final int igmpType = 33;
    
    public static final int flowActiveTimeout = 36;
    public static final int flowIdleTimeout = 37;
    public static final int fragmentIdentification = 54;
    public static final int ipVersion = 60;
    public static final int octetTotalCount = 85;
    public static final int packetTotalCount = 86;
    public static final int fragmentOffset = 88;
    public static final int flowEndReason = 136;
    public static final int observationPointID = 138;
    public static final int flowId = 148;
    public static final int flowStartMilliseconds = 152;
    
    public static final int flowEndMilliseconds = 153;
    public static final int flowStartMicroseconds = 154;
    public static final int flowEndMicroseconds = 155;
    public static final int flowStartNanoseconds = 156;
    public static final int flowEndNanoseconds = 157;
    public static final int systemInitTimeMilliseconds = 160;
    public static final int flowDurationMilliseconds = 161;
    public static final int	flowDurationMicroseconds = 162;
    public static final int icmpTypeIPv4 = 176;
    public static final int icmpCodeIPv4 = 177;
    //public static final int icmpTypeIPv6 = 178;
    //public static final int icmpCodeIPv6 = 179;
    
    public static final int tcpSequenceNumber = 184;
    public static final int tcpAcknowledgementNumber = 185;
    public static final int tcpWindowSize = 186;
    public static final int tcpUrgentPointer = 187;
    public static final int ipHeaderLength = 189;
    public static final int totalLengthIPv4 = 190;
    public static final int ipTTL = 192;
    public static final int ipDiffServCodePoint = 195;
    public static final int ipPrecedence = 196;
    public static final int fragmentFlags = 197;
    
    public static final int octetTotalSumOfSquares = 199;
    public static final int isMulticast = 206;
    public static final int ipv4IHL = 207;
    public static final int exportInterface =213;
    public static final int tcpSynTotalCount = 218;
    public static final int tcpFinTotalCount = 219;
    public static final int tcpRstTotalCount = 220;
    public static final int tcpPshTotalCount = 221;
    public static final int tcpAckTotalCount = 222;
    public static final int tcpUrgTotalCount = 223;
    public static final int roundTripTimeNanoseconds = 240; // field enterprise="26235"
    
    public static final int packetPairsTotalCount = 241; // field enterprise="26235"

    public static final int[] AllTemplates = { exportInterface, protocolIdentifier,
    											ipClassOfService,
    											sourceTransportPort,
    											sourceIPv4Address,
    											destinationTransportPort,
    											destinationIPv4Address,
    											flowEndSysUpTime,
    											flowStartSysUpTime,
    											icmpTypeCodeIPv4,
    											igmpType,
    											
    											flowActiveTimeout,
    											flowIdleTimeout,
    											fragmentIdentification,
    											ipVersion,
    											octetTotalCount,
    											packetTotalCount,
    											fragmentOffset,
    											observationPointID,
    											flowEndReason,
    											flowStartMilliseconds,
    											
    											flowEndMilliseconds,
    											flowStartMicroseconds,
    											flowEndMicroseconds,
    											flowStartNanoseconds,
    											flowEndNanoseconds,
    											systemInitTimeMilliseconds,
    											flowDurationMilliseconds,
    											flowDurationMicroseconds,
    											icmpTypeIPv4,
    											icmpCodeIPv4,
    											
    											tcpSequenceNumber,
    											tcpAcknowledgementNumber,
    											tcpWindowSize,
    											tcpUrgentPointer,
    											ipHeaderLength,
    											totalLengthIPv4,
    											ipTTL,
    											ipDiffServCodePoint,
    											ipPrecedence,
    											fragmentFlags,
    											
    											octetTotalSumOfSquares,
    											isMulticast,
    											ipv4IHL,
    											tcpSynTotalCount,
    											tcpFinTotalCount,
    											tcpRstTotalCount,
    											tcpPshTotalCount,
    											tcpAckTotalCount,
    											tcpUrgTotalCount,
    											roundTripTimeNanoseconds,
    											
    											packetPairsTotalCount};

     /**
   * Vráti index daného atribútu v danej šablóne.
   * @param templateID ID šablóny
   * @param fieldID ID atribútu
   * @return index daného atribútu v šablóne, ak daný atribút v šablóne neexistuje vráti <CODE>-1</CODE>
   */
  public static int getFieldIndex(int fieldID) {

    for (int i = 0; i < AllTemplates.length; i++)
      if (AllTemplates[i] == fieldID)
        return i;
    return -1;

  } //getFieldIndex()

  /**
   * Vráti názov informčného elementu podľla jeho ID.
   * @param id identifikátora informačného elementu.
   * @return názov informačného elementu.
   */
  public static String getnamebyID(int id){
      if (id == 4) return "protocolIdentifier";
      if (id == 5) return "ipClassOfService";
      if (id == 7) return "sourceTransportPort";
      if (id == 8) return "sourceIPv4Address";
      if (id == 11) return "destinationTransportPort";
      if (id == 12) return "destinationIPv4Address";
      if (id == 21) return "flowEndSysUpTime";
      if (id == 22) return "flowStartSysUpTime";
      	if (id == 27) return "sourceIPv6Address";
      	if (id == 28) return "destinationIPv6Address";
      if (id == 32) return "icmpTypeCodeIPv4";
      if (id == 33) return "igmpType";
      
      if (id == 36) return "flowActiveTimeout";
      if (id == 37) return "flowIdleTimeout";
      if (id == 54) return "fragmentIdentification";
      if (id == 60) return "ipVersion";
      if (id == 85) return "octetTotalCount";
      if (id == 86) return "packetTotalCount";
      if (id == 88) return "fragmentOffset";
      if (id == 136) return "flowEndReason";
      if (id == 138) return "observationPointID";
      if (id == 148) return "flowId";
      if (id == 152) return "flowStartMilliseconds";
      
     
      if (id == 153) return "flowEndMilliseconds";
      if (id == 154) return "flowStartMicroseconds";
      if (id == 155) return "flowEndMicroseconds";
      if (id == 156) return "flowStartNanoseconds";
      if (id == 157) return "flowEndNanoseconds";
      if (id == 160) return "systemInitTimeMilliseconds";
      if (id == 161) return "flowDurationMilliseconds";
      if (id == 162) return "flowDurationMicroseconds";
      if (id == 176) return "icmpTypeIPv4";
      if (id == 177) return "icmpCodeIPv4";
      	if (id == 178) return "icmpTypeIPv6";
      	if (id == 179) return "icmpCodeIPv6";
     
      if (id == 184) return "tcpSequenceNumber";
      if (id == 185) return "tcpAcknowledgementNumber";
      if (id == 186) return "tcpWindowSize";
      if (id == 187) return "tcpUrgentPointer";
      if (id == 189) return "ipHeaderLength";
      if (id == 190) return "totalLengthIPv4";
      if (id == 192) return "ipTTL";
      if (id == 195) return "ipDiffServCodePoint";
      if (id == 196) return "ipPrecedence";
      if (id == 197) return "fragmentFlags";
      
      if (id == 199) return "octetTotalSumOfSquares";
      if (id == 206) return "isMulticast";
      if (id == 207) return "ipv4IHL";
      if (id == 213) return "exportInterface";
      if (id == 218) return "tcpSynTotalCount";
      if (id == 219) return "tcpFinTotalCount";
      if (id == 220) return "tcpRstTotalCount";
      if (id == 221) return "tcpPshTotalCount";
      if (id == 222) return "tcpAckTotalCount";
      if (id == 223) return "tcpUrgTotalCount";
      if (id == 240) return "roundTripTimeNanoseconds";
      
      if (id == 241) return "packetPairsTotalCount";
      return "NO MATCH!";
  }//getnamebyID()

}
