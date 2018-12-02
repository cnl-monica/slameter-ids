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
 *  Subor: Learn.java
 */
package sk.tuke.cnl.bmIDS;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import sk.tuke.cnl.bmIDS.processor.PortScanProcessor;
import sk.tuke.cnl.bmIDS.processor.SynFloodProcessor;
import sk.tuke.cnl.bmIDS.processor.UdpFloodProcessor;
//import sk.tuke.cnl.bmIDS.processor.AckFloodProcessor;
import sk.tuke.cnl.bmIDS.processor.RstFloodProcessor;
import sk.tuke.cnl.bmIDS.processor.TTLFloodProcessor;
import sk.tuke.cnl.bmIDS.processor.FinFloodProcessor;

/**
 * Zabezpečuje režim učenia, vytvorenie profilu štandardnej prevádzky z historických záznamov. 
 * @author Martin Ujlaky
 */
public class Learn {

    private static BufferedReader inBuffReader = new BufferedReader(new InputStreamReader(System.in));
    private static String input = "";
    private static DateFormat df = new SimpleDateFormat("dd.MM.yy");
    private static Date date = null;
    private static int psMaxFlowCount = 0;
    private static int sfMaxSynCount = 0;
    private static long ufMaxPacketCount = 0;
//    private static int afMaxAckCount = 0;
    private static int rfMaxRstCount = 0;
    private static long tfMaxTtlCount = 0;
    private static int ffMaxFinCount = 0;

    /**
     * Spúšťa režim učenia.
     * @throws Exception 
     */
    public static void start() throws Exception {
        getLearnDate();
        learn();
        processLearnedResults();
    }

    /**
     * Načíta deň učenia zadaný používateľom.
     * @return deň učenia
     * @throws Exception 
     */
    private static Date getLearnDate() throws Exception {
        System.out.println("Type learning date (dd.mm.yy): ");
        try {
            input = inBuffReader.readLine();
            date = df.parse(input);
            //System.out.println("Learn 01.");
        } catch (IOException ex) {
            throw new Exception(ex.getMessage());
        } catch (ParseException ex) {
            System.out.println("Incorrect date format!");
            getLearnDate();
        }
        return date;
    }

    /**
     * Načitáva historické hodnoty z databázy a vykonáva režim učenia.
     * @throws Exception 
     */
    private static void learn() throws Exception {
        IPFlow ipFlow;
        PortScanProcessor psProcessor = new PortScanProcessor();
        //System.out.println("Learn 01 - psProcessor.");
        UdpFloodProcessor ufProcessor = new UdpFloodProcessor();
        //System.out.println("Learn 02 - ufProcessor.");
        SynFloodProcessor sfProcessor = new SynFloodProcessor();
        //System.out.println("Learn 03 - sfProcessor.");
        RstFloodProcessor rfProcessor = new RstFloodProcessor();
        //System.out.println("Learn 04 - rfProcessor.");
        TTLFloodProcessor tfProcessor = new TTLFloodProcessor();
        //System.out.println("Learn 05 - tfProcessor.");
        FinFloodProcessor ffProcessor = new FinFloodProcessor();
        //System.out.println("Learn 06 - ffProcessor.");
        

        long sinceMilis = date.getTime();
        long dayMilis = 86400000;
        long tillMilis = sinceMilis + dayMilis;

        int psResult;
        int sfResult;
        long ufResult;
        int rfResult;
        long tfResult;
        int ffResult;

        Connection connection = null;
        Statement stm = null;
        ResultSet result;
        String sql;
        
        //System.out.println("Learn 10.");
        Class.forName("org.postgresql.Driver");
        
        System.out.println("=========================");
        System.out.println("  Database information   ");
        System.out.println("=========================");
        
        System.out.println("IP address: " + Config.dbIP);
        System.out.println("Port:       " + Config.dbPort);
        System.out.println("Name:       " + Config.dbName);
        System.out.println("Login:      " + Config.dbLogin);
        System.out.println("Password:   " + Config.dbPassword);
        
        System.out.println("=========================");
        
        connection = DriverManager.getConnection("jdbc:postgresql://" + Config.dbIP + ":" + Config.dbPort + "/" + Config.dbName, Config.dbLogin, Config.dbPassword);

        //System.out.println("Learn 11.");
        
        stm = connection.createStatement();
        result = stm.executeQuery("SELECT COUNT(*) AS rowCount FROM records_main WHERE "
                + "flowendmilliseconds BETWEEN " + sinceMilis + " AND " + tillMilis);
        result.next();

        if (result.getInt("rowCount") == 0) {
            throw new Exception("There is no record in database at specified date.");
        } else {
            System.out.println("Number of records in database = " + result.getInt("rowCount"));
        }
              
        sql = "SELECT records_main.rid, flowstartmilliseconds, flowendmilliseconds,"
                + "observationpointid, flowendreason, protocolidentifier, sourceipv4address, destinationipv4address, sourcetransportport, destinationtransportport, packettotalcount, tcpsyntotalcount, tcpacktotalcount, tcprsttotalcount, tcpfintotalcount, icmptypeipv4, icmpcodeipv4, flowid "
                + "FROM records_main "
                + "LEFT JOIN records_flowcounter USING (rid) "
                + "LEFT JOIN records_transportheader USING (rid) "
                + "WHERE (flowendmilliseconds BETWEEN " + sinceMilis + " AND " + tillMilis + ") "
                + "ORDER BY flowendmilliseconds ASC";
        stm = connection.createStatement(ResultSet.TYPE_SCROLL_INSENSITIVE, ResultSet.CONCUR_READ_ONLY);
        
        result = stm.executeQuery(sql);
        
        System.out.println("Learning.....");
        System.out.println(".");
        System.out.println(".");
        
        while (result.next()) {
            ipFlow = new IPFlow();
            ipFlow.setObsPoint(result.getInt("observationpointid"));
            ipFlow.setFer(result.getInt("flowendreason"));
            ipFlow.setProtocol(result.getInt("protocolidentifier"));
            ipFlow.setSourceIP(result.getString("sourceipv4address"));
            ipFlow.setDestIP(result.getString("destinationipv4address"));
            ipFlow.setSourcePort(result.getInt("sourcetransportport"));
            ipFlow.setDestPort(result.getInt("destinationtransportport"));
            ipFlow.setPacketCount(result.getLong("packettotalcount"));
            ipFlow.setStartTimeMilis(result.getLong("flowstartmilliseconds"));
            ipFlow.setEndTimeMilis(result.getLong("flowendmilliseconds"));
            ipFlow.setSynCount(result.getInt("tcpsyntotalcount"));
            ipFlow.setAckCount(result.getInt("tcpacktotalcount"));
            ipFlow.setRstCount(result.getInt("tcprsttotalcount"));
            ipFlow.setFinCount(result.getInt("tcpfintotalcount"));
            ipFlow.setIcmpType(result.getInt("icmptypeipv4"));
            ipFlow.setIcmpCode(result.getInt("icmpcodeipv4"));
            ipFlow.setTtlCount(result.getLong("packettotalcount"));
            //ipFlow.setFlowId(result.getLong("flowid"));
            ipFlow.setFlowId(result.getString("flowid"));
            
            psResult = psProcessor.learn(ipFlow);
            sfResult = sfProcessor.learn(ipFlow);
            ufResult = ufProcessor.learn(ipFlow);
            rfResult = rfProcessor.learn(ipFlow);
            tfResult = tfProcessor.learn(ipFlow);
            ffResult = ffProcessor.learn(ipFlow);

            //port scan
            if (psResult != 0) {
                //System.out.println("LearnMode:ps: vyhodnocujem prijate IP toky ");
                if (psResult > psMaxFlowCount) {
                    //System.out.println("LearnMode:ps: !!! maximalny pocet paketov je viac ako defaultny");
                    psMaxFlowCount = psResult;
                }
            } else {
                //System.out.println("LearnMode:ps: spracoval som IP tok");
            }
            
            //udp flood
            if (ufResult != 0) {
                //System.out.println("LearnMode:uf: vyhodnocujem prijate IP toky ");
                if (ufResult > ufMaxPacketCount) {
                    //System.out.println("LearnMode:uf: !!! maximalny pocet paketov je viac ako defaultny");
                    ufMaxPacketCount = ufResult;
                }
            } else {
                //System.out.println("LearnMode:uf: spracoval som IP tok");
            }

            //syn flood
            if (sfResult != 0) {
                //System.out.println("LearnMode:sf: vyhodnocujem prijate IP toky ");
                if (sfResult > sfMaxSynCount) {
                    //System.out.println("LearnMode:sf: !!! maximalny pocet paketov je viac ako defaultny");
                    sfMaxSynCount = sfResult;
                }
            } else {
                //System.out.println("LearnMode:sf: spracoval som IP tok");
            }
            
            //RST flood
            if (rfResult != 0) {
                //System.out.println("LearnMode:rf: vyhodnocujem prijate IP toky ");
                if (rfResult > rfMaxRstCount) {
                    //System.out.println("LearnMode:rf: !!! maximalny pocet paketov je viac ako defaultny");
                    rfMaxRstCount = rfResult;
                }
            } else {
                //System.out.println("LearnMode:rf: spracoval som IP tok");
            }

            //TTL expiry flood
            if (tfResult != 0) {
                //System.out.println("LearnMode:tf: vyhodnocujem prijate IP toky ");
                if (tfResult > tfMaxTtlCount) {
                    //System.out.println("LearnMode:tf: !!! maximalny pocet paketov je viac ako defaultny");
                    tfMaxTtlCount = tfResult;
                }
            } else {
                //System.out.println("LearnMode:tf: spracoval som IP tok");
            }
            
            //FIN flood
            if (ffResult != 0) {
                //System.out.println("LearnMode:ff: vyhodnocujem prijate IP toky ");
                if (ffResult > ffMaxFinCount) {
                    //System.out.println("LearnMode:ff: !!! maximalny pocet paketov je viac ako defaultny");
                    ffMaxFinCount = ffResult;
                }
            } else {
                //System.out.println("LearnMode:ff: spracoval som IP tok");
            }
        }
        
        stm.close();
        connection.close();
        
        System.out.println("Learning finished.");

        System.out.println("----------------------");
        System.out.println("Learning results:\n");
        System.out.println("psMaxFlowCount=   " + psMaxFlowCount);
        System.out.println("sfMaxSynCount=    " + sfMaxSynCount);
        System.out.println("ufMaxPacketCount= " + ufMaxPacketCount);
        System.out.println("rfMaxRstCount=    " + rfMaxRstCount);
        System.out.println("tfMaxTtlCount=    " + tfMaxTtlCount);
        System.out.println("ffMaxFinCount=    " + ffMaxFinCount);
    }

    /**
     * Spracováva výsledky učenia.
     * @throws Exception 
     */
    private static void processLearnedResults() throws Exception {
        System.out.println("\nSave? [y/n]");
        try {
            input = inBuffReader.readLine();
            if (input.equals("y")) {
                saveLearnedValues();
                System.out.println("Learned values have been saved in file.");
            } else if (input.equals("n")) {
                System.out.println("Learned values have been ignored.");
            } else {
                System.out.println("Incorrect choice!");
                processLearnedResults();
            }
        } catch (IOException ex) {
            throw new Exception(ex.getMessage());
        }
    }
    
    /**
     * Ukladá výsledky učenia.
     */
    private static void saveLearnedValues() {
        Config.psMaxFlowCount = psMaxFlowCount;
        Config.ufMaxPacketCount = ufMaxPacketCount;
        Config.sfMaxSynCount = sfMaxSynCount;
        Config.rfMaxRstCount = rfMaxRstCount;
        Config.tfMaxTtlCount = tfMaxTtlCount;
        Config.ffMaxFinCount = ffMaxFinCount;
        Config.saveData();
    }
}
