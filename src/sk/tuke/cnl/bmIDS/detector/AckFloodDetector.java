///*  Copyright © 2013 MONICA Research Group / TUKE.
// *  This file is part of bmIDSanalyzer.
// *  bmIDSanylyzer is free software: you can redistribute it and/or modify
// *  it under the terms of the GNU General Public License as published by
// *  the Free Software Foundation, either version 3 of the License, or
// *  (at your option) any later version.
// *
// *  bmIDSanalyzer is distributed in the hope that it will be useful,
// *  but WITHOUT ANY WARRANTY; without even the implied warranty of
// *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// *  GNU General Public License for more details.
// *
// *  You should have received a copy of the GNU General Public License
// *  along with bmIDSanalyzer.  If not, see <http://www.gnu.org/licenses/>.
// *
// *             Fakulta Elektrotechniky a informatiky
// *               Technicka univerzita v Kosiciach
// *
// *              Systemy pre detekciu narusenia sieti
// *                      Bakalarska praca
// *
// *  Veduci BP:        Ing. Miroslav Biňas, PhD.
// *  Konzultant BP:    Ing. Adrián Pekár
// *
// *  Autor:            Ladislav Berta
// *
// *  Zdrojove texty:
// *  Subor: AckFloodDetector.java
// */
//package sk.tuke.cnl.bmIDS.detector;
//
//import java.io.IOException;
//import java.io.Serializable;
//import java.sql.Connection;
//import java.sql.ResultSet;
//import java.sql.SQLException;
//import java.sql.Statement;
//import java.sql.Timestamp;
//import java.util.Date;
//import java.util.LinkedList;
//import java.util.logging.Level;
//import java.util.logging.Logger;
//import net.sourceforge.jFuzzyLogic.FIS;
//import sk.tuke.cnl.bmIDS.Config;
//import sk.tuke.cnl.bmIDS.Constants;
//import sk.tuke.cnl.bmIDS.traffic.AckFloodSignTraffic;
//import sk.tuke.cnl.bmIDS.api.*;
//
///**
// * Vyhodnocuje roztriedenú prevádzku voči útoku typu ACK Flood. 
// * @author Ladislav Berta
// */
//public class AckFloodDetector extends FuzzyDetector implements Serializable {
//
//    /** Objekt fuzzy podsystému.*/
//    private transient FIS fis;
//    private int maxAckCount = 0;
//    private double attackProbability = 0;
//    private AckFloodSignTraffic maxTraffic = null;
//    private AckFloodSignTraffic criticalTraffic = null;
//    private LinkedList<Integer> pastAckCounts;
//
//    /**
//     * Vytvorí objekt detektora a načíta fuzzy údaje zo súboru.
//     * @throws Exception 
//     */
//    public AckFloodDetector() throws Exception {
//        super();
//        String filename = "files/ackf.fcl";
//        fis = FIS.load(filename, true);
//        System.out.println("Nacital som ack.fcl subor.");
//       
//        if (fis == null) {
//            throw new Exception("Fuzzy Control error: Can't load fcl file " + filename);
//        }
//        pastAckCounts = new LinkedList<Integer>();
//    }
//
//    /**
//     * Vytvorí obraz štandardnej prevádzky v podobe fuzzy množín podľa naučenej maximálnej hodnoty sledovanej charakteristiky.
//     * @param maxAckCount maximálny počet paketov s ACK príznakom v tokoch s rovnakou cieľovou IP adresou a rovnakým cieľovým portom
//     */
//    public synchronized void setLimits(int maxAckCount) {
//        int count = maxAckCount / 3;
//        fis.setVariable("ackCount1", count);
//        fis.setVariable("ackCount2", count * 2);
//        fis.setVariable("ackCount3", maxAckCount);
//        fis.setVariable("ackCount4", count * 4);
//        fis.setVariable("ackCount5", count * 5);
//        fis.setVariable("pastAckCount1", count);
//        fis.setVariable("pastAckCount2", count * 2);
//        fis.setVariable("pastAckCount3", maxAckCount);
//        fis.setVariable("pastAckCount4", count * 4);
//        fis.setVariable("pastAckCount5", count * 5);
//    }
//
//    /**
//     * Vráti maximálnu hodnotu najpravejšej fuzzy množiny.
//     * @return maximálna hodnota najpravejšej fuzzy množiny
//     */
//    public int getMaxAckCount() {
//        return (int) fis.getVariable("ackCount5").getValue();
//    }
//
//    public boolean isWebClientConnected() {
//        return webClientConnected;
//    }
//
//    public void setWebClientConnected(boolean flag) {
//        webClientConnected = flag;
//    }
//
//    /**
//     * Vyhodnotí roztriedenú prevádzku fuzzy podsystémom.
//     * @param ackFTrafficList roztriedená prevádzka podľa charakteristík útoku typu ACK Flood
//     * @param reason dôvod vyhodnotenia
//     */
//    public void evaluate(LinkedList<AckFloodSignTraffic> ackFTrafficList, int reason) {
//        int ackCount = 0;
//
//        if (ackFTrafficList.isEmpty()) {
//            return;
//        }
//
//        for (AckFloodSignTraffic ackFloodSignTraffic : ackFTrafficList) {
//            ackCount = ackFloodSignTraffic.getAckCount();
//            if (ackCount > maxAckCount) {
//                maxAckCount = ackCount;
//                maxTraffic = ackFloodSignTraffic;
//            }
//        }
//        if (maxTraffic == null) {
//            return;
//        }
//
//        fis.setVariable("pastAckCount", getPastAckCount());
//        fis.setVariable("ackCount", maxAckCount);
//        fis.evaluate();
//        if (reason == Constants.NORMAL_EVAL) {
//            attackProbability = fis.getVariable("traffic").getLatestDefuzzifiedValue();
//        } else {
//            attackProbability = 100;
//        }
//
//        sendOutputToClient(new Date(maxTraffic.getTillMilis()), maxAckCount, attackProbability);
//
//        if (attackProbability > Config.threshold) {
//            try {
//                synchronized (database) {
//                    saveOutputToDatabase();
//                }
//            } catch (SQLException ex) {
//                Logger.getLogger(AckFloodDetector.class.getName()).log(Level.SEVERE, null, ex);
//            }
//        }
//
//        updatePastPacketCount(maxAckCount);
//        maxAckCount = 0;
//        attackProbability = 0;
//        maxTraffic = null;
//    }
//
//    /**
//     * Vráti hodnotu sledovanej charakteristiky v predchadzajúcich cykloch.
//     * @return hodnota sledovanej charakteristiky v predchadzajúcich cykloch
//     */
//    private int getPastAckCount() {
//        int sum = 0;
//        for (Integer packetCount : pastAckCounts) {
//            sum += packetCount;
//        }
//        return sum / 2;
//    }
//
//    /**
//     * Aktualizuje zoznam vyhodnotenej prevádzky v predchadzajúcich dvoch cykloch.
//     * @param ackCount 
//     */
//    private void updatePastPacketCount(int ackCount) {
//        if (pastAckCounts.size() < 2) {
//            pastAckCounts.add(ackCount);
//        } else {
//            pastAckCounts.removeFirst();
//            pastAckCounts.add(ackCount);
//        }
//    }
//
//    /**
//     * Odošle údaje o vyhodnotenej prevádzke webovej aplikácii.
//     * @param time čas vyhodnotenia
//     * @param ackCount hodnota sledovanej charakteristiky útoku typu ACK Flood
//     * @param probability pravdepodobnosť výskytu útoku
//     */
//    private void sendOutputToClient(Date time, int ackCount, double probability) {
//        Message message = new Message();
//        message.setType(Flag.Data);
//        message.setTrafficInfo(new AckFloodInfo(time, ackCount, probability));
//        if (attackProbability >= Config.threshold) {
//            message.setAttack(true);
//        }
//        if (server.getClient() != null) {
//            try {
//                System.out.println(this + ": sending message to web client");
//                server.getClient().getOos().reset();
//                server.getClient().getOos().writeObject(message);
//                server.getClient().getOos().flush();
//                //System.out.println("afDetector: odoslal som spravu");
//            } catch (IOException ex) {
//                System.out.println(ex.getMessage());
//            }
//        } else {
//            //System.out.println("afDetector: client nie je pripojeny.");
//        }
//    }
//
//    /**
//     * Uloží údaje o útoku do databázy.
//     * @throws SQLException 
//     */
//    private void saveOutputToDatabase() throws SQLException {
//        System.out.println("------------------------------------");
//        System.out.println(this + ": ATTACK");
//        System.out.println("------------------------------------");
//        System.out.println("Writing to database.");
//        System.out.println("since:          " + df.format(new Date(maxTraffic.getSinceMilis())));
//        System.out.println("till:           " + df.format(new Date(maxTraffic.getTillMilis())));
//        System.out.println("attackProb:     " + attackProbability);
//        System.out.println("ackCount:       " + maxAckCount);
//        System.out.println("pastAckC:       " + getPastAckCount());
//        System.out.println("source IP:      " + maxTraffic.getSrcIP());
//        System.out.println("destination IP: " + maxTraffic.getDestIP());
//        System.out.println("dest port:      " + maxTraffic.getDestPort());
//        System.out.println("------------------------------------");
//
//        //pri prvom detekovani utoku sa nastavi premenna criticalTraffic, aby nebola null pri dalsom porovnavani
//        if (criticalTraffic == null) {
//            //new attack
//            //System.out.println("new attack");
//            criticalTraffic = maxTraffic;
//            criticalTraffic.setAttackProbability(attackProbability);
//            insertAttackDataToDB();
//        } else {
//            if (maxTraffic.getSinceMilis() > criticalTraffic.getTillMilis() + 10000) {
//                //new attack
//                //System.out.println("new attack");
//                criticalTraffic = maxTraffic;
//                criticalTraffic.setAttackProbability(attackProbability);
//                insertAttackDataToDB();
//
//            } else {
//                //existing attack
//                //System.out.println("existing attack");
//                if (criticalTraffic.equals(maxTraffic)) {
//                    criticalTraffic.update(maxTraffic, attackProbability);
//                    updateAttackDataInDB();
//                } else {
//                    //toto pravdepodobne nenastane nikdy..to by museli vzniknut simultanne (resp. rozne) utoky na obet
//                    //System.out.println("simultanny attack");
//                    criticalTraffic = maxTraffic;
//                    criticalTraffic.setAttackProbability(attackProbability);
//                    insertAttackDataToDB();
//                }
//            }
//        }
//        System.out.println("====================================");
//    }
//
//    /**
//     * Vloží údaje o novom útoku do tabuľky v databáze.
//     * @throws SQLException 
//     */
//    private void insertAttackDataToDB() throws SQLException {
//        Connection conn = database.getConn();
//
//        //INSERT TO main table - attack_logs + GETTING generated primary key          
//        Statement stm = conn.createStatement();
//        String attackData = "'AckFlood', " + "'" + new Timestamp(criticalTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(criticalTraffic.getTillMilis()) + "'," + "'" + criticalTraffic.getDestIP() + "'," + "'" + criticalTraffic.getSrcIP() + "'," + criticalTraffic.getDestPort() + "," + criticalTraffic.getAckCount() + "," + attackProbability;
//        String sql = "INSERT INTO ids.attack_logs(attacktype, starttime, endtime, destip, srcip, destport, af_ackcount, probability) VALUES( " + attackData + ");";
//        stm.executeUpdate(sql);
//
//        int id = 0;
//        ResultSet rs = stm.executeQuery("SELECT currval('ids.attack_logs_id_seq');");
//        if (rs.next()) {
//            id = rs.getInt(1);
//            criticalTraffic.setId(id);
//
//            //INSERT TO detail table - attack_details
//            attackData = "'" + new Timestamp(maxTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(maxTraffic.getTillMilis()) + "'," + maxTraffic.getAckCount() + "," + attackProbability + "," + id;
//            sql = "INSERT INTO ids.attack_details(since, till, af_ackcount, probability, attack_id) VALUES( " + attackData + ");";
//            stm.executeUpdate(sql);
//            //System.out.println("data ulozene");
//        }
//    }
//
//    /**
//     * Aktualizuje údaje o útoku v hlavnej tabuľke a vloží údaje o útoku do detailnej tabuľky. 
//     * @throws SQLException 
//     */
//    private void updateAttackDataInDB() throws SQLException {
//        Connection conn = database.getConn();
//
//        //UPDATE main table - attack_logs
//        String sql = "UPDATE ids.attack_logs SET endtime='" + new Timestamp(criticalTraffic.getTillMilis()) + "', af_ackcount=" + criticalTraffic.getAckCount() + ", probability=" + criticalTraffic.getAttackProbability() + "WHERE id=" + criticalTraffic.getId() + ";";
//        Statement stm = conn.createStatement();
//        stm.executeUpdate(sql);
//
//        //INSERT TO detail table - attack_detail
//        String attackData = "'" + new Timestamp(maxTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(maxTraffic.getTillMilis()) + "'," + maxTraffic.getAckCount() + "," + attackProbability + "," + criticalTraffic.getId();
//        sql = "INSERT INTO ids.attack_details(since, till, af_ackcount, probability, attack_id) VALUES( " + attackData + ");";
//        stm.executeUpdate(sql);
//        //System.out.println("data updatovane");
//    }
//
//    @Override
//    public String toString() {
//        return this.getClass().getSimpleName();
//    }
//}
