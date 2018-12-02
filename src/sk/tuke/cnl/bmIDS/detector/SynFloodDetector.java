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
 *  Subor: SynFloodDetector.java
 */
package sk.tuke.cnl.bmIDS.detector;

import java.io.IOException;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.Date;
import java.util.LinkedList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.mail.MessagingException;
import javax.mail.Transport;
import net.sourceforge.jFuzzyLogic.FIS;
import sk.tuke.cnl.bmIDS.Application;
import sk.tuke.cnl.bmIDS.Config;
import sk.tuke.cnl.bmIDS.Constants;
import sk.tuke.cnl.bmIDS.traffic.SynFloodSignTraffic;
import sk.tuke.cnl.bmIDS.api.*;

/**
 * Vyhodnocuje roztriedenú prevádzku voči útoku typu SYN Flood. 
 * @author Martin Ujlaky
 */
public class SynFloodDetector extends FuzzyDetector implements Serializable {

    /** Objekt fuzzy podsystému.*/
    private transient FIS fis;
    private int maxSynCount = 0;
    private double attackProbability = 0;
    private SynFloodSignTraffic maxTraffic = null;
    private SynFloodSignTraffic criticalTraffic = null;
    private LinkedList<Integer> pastSynCounts;
    private long lastEvalTime = 0;
    private long lastEvalTime2 = 0;
    
    private int maxSynCountForSetChart = 0;
    private boolean attackDeteceted = false;

    /**
     * Vytvorí objekt detektora a načíta fuzzy údaje zo súboru.
     * @throws Exception 
     */
    public SynFloodDetector() throws Exception {
        super();
        String filename = "files/synf.fcl";
        fis = FIS.load(filename, true);
        //System.out.println("Nacital som synf.fcl subor.");

        if (fis == null) {
            throw new Exception("Fuzzy Control error: Can't load fcl file " + filename);
        }
        pastSynCounts = new LinkedList<Integer>();
    }

    /**
     * Vytvorí obraz štandardnej prevádzky v podobe fuzzy množín podľa naučenej maximálnej hodnoty sledovanej charakteristiky.
     * @param maxSynCount maximálny počet paketov so syn príznakom v tokoch s rovnakou cieľovou IP adresou a rovnakým cieľovým portom
     */
    public synchronized void setLimits(int maxSynCount) {   // 30
        int count = maxSynCount / 3;                        // 10
        fis.setVariable("synCount1", count);                // 10
        fis.setVariable("synCount2", count * 2);            // 20
        fis.setVariable("synCount3", maxSynCount);          // 30
        fis.setVariable("synCount4", count * 4);            // 40
        fis.setVariable("synCount5", count * 5);            // 50
        fis.setVariable("pastSynCount1", count);            // 10
        fis.setVariable("pastSynCount2", count * 2);        // 20
        fis.setVariable("pastSynCount3", maxSynCount);      // 30
        fis.setVariable("pastSynCount4", count * 4);        // 40
        fis.setVariable("pastSynCount5", count * 5);        // 50
    }

    /**
     * Vráti maximálnu hodnotu najpravejšej fuzzy množiny.
     * @return maximálna hodnota najpravejšej fuzzy množiny
     */
    public int getMaxSynCount() {
        return (int) fis.getVariable("synCount5").getValue();
    }

    public boolean isWebClientConnected() {
        return webClientConnected;
    }

    public void setWebClientConnected(boolean flag) {
        webClientConnected = flag;
    }
    
    
    /********************* SLA START ************************/
    public boolean isSLAWebClientConnected(){
        return webSLAclientConnected;
    }
    
    public void setSLAWebClientConnected(boolean flag) {
        webSLAclientConnected = flag;
    }
    
    
    public void odosliOhraniceniaPreSLA(){
        maxSynCountForSetChart = this.getMaxSynCount();
        jedis.publish("IdsSynFloodAttack", "{\"time\": " + (System.currentTimeMillis() - 600000) + ",\"count\": " + maxSynCountForSetChart + ",\"attack\": " + "false" + "}");
        //System.out.println(this + ": poslal som horne ohranicenia pre SLA web...");    
    }
    
    public void odosliNulaProbabilityPreSLA(){
        jedis.publish("IdsSynFloodAttackProbability", "{\"time\": " + (System.currentTimeMillis() - 600000)+ ",\"count\": " + 0 + ",\"attack\": " + "false" + "}");
        //System.out.println(this + ": poslal som nula probability pre SLA web...");
    }
    /********************* SLA END ************************/
    
    

    /**
     * Vyhodnotí roztriedenú prevádzku fuzzy podsystémom.
     * @param synFTrafficList roztriedená prevádzka podľa charakteristík útoku typu SYN Flood
     * @param reason dôvod vyhodnotenia
     */
    public void evaluate(LinkedList<SynFloodSignTraffic> synFTrafficList, int reason){
        int synCount = 0;

        if (synFTrafficList.isEmpty()) {
            return;
        }

        for (SynFloodSignTraffic synFloodSignTraffic : synFTrafficList) {
            synCount = synFloodSignTraffic.getSynCount();
            if (synCount > maxSynCount) {
                maxSynCount = synCount;
                maxTraffic = synFloodSignTraffic;
            }
        }
        if (maxTraffic == null) {
            return;
        }

        fis.setVariable("pastSynCount", getPastSynCount());
        fis.setVariable("synCount", maxSynCount);
        fis.evaluate();
        if (reason == Constants.NORMAL_EVAL) {
            attackProbability = fis.getVariable("traffic").getLatestDefuzzifiedValue();
        } else {
            attackProbability = 100;
        }

//        if (attackProbability <= Config.threshold) {
//            System.out.println(this + " evaluation:");
//            System.out.println(" output= " + attackProbability);
//            System.out.println(" synCount= " + maxSynCount);
//            System.out.println(" previousSynC= " + getPastSynCount());
//            //System.out.println("src IP: " + maxTraffic.getSourceIPList().getFirst());
//            if (maxTraffic != null) {
//                if (!maxTraffic.getSourceIPList().isEmpty()) {
//                    System.out.println("src ip: " + maxTraffic.getSourceIPList().getFirst());
//                }
//                System.out.println("dst ip: " + maxTraffic.getDestIP());
//            }
//        }

        if (attackProbability > Config.threshold){
            attackDeteceted = true;
        }
        
        sendOutputToClient(maxTraffic.getTillMilis(), maxSynCount);
        try{ Thread.sleep(30);} catch (InterruptedException ex) {}
        sendOutputProbabilityToClient(maxTraffic.getTillMilis(), attackProbability);
        

        if (attackProbability > Config.threshold) {
            if(Config.sendMail.equals("true")){
                sendMailToAdmin();
            }
            
            try {
                synchronized (database) {
                    saveOutputToDatabase();
                }
            } catch (SQLException ex) {
                Logger.getLogger(SynFloodDetector.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        updatePastPacketCount(maxSynCount);
        maxSynCount = 0;
        attackProbability = 0;
        maxTraffic = null;
        attackDeteceted = false;
    }

    /**
     * Vráti hodnotu sledovanej charakteristiky v predchadzajúcich cykloch.
     * @return hodnota sledovanej charakteristiky v predchadzajúcich cykloch
     */
    private int getPastSynCount() {
        int sum = 0;
        for (Integer packetCount : pastSynCounts) {
            sum += packetCount;
        }
        return sum / 2;
    }

    /**
     * Aktualizuje zoznam vyhodnotenej prevádzky v predchadzajúcich dvoch cykloch.
     * @param synCount 
     */
    private void updatePastPacketCount(int synCount) {
        if (pastSynCounts.size() < 2) {
            pastSynCounts.add(synCount);
        } else {
            pastSynCounts.removeFirst();
            pastSynCounts.add(synCount);
        }
    }
    
    private void sendOutputToClient(long time, int synCount) {
        if (isSLAWebClientConnected()) {
            //pri prvom volani nastavi cas vyhodnotenia
            if (lastEvalTime == 0) {
                lastEvalTime = time;
            }
            //v pripade, ze cas aktualneho vyhodnotenia prevadzky je mensi ako pri predoslom vyhodnotenii, upravi sa cas
            //toky od kolektora neprichadzaju v casovom poradi!!! 
            if (time <= lastEvalTime) {
                //uz asi netreba upravit, lebo graf je upraveny tak, ze zobrazi aj predoslu hodnotu
                time = lastEvalTime + 10;
            }
            lastEvalTime = time;        
           
            System.out.println(this + ": sending message to SLA web client");
            jedis.publish("IdsSynFloodAttack", "{\"time\": " + time + ",\"count\": " + synCount + ",\"attack\": " + attackDeteceted + "}");
        } else {
            System.out.println(this + ": client nie je pripojeny.");
        }
    }
    
    private void sendOutputProbabilityToClient(long time, double probability) {
        if (isSLAWebClientConnected()) {
            //pri prvom volani nastavi cas vyhodnotenia
            if (lastEvalTime2 == 0) {
                lastEvalTime2 = time;
            }
            //v pripade, ze cas aktualneho vyhodnotenia prevadzky je mensi ako pri predoslom vyhodnotenii, upravi sa cas
            //toky od kolektora neprichadzaju v casovom poradi!!! 
            if (time <= lastEvalTime2) {
                //uz asi netreba upravit, lebo graf je upraveny tak, ze zobrazi aj predoslu hodnotu
                //System.out.println("SYN detector: ACTUAL time is < PREVIOUS time! Pozri graf");
                time = lastEvalTime2 + 10;
            }
            lastEvalTime2 = time; 
            //long timeToSend = time.getTime();
            System.out.println(this + ": sending message to SLA web client");
            jedis.publish("IdsSynFloodAttackProbability", "{\"time\": " + time + ",\"count\": " + (int) probability + ",\"attack\": " + attackDeteceted + "}");
        } else {
            System.out.println(this + ": client nie je pripojeny.");
        }
    }
    
    private void sendMailToAdmin(){
        try {
            Application.getMessage().setText("\n"
                    + "SYN flood attack detected by " + this + ". Please visit your analyzer. \n"
                    + "\n \n \n"
                    + "---------------------------------------------------------- \n"
                    + "  ATTACK details: \n"
                    + "---------------------------------------------------------- \n"
                    + "       Time since:  " + df.format(new Date(maxTraffic.getSinceMilis())) + "\n"
                    + "       Time till:  " + df.format(new Date(maxTraffic.getTillMilis())) + "\n"
                    + "       Attack probability:  " + (int) attackProbability + "%\n"
                    + "       SYN count:  " + maxSynCount + "\n"
                    + "       Past SYN count:  " + getPastSynCount() + "\n"
                    + "       Source IP:  " + maxTraffic.getSrcIP() + "\n"
                    + "       Destination IP:  " + maxTraffic.getDestIP() + "\n"
                    + "       Destination port:  " + maxTraffic.getDestPort() + "\n"
                    + "---------------------------------------------------------- \n"
                    + "\n \n \n \n"
                    );
            System.out.println(this + ": sending mail to " + Config.mailTo + ".");
            Transport.send(Application.getMessage());
            System.out.println(this + ": mail send.");
        } catch (MessagingException e) {
            e.printStackTrace();
            System.out.println("Sprava od MessagingException");
            System.out.println(e.getMessage());
        }
    }
    

    
    
//    /**
//     * Odošle údaje o vyhodnotenej prevádzke webovej aplikácii.
//     * @param time čas vyhodnotenia
//     * @param synCount hodnota sledovanej charakteristiky útoku typu SYN Flood
//     * @param probability pravdepodobnosť výskytu útoku
//     */
//    private void sendOutputToClient(Date time, int synCount, double probability) {
//        Message message = new Message();
//        message.setType(Flag.Data);
//        message.setTrafficInfo(new SynFloodInfo(time, synCount, probability));
//        if (attackProbability >= Config.threshold) {
//            message.setAttack(true);
//        }
//        if (server.getClient() != null) {
//            try {
//                System.out.println(this + ": sending message to web client");
//                server.getClient().getOos().reset();
//                server.getClient().getOos().writeObject(message);
//                server.getClient().getOos().flush();
//                //System.out.println("sfDetector: odoslal som spravu");
//            } catch (IOException ex) {
//                System.out.println(ex.getMessage());
//            }
//        } else {
//            //System.out.println("sfDetector: client nie je pripojeny.");
//        }
//    }

    /**
     * Uloží údaje o útoku do databázy.
     * @throws SQLException 
     */
    private void saveOutputToDatabase() throws SQLException {
        System.out.println(this + ": ATTACK");
        System.out.println("--------------------------");
        System.out.println("Writing to database.");
        System.out.println("since = " + df.format(new Date(maxTraffic.getSinceMilis())));
        System.out.println("till = " + df.format(new Date(maxTraffic.getTillMilis())));
        System.out.println("vystup = " + attackProbability);
        System.out.println("synCount = " + maxSynCount);
        System.out.println("pastSynC = " + getPastSynCount());
        System.out.println("source ip = " + maxTraffic.getSrcIP());
        System.out.println("destination ip= " + maxTraffic.getDestIP());
        System.out.println("dest port = " + maxTraffic.getDestPort());
        System.out.println("--------------------------");

        //pri prvom detekovani utoku sa nastavi premenna criticalTraffic, aby nebola null pri dalsom porovnavani
        if (criticalTraffic == null) {
            //new attack
            //System.out.println("new attack");
            criticalTraffic = maxTraffic;
            criticalTraffic.setAttackProbability(attackProbability);
            insertAttackDataToDB();
        } else {
            if (maxTraffic.getSinceMilis() > criticalTraffic.getTillMilis() + 10000) {
                //new attack
                //System.out.println("new attack");
                criticalTraffic = maxTraffic;
                criticalTraffic.setAttackProbability(attackProbability);
                insertAttackDataToDB();

            } else {
                //existing attack
                //System.out.println("existing attack");
                if (criticalTraffic.equals(maxTraffic)) {
                    criticalTraffic.update(maxTraffic, attackProbability);
                    updateAttackDataInDB();
                } else {
                    //toto pravdepodobne nenastane nikdy..to by museli vzniknut simultanne (resp. rozne) utoky na obet
                    //System.out.println("simultanny attack");
                    criticalTraffic = maxTraffic;
                    criticalTraffic.setAttackProbability(attackProbability);
                    insertAttackDataToDB();
                }
            }
        }
        System.out.println("===========================");
    }

    /**
     * Vloží údaje o novom útoku do tabuľky v databáze.
     * @throws SQLException 
     */
    private void insertAttackDataToDB() throws SQLException {
        Connection conn = database.getConn();

        //INSERT TO main table - attack_logs + GETTING generated primary key 
        Statement stm = conn.createStatement();
        String attackData = "'SynFlood', " + "'" + new Timestamp(criticalTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(criticalTraffic.getTillMilis()) + "'," + "'" + criticalTraffic.getDestIP() + "'," + "'" + criticalTraffic.getSrcIP() + "'," + criticalTraffic.getDestPort() + "," + criticalTraffic.getSynCount() + "," + (int)attackProbability;
        String sql = "INSERT INTO public.ids_attacklogs(attacktype, starttime, endtime, destip, srcip, destport, sf_syncount, probability) VALUES( " + attackData + ");";
        stm.executeUpdate(sql);

        int id = 0;
        ResultSet rs = stm.executeQuery("SELECT currval('public.ids_attacklogs_id_seq');");
        if (rs.next()) {
            id = rs.getInt(1);
            criticalTraffic.setId(id);

            //INSERT TO detail table - attack_details
            attackData = "'" + new Timestamp(maxTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(maxTraffic.getTillMilis()) + "'," + maxTraffic.getSynCount() + "," + (int)attackProbability + "," + id;
            sql = "INSERT INTO public.ids_attackdetails(since, till, sf_syncount, probability, attack_id) VALUES( " + attackData + ");";
            stm.executeUpdate(sql);
            //System.out.println("data ulozene");
        }
    }

    /**
     * Aktualizuje údaje o útoku v hlavnej tabuľke a vloží údaje o útoku do detailnej tabuľky. 
     * @throws SQLException 
     */
    private void updateAttackDataInDB() throws SQLException {
        Connection conn = database.getConn();
        
        //UPDATE main table - attack_logs
        String sql = "UPDATE public.ids_attacklogs SET endtime='" + new Timestamp(criticalTraffic.getTillMilis()) + "', sf_syncount=" + criticalTraffic.getSynCount() + ", probability=" + (int)criticalTraffic.getAttackProbability() + "WHERE id=" + criticalTraffic.getId() + ";";
        Statement stm = conn.createStatement();
        stm.executeUpdate(sql);
        
        //INSERT TO detail table - attack_detail
        String attackData = "'" + new Timestamp(maxTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(maxTraffic.getTillMilis()) + "'," + maxTraffic.getSynCount() + "," + (int)attackProbability + "," + criticalTraffic.getId();
        sql = "INSERT INTO public.ids_attackdetails(since, till, sf_syncount, probability, attack_id) VALUES( " + attackData + ");";
        stm.executeUpdate(sql);
        //System.out.println("data updatovane");
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName();
    }
}



//    /**
//     * Vloží údaje o novom útoku do tabuľky v databáze.
//     * @throws SQLException 
//     */
//    private void insertAttackDataToDB() throws SQLException {
//        Connection conn = database.getConn();
//
//        //INSERT TO main table - attack_logs + GETTING generated primary key          
//        Statement stm = conn.createStatement();
//        String attackData = "'SynFlood', " + "'" + new Timestamp(criticalTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(criticalTraffic.getTillMilis()) + "'," + "'" + criticalTraffic.getDestIP() + "'," + "'" + criticalTraffic.getSrcIP() + "'," + criticalTraffic.getDestPort() + "," + criticalTraffic.getSynCount() + "," + attackProbability;
//        String sql = "INSERT INTO ids.attack_logs(attacktype, starttime, endtime, destip, srcip, destport, sf_syncount, probability) VALUES( " + attackData + ");";
//        stm.executeUpdate(sql);
//
//        int id = 0;
//        ResultSet rs = stm.executeQuery("SELECT currval('ids.attack_logs_id_seq');");
//        if (rs.next()) {
//            id = rs.getInt(1);
//            criticalTraffic.setId(id);
//
//            //INSERT TO detail table - attack_details
//            attackData = "'" + new Timestamp(maxTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(maxTraffic.getTillMilis()) + "'," + maxTraffic.getSynCount() + "," + attackProbability + "," + id;
//            sql = "INSERT INTO ids.attack_details(since, till, sf_syncount, probability, attack_id) VALUES( " + attackData + ");";
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
//        String sql = "UPDATE ids.attack_logs SET endtime='" + new Timestamp(criticalTraffic.getTillMilis()) + "', sf_syncount=" + criticalTraffic.getSynCount() + ", probability=" + criticalTraffic.getAttackProbability() + "WHERE id=" + criticalTraffic.getId() + ";";
//        Statement stm = conn.createStatement();
//        stm.executeUpdate(sql);
//
//        //INSERT TO detail table - attack_detail
//        String attackData = "'" + new Timestamp(maxTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(maxTraffic.getTillMilis()) + "'," + maxTraffic.getSynCount() + "," + attackProbability + "," + criticalTraffic.getId();
//        sql = "INSERT INTO ids.attack_details(since, till, sf_syncount, probability, attack_id) VALUES( " + attackData + ");";
//        stm.executeUpdate(sql);
//        //System.out.println("data updatovane");
//    }
//
//    @Override
//    public String toString() {
//        return this.getClass().getSimpleName();
//    }
//}