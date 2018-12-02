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
 *  Subor: FinFloodDetector.java
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
import redis.clients.jedis.Jedis;
import sk.tuke.cnl.bmIDS.Application;
import sk.tuke.cnl.bmIDS.Config;
import sk.tuke.cnl.bmIDS.Constants;
import sk.tuke.cnl.bmIDS.traffic.FinFloodSignTraffic;
import sk.tuke.cnl.bmIDS.api.*;
import static sk.tuke.cnl.bmIDS.detector.FuzzyDetector.df;
//import static sk.tuke.cnl.bmIDS.detector.FuzzyDetector.komunikacia;

/**
 * Vyhodnocuje roztriedenú prevádzku voči útoku typu FIN Flood. 
 * @author Ladislav Berta
 */
public class FinFloodDetector extends FuzzyDetector implements Serializable {

    /** Objekt fuzzy podsystému.*/
    private transient FIS fis;
    private int maxFinCount = 0;
    private double attackProbability = 0;
    private FinFloodSignTraffic maxTraffic = null;
    private FinFloodSignTraffic criticalTraffic = null;
    private LinkedList<Integer> pastFinCounts;
    
    private int maxFinCountForSetChart = 0;
    private boolean attackDeteceted = false;
    private long lastEvalTime = 0;
    private long lastEvalTime2 = 0;
  

    /**
     * Vytvorí objekt detektora a načíta fuzzy údaje zo súboru.
     * @throws Exception 
     */
    public FinFloodDetector() throws Exception {
        super();
        String filename = "files/finf.fcl";
        fis = FIS.load(filename, true);
        //System.out.println("Nacital som finf.fcl subor.");

        if (fis == null) {
            throw new Exception("Fuzzy Control error: Can't load fcl file " + filename);
        }
        pastFinCounts = new LinkedList<Integer>();
    }

    /**
     * Vytvorí obraz štandardnej prevádzky v podobe fuzzy množín podľa naučenej maximálnej hodnoty sledovanej charakteristiky.
     * @param maxFinCount maximálny počet paketov s FIN príznakom v tokoch s rovnakou cieľovou IP adresou a rovnakým cieľovým portom
     */
    public synchronized void setLimits(int maxFinCount) {   // 30
        int count = maxFinCount / 3;                        // 10
        fis.setVariable("finCount1", count);                // 10
        fis.setVariable("finCount2", count * 2);            // 20
        fis.setVariable("finCount3", maxFinCount);          // 30
        fis.setVariable("finCount4", count * 4);            // 40
        fis.setVariable("finCount5", count * 5);            // 50
        fis.setVariable("pastFinCount1", count);            // 10
        fis.setVariable("pastFinCount2", count * 2);        // 20
        fis.setVariable("pastFinCount3", maxFinCount);      // 30
        fis.setVariable("pastFinCount4", count * 4);        // 40
        fis.setVariable("pastFinCount5", count * 5);        // 50
    }

    /**
     * Vráti maximálnu hodnotu najpravejšej fuzzy množiny.
     * @return maximálna hodnota najpravejšej fuzzy množiny
     */
    public int getMaxFinCount() {
        return (int) fis.getVariable("finCount5").getValue();
    }

    public boolean isWebClientConnected() {
        return webClientConnected;
    }
    
    public void setWebClientConnected(boolean flag) {
        webClientConnected = flag;
    }
    
    /****** SLA ******/
    public boolean isSLAWebClientConnected(){
        return webSLAclientConnected;
    }
    
    public void setSLAWebClientConnected(boolean flag) {
        webSLAclientConnected = flag;
    }
   
           
    public void odosliOhraniceniaPreSLA(){
        maxFinCountForSetChart = this.getMaxFinCount();
        jedis.publish("IdsFinFloodAttack", "{\"time\": " + (System.currentTimeMillis() - 600000) + ",\"count\": " + maxFinCountForSetChart + ",\"attack\": " + "false" + "}");
        //System.out.println(this + ": poslal som horne ohranicenia pre SLA web...");    
    }
    
    public void odosliNulaProbabilityPreSLA(){
        jedis.publish("IdsFinFloodAttackProbability", "{\"time\": " + (System.currentTimeMillis() - 600000)+ ",\"count\": " + 0 + ",\"attack\": " + "false" + "}");
        //System.out.println(this + ": poslal som nula probability pre SLA web...");
    }
    /****** SLA ******/

    
    
    /**
     * Vyhodnotí roztriedenú prevádzku fuzzy podsystémom.
     * @param finFTrafficList roztriedená prevádzka podľa charakteristík útoku typu FIN Flood
     * @param reason dôvod vyhodnotenia
     */
    public void evaluate(LinkedList<FinFloodSignTraffic> finFTrafficList, int reason) {
        int finCount = 0;

        if (finFTrafficList.isEmpty()) {
            return;
        }

        for (FinFloodSignTraffic finFloodSignTraffic : finFTrafficList) {
            finCount = finFloodSignTraffic.getFinCount();
            if (finCount > maxFinCount) {
                maxFinCount = finCount;
                maxTraffic = finFloodSignTraffic;
            }
        }
        if (maxTraffic == null) {
            return;
        }

        fis.setVariable("pastFinCount", getPastFinCount());
        fis.setVariable("finCount", maxFinCount);
        fis.evaluate();
        if (reason == Constants.NORMAL_EVAL) {
            attackProbability = fis.getVariable("traffic").getLatestDefuzzifiedValue();
        } else {
            attackProbability = 100;
        }

        if (attackProbability > Config.threshold){
            attackDeteceted = true;
        }
        
        sendOutputToClient(maxTraffic.getTillMilis(), maxFinCount);
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
                Logger.getLogger(FinFloodDetector.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        updatePastPacketCount(maxFinCount);
        maxFinCount = 0;
        attackProbability = 0;
        maxTraffic = null;
        attackDeteceted = false;
    }

    /**
     * Vráti hodnotu sledovanej charakteristiky v predchadzajúcich cykloch.
     * @return hodnota sledovanej charakteristiky v predchadzajúcich cykloch
     */
    private int getPastFinCount() {
        int sum = 0;
        for (Integer packetCount : pastFinCounts) {
            sum += packetCount;
        }
        return sum / 3;
    }

    /**
     * Aktualizuje zoznam vyhodnotenej prevádzky v predchadzajúcich troch cykloch.
     * @param finCount 
     */
    private void updatePastPacketCount(int finCount) {
        if (pastFinCounts.size() < 3) {
            pastFinCounts.add(finCount);
        } else {
            pastFinCounts.removeFirst();
            pastFinCounts.add(finCount);
        }
    }

    private void sendOutputToClient(long time, int finCount) {
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
            jedis.publish("IdsFinFloodAttack", "{\"time\": " + time + ",\"count\": " + finCount + ",\"attack\": " + attackDeteceted + "}");
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
                time = lastEvalTime2 + 10;
            }
            lastEvalTime2 = time; 
            
            System.out.println(this + ": sending message to SLA web client");
            jedis.publish("IdsFinFloodAttackProbability", "{\"time\": " + time + ",\"count\": " + (int)probability + ",\"attack\": " + attackDeteceted + "}");
        } else {
            System.out.println(this + ": client nie je pripojeny.");
        }
    }
    
    private void sendMailToAdmin(){
        try {
            Application.getMessage().setText("\n"
                    + "FIN flood attack detected by " + this + ". Please visit your analyzer. \n"
                    + "\n \n \n"
                    + "---------------------------------------------------------- \n"
                    + "  ATTACK details: \n"
                    + "---------------------------------------------------------- \n"
                    + "       Time since:  " + df.format(new Date(maxTraffic.getSinceMilis())) + "\n"
                    + "       Time till:  " + df.format(new Date(maxTraffic.getTillMilis())) + "\n"
                    + "       Attack probability:  " + (int) attackProbability + "%\n"
                    + "       FIN count:  " + maxFinCount + "\n"
                    + "       Past FIN count:  " + getPastFinCount() + "\n"
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
    
    
    
//    private void sendOutputToClient(Date time, int finCount, double probability) {
//        Message message = new Message();
//        message.setType(Flag.Data);
//        message.setTrafficInfo(new FinFloodInfo(time, finCount, probability));
//        if (attackProbability >= Config.threshold) {
//            message.setAttack(true);
//        }
//        if (server.getClient() != null) {
//            try {
//                System.out.println(this + ": sending message to web client");
//                server.getClient().getOos().reset();
//                server.getClient().getOos().writeObject(message);
//                server.getClient().getOos().flush();
//                //jedis.publish("idsSettings", "{\"time\": " + System.currentTimeMillis() + ",\"idsSettings\": " + 30 + "}");
//                //System.out.println("ffDetector: odoslal som spravu");
//            } catch (IOException ex) {
//                System.out.println(ex.getMessage());
//            }
//        } else {
//            //System.out.println("ffDetector: client nie je pripojeny.");
//        }
//    }

    /**
     * Uloží údaje o útoku do databázy.
     * @throws SQLException 
     */
    private void saveOutputToDatabase() throws SQLException {
        System.out.println("------------------------------------");
        System.out.println(this + ": ATTACK");
        System.out.println("------------------------------------");
        System.out.println("Writing to database.");
        System.out.println("since:          " + df.format(new Date(maxTraffic.getSinceMilis())));
        System.out.println("till:           " + df.format(new Date(maxTraffic.getTillMilis())));
        System.out.println("attackProb:     " + attackProbability);
        System.out.println("finCount:       " + maxFinCount);
        System.out.println("pastFinC:       " + getPastFinCount());
        System.out.println("source IP:      " + maxTraffic.getSrcIP());
        System.out.println("destination IP: " + maxTraffic.getDestIP());
        System.out.println("dest port:      " + maxTraffic.getDestPort());
        System.out.println("------------------------------------");

        //pri prvom detekovani utoku sa nastavi premenna criticalTraffic, aby nebola null pri dalsom porovnavani
        if (criticalTraffic == null) {
            //new attack
            //System.out.println("new attack");
            criticalTraffic = maxTraffic;
            criticalTraffic.setAttackProbability(attackProbability);
            insertAttackDataToDB();
        } else {
            if (maxTraffic.getSinceMilis() > criticalTraffic.getTillMilis() + 15000) {
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
        System.out.println("====================================");
    }

    /**
     * Vloží údaje o novom útoku do tabuľky v databáze.
     * @throws SQLException 
     */
    private void insertAttackDataToDB() throws SQLException {
        Connection conn = database.getConn();

        //INSERT TO main table - attack_logs + GETTING generated primary key          
        Statement stm = conn.createStatement();
        String attackData = "'FinFlood', " + "'" + new Timestamp(criticalTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(criticalTraffic.getTillMilis()) + "'," + "'" + criticalTraffic.getDestIP() + "'," + "'" + criticalTraffic.getSrcIP() + "'," + criticalTraffic.getDestPort() + "," + criticalTraffic.getFinCount() + "," + (int)attackProbability;
        String sql = "INSERT INTO public.ids_attacklogs(attacktype, starttime, endtime, destip, srcip, destport, ff_fincount, probability) VALUES( " + attackData + ");";
        stm.executeUpdate(sql);

        int id = 0;
        ResultSet rs = stm.executeQuery("SELECT currval('public.ids_attacklogs_id_seq');");
        if (rs.next()) {
            id = rs.getInt(1);
            criticalTraffic.setId(id);

            //INSERT TO detail table - attack_details
            attackData = "'" + new Timestamp(maxTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(maxTraffic.getTillMilis()) + "'," + maxTraffic.getFinCount() + "," + (int)attackProbability + "," + id;
            sql = "INSERT INTO public.ids_attackdetails(since, till, ff_fincount, probability, attack_id) VALUES( " + attackData + ");";
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
        String sql = "UPDATE public.ids_attacklogs SET endtime='" + new Timestamp(criticalTraffic.getTillMilis()) + "', ff_fincount=" + criticalTraffic.getFinCount() + ", probability=" + (int)criticalTraffic.getAttackProbability() + "WHERE id=" + criticalTraffic.getId() + ";";
        Statement stm = conn.createStatement();
        stm.executeUpdate(sql);

        //INSERT TO detail table - attack_detail
        String attackData = "'" + new Timestamp(maxTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(maxTraffic.getTillMilis()) + "'," + maxTraffic.getFinCount() + "," + (int)attackProbability + "," + criticalTraffic.getId();
        sql = "INSERT INTO public.ids_attackdetails(since, till, ff_fincount, probability, attack_id) VALUES( " + attackData + ");";
        stm.executeUpdate(sql);
        //System.out.println("data updatovane");
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName();
    }
}
