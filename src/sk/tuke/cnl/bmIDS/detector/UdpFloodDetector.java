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
 *  Subor: UdpFloodDetector.java
 */
package sk.tuke.cnl.bmIDS.detector;

import java.io.IOException;
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
import sk.tuke.cnl.bmIDS.traffic.UdpFloodSignTraffic;
import sk.tuke.cnl.bmIDS.api.*;
import static sk.tuke.cnl.bmIDS.detector.FuzzyDetector.df;

/**
 * Vyhodnocuje roztriedenú prevádzku voči útoku typu UDP Flood. 
 * @author Martin Ujlaky
 */
public class UdpFloodDetector extends FuzzyDetector implements java.io.Serializable {

    /** Objekt fuzzy podsystému.*/
    private transient FIS fis;
    private UdpFloodSignTraffic criticalTraffic = null;
    private long maxPacketCount = 0;
    private double attackProbability = 0;
    private UdpFloodSignTraffic maxTraffic = null;
    private LinkedList<Long> pastPacketCounts;
    private long lastEvalTime = 0;
    private long lastEvalTime2 = 0;
    
    private int maxUdpCountForSetChart = 0;
    private boolean attackDeteceted = false;

    /**
     * Vytvorí objekt detektora a načíta fuzzy údaje zo súboru.
     * @throws Exception 
     */
    public UdpFloodDetector() throws Exception {
        super();
        String filename = "files/udpf.fcl";
        fis = FIS.load(filename, true);
        //System.out.println("Nacital som udpf.fcl subor.");

        if (fis == null) {
            throw new Exception("Fuzzy Control error: Can't load fcl file " + filename);
        }
        pastPacketCounts = new LinkedList<Long>();
        //System.out.println("Som tu 008.");
    }

    /**
     * Vytvorí obraz štandardnej prevádzky v podobe fuzzy množín podľa naučenej maximálnej hodnoty sledovanej charakteristiky.
     * @param maxPacketCount maximálny počet paketov protokolu udp v tokoch s rovnakou cieľovou IP adresou a rôznym cieľovým portom
     */
    public synchronized void setLimits(long maxPacketCount) {   // 150
        long count = maxPacketCount / 3;                        // 50
        fis.setVariable("packetCount1", count);                 // 50
        fis.setVariable("packetCount2", count * 2);             // 100
        fis.setVariable("packetCount3", maxPacketCount);        // 150
        fis.setVariable("packetCount4", count * 4);             // 200
        fis.setVariable("packetCount5", count * 5);             // 250
        fis.setVariable("pastpacketCount1", count);             // 50
        fis.setVariable("pastpacketCount2", count * 2);         // 100
        fis.setVariable("pastpacketCount3", maxPacketCount);    // 150
        fis.setVariable("pastpacketCount4", count * 4);         // 200
        fis.setVariable("pastpacketCount5", count * 5);         // 250
    }

    /**
     * Vráti maximálnu hodnotu najpravejšej fuzzy množiny.
     * @return maximálna hodnota najpravejšej fuzzy množiny
     */
    public int getMaxPacketCount() {
        return (int) fis.getVariable("packetCount5").getValue();
    }

    public boolean isWebClientConnected() {
        return webClientConnected;
    }

    public void setWebClientConnected(boolean flag) {
        webClientConnected = flag;
    }

    /********************* SLA ************************/
    
    public boolean isSLAWebClientConnected(){
        return webSLAclientConnected;
    }
    
    public void setSLAWebClientConnected(boolean flag) {
        webSLAclientConnected = flag;
    }
    
    
    public void odosliOhraniceniaPreSLA(){
        maxUdpCountForSetChart = this.getMaxPacketCount();
        jedis.publish("IdsUdpFloodAttack", "{\"time\": " + (System.currentTimeMillis() - 600000) + ",\"count\": " + maxUdpCountForSetChart + ",\"attack\": " + "false" + "}");
        //System.out.println(this + ": poslal som horne ohranicenia pre SLA web...");    
    }
    
    public void odosliNulaProbabilityPreSLA(){
        jedis.publish("IdsUdpFloodAttackProbability", "{\"time\": " + (System.currentTimeMillis() - 600000)+ ",\"count\": " + 0 + ",\"attack\": " + "false" + "}");
        //System.out.println(this + ": poslal som nula probability pre SLA web...");
    }
    /********************* SLA ************************/    
    
    
    

    /**
     * Vyhodnotí roztriedenú prevádzku fuzzy podsystémom.
     * @param udpFTrafficList roztriedená prevádzka podľa charakteristík útoku typu UDP Flood
     * @param reason dôvod vyhodnotenia
     */
    public void evaluate(LinkedList<UdpFloodSignTraffic> udpFTrafficList, int reason) {
        long packetCount;

        if (udpFTrafficList.isEmpty()) {
            return;
        }

        for (UdpFloodSignTraffic udpFloodSignTraffic : udpFTrafficList) {
            packetCount = udpFloodSignTraffic.getPacketCount();
            if (packetCount > maxPacketCount) {
                maxPacketCount = packetCount;
                maxTraffic = udpFloodSignTraffic;
            }
        }

        fis.setVariable("pastpacketCount", getPastPacketCount());
        fis.setVariable("packetCount", maxPacketCount);
        fis.evaluate();
        if (reason == Constants.NORMAL_EVAL) {
            attackProbability = fis.getVariable("traffic").getLatestDefuzzifiedValue();
        } else {
            attackProbability = 100;
        }

//        if (attackProbability <= Config.threshold) {
//            System.out.println(this + " evaluation:");
//            System.out.println(" output= " + attackProbability);
//            System.out.println(" packetCount= " + maxPacketCount);
//            System.out.println(" previousPacketC= " + getPastPacketCount());
//        }
        
        
        if (attackProbability > Config.threshold){
            attackDeteceted = true;
        }

        sendOutputToClient(maxTraffic.getTillMilis(), maxPacketCount);
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
                Logger.getLogger(UdpFloodDetector.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        updatePastPacketCount(maxPacketCount);
        maxPacketCount = 0;
        attackProbability = 0;
        maxTraffic = null;
        attackDeteceted = false;
    }

    private void sendOutputToClient(long time, long packetCount) {
        if (isSLAWebClientConnected()) {
            //pri prvom volani nastavi cas vyhodnotenia
            if (lastEvalTime == 0) {
                lastEvalTime = time;
            }
            //v pripade, ze cas aktualneho vyhodnotenia prevadzky je mensi ako pri predoslom vyhodnotenii, upravi sa cas
            //toky od kolektora neprichadzaju v casovom poradi!!! 
            if (time <= lastEvalTime) {
                //uz asi netreba upravit, lebo graf je upraveny tak, ze zobrazi aj predoslu hodnotu
                //System.out.println("UDP detector: ACTUAL time is < PREVIOUS time! Pozri graf");
                time = lastEvalTime + 10;
            }
            lastEvalTime = time;
            
            System.out.println(this + ": sending message to SLA web client");
            jedis.publish("IdsUdpFloodAttack", "{\"time\": " + time + ",\"count\": " + (int) packetCount + ",\"attack\": " + attackDeteceted + "}");
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
                //System.out.println("UDP detector: ACTUAL time is < PREVIOUS time! Pozri graf");
                time = lastEvalTime2 + 10;
            }
            lastEvalTime2 = time;
            
            System.out.println(this + ": sending message to SLA web client");
            jedis.publish("IdsUdpFloodAttackProbability", "{\"time\": " + time + ",\"count\": " + (int) probability + ",\"attack\": " + attackDeteceted + "}");
        } else {
            System.out.println(this + ": client nie je pripojeny.");
        }
    }
    
    private void sendMailToAdmin(){
        try {
            Application.getMessage().setText("\n"
                    + "UDP flood attack detected by " + this + ". Please visit your analyzer. \n"
                    + "\n \n \n"
                    + "---------------------------------------------------------- \n"
                    + "  ATTACK details: \n"
                    + "---------------------------------------------------------- \n"
                    + "       Time since:  " + df.format(new Date(maxTraffic.getSinceMilis())) + "\n"
                    + "       Time till:  " + df.format(new Date(maxTraffic.getTillMilis())) + "\n"
                    + "       Attack probability:  " + attackProbability + "\n"
                    + "       UDP packet count:  " + (int) maxPacketCount + "%\n"
                    + "       Past UDP packet count:  " + getPastPacketCount() + "\n"
                    + "       Source IP:  " + maxTraffic.getSrcIP() + "\n"
                    + "       Destination IP:  " + maxTraffic.getDestIP() + "\n"
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
//     * @param packetCount hodnota sledovanej charakteristiky útoku typu UDP Flood
//     * @param probability pravdepodobnosť výskytu útoku
//     */
//    private void sendOutputToClient(long time, long packetCount, double probability) {
//        //pri prvom volani nastavi cas vyhodnotenia
//        if (lastEvalTime == 0) {
//            lastEvalTime = time;
//        }
//        //v pripade, ze cas aktualneho vyhodnotenia prevadzky je mensi ako pri predoslom vyhodnotenii, upravi sa cas
//        //toky od kolektora neprichadzaju v casovom poradi!!! 
//        if (time <= lastEvalTime) {
//            //uz asi netreba upravit, lebo graf je upraveny tak, ze zobrazi aj predoslu hodnotu
//            //System.out.println("UDP detector: ACTUAL time is < PREVIOUS time! Pozri graf");
//            //time = lastEvalTime + 10;
//        }
//        lastEvalTime = time;
//
//        Message message = new Message();
//        message.setType(Flag.Data);
//        //message.setTrafficInfo(new UdpFloodInfo(new Date(time), (int) maxPacketCount, attackProbability));
//        message.setTrafficInfo(new UdpFloodInfo(new Date(time), (int) packetCount, probability));
//        if (attackProbability >= Config.threshold) {
//            message.setAttack(true);
//        }
//
//        if (server.getClient() != null) {
//            try {
//                System.out.println(this + ": sending message to web client");
//                server.getClient().getOos().reset();
//                server.getClient().getOos().writeObject(message);
//                server.getClient().getOos().flush();
//                //System.out.println(this + ": odoslal som spravu");
//            } catch (IOException ex) {
//                System.out.println(ex.getMessage());
//            }
//        } else {
//            //System.out.println(this + ": client nie je pripojeny.");
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
        System.out.println("packetCount = " + maxPacketCount);
        System.out.println("pastPacketC = " + getPastPacketCount());
        System.out.println("source = " + maxTraffic.getSrcIP());
        System.out.println("destination = " + maxTraffic.getDestIP());
        System.out.println("--------------------------");

        //pri prvom detekovani utoku sa nastavi premenna criticalTraffic, aby nebola null pri dalsom porovnavani
        if (criticalTraffic == null) {
            criticalTraffic = maxTraffic;
            criticalTraffic.setAttackProbability(attackProbability);
            //new attack
            //System.out.println("new attack");
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
        String attackData = "'UdpFlood', " + "'" + new Timestamp(criticalTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(criticalTraffic.getTillMilis()) + "'," + "'" + criticalTraffic.getDestIP() + "'," + "'" + criticalTraffic.getSrcIP() + "'," + criticalTraffic.getPacketCount() + "," + (int)attackProbability;
        String sql = "INSERT INTO public.ids_attacklogs(attacktype, starttime, endtime, destip, srcip, uf_packetcount, probability) VALUES( " + attackData + ");";
        stm.executeUpdate(sql);

        int id = 0;
        ResultSet rs = stm.executeQuery("SELECT currval('public.ids_attacklogs_id_seq');");
        if (rs.next()) {
            id = rs.getInt(1);
            criticalTraffic.setId(id);

            //INSERT TO detail table - attack_details
            attackData = "'" + new Timestamp(maxTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(maxTraffic.getTillMilis()) + "'," + maxTraffic.getPacketCount() + "," + (int)attackProbability + "," + id;
            sql = "INSERT INTO public.ids_attackdetails(since, till, uf_packetcount, probability, attack_id) VALUES( " + attackData + ");";
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
        String sql = "UPDATE public.ids_attacklogs SET endtime='" + new Timestamp(criticalTraffic.getTillMilis()) + "', uf_packetcount=" + criticalTraffic.getPacketCount() + ", probability=" + (int)criticalTraffic.getAttackProbability() + "WHERE id=" + criticalTraffic.getId() + ";";
        Statement stm = conn.createStatement();
        stm.executeUpdate(sql);

        //INSERT TO detail table - attack_detail
        String attackData = "'" + new Timestamp(maxTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(maxTraffic.getTillMilis()) + "'," + maxTraffic.getPacketCount() + "," + (int)attackProbability + "," + criticalTraffic.getId();
        sql = "INSERT INTO public.ids_attackdetails(since, till, uf_packetcount, probability, attack_id) VALUES( " + attackData + ");";
        stm.executeUpdate(sql);
        //System.out.println("data updatovane");
    }

    /**
     * Vráti hodnotu sledovanej charakteristiky v predchadzajúcich cykloch.
     * @return hodnota sledovanej charakteristiky v predchadzajúcich cykloch
     */
    private int getPastPacketCount() {
        int sum = 0;
        for (Long packetCount : pastPacketCounts) {
            sum += packetCount;
        }
        return sum / 2;
    }

    /**
     * Aktualizuje zoznam vyhodnotenej prevádzky v predchadzajúcich dvoch cykloch.
     * @param packetCount 
     */
    private void updatePastPacketCount(long packetCount) {
        if (pastPacketCounts.size() < 2) {
            pastPacketCounts.add(packetCount);
        } else {
            pastPacketCounts.removeFirst();
            pastPacketCounts.add(packetCount);
        }
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName();
    }
}
