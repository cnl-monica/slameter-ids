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
 *  Subor: PortScanDetector.java
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
import sk.tuke.cnl.bmIDS.traffic.PortScanSignTraffic;
import sk.tuke.cnl.bmIDS.api.*;
import static sk.tuke.cnl.bmIDS.detector.FuzzyDetector.df;

/**
 * Vyhodnocuje roztriedenú prevádzku voči útoku typu Port Scan. 
 * @author Martin Ujlaky
 */
public class PortScanDetector extends FuzzyDetector implements java.io.Serializable {

    /** Objekt fuzzy podsystému.*/
    private transient FIS fis;
    private int maxFlowCount = 0;
    private double attackProbability = 0;
    private PortScanSignTraffic maxTraffic = null;
    private PortScanSignTraffic criticalTraffic = null;
    private long lastEvalTime = 0;
    private long lastEvalTime2 = 0;
    
    private int maxFlowCountForSetChart = 0;
    private boolean attackDeteceted = false;

    /**
     * Vytvorí objekt detektora a načíta fuzzy údaje zo súboru.
     * @throws Exception 
     */
    public PortScanDetector() throws Exception {
        super();
        String filename = "files/ps.fcl";
        fis = FIS.load(filename, true);
        //System.out.println("Nacital som ps.fcl subor.");

        if (fis == null) {
            throw new Exception("Fuzzy Control error: Can't load fcl file " + filename);
        }
    }

    /**
     * Vytvorí obraz štandardnej prevádzky v podobe fuzzy množín podľa naučenej maximálnej hodnoty sledovanej charakteristiky.
     * @param maxFlowCount maximálny počet tokov s rovnakými IP adresami, ale rôznými cieľovými portami
     */
    public synchronized void setLimits(int maxFlowCount) {
        int count = maxFlowCount / 3;               // 10/3          
        fis.setVariable("flowCount1", count);       // 3.33
        fis.setVariable("flowCount2", count * 2);   // 1.16
        fis.setVariable("flowCount3", maxFlowCount);// 10
        fis.setVariable("flowCount4", count * 4);   // 13
        fis.setVariable("flowCount5", count * 5);   // 16.5
    }

    /**
     * Vráti maximálnu hodnotu najpravejšej fuzzy množiny.
     * @return maximálna hodnota najpravejšej fuzzy množiny
     */
    public int getMaxFlowCount() {
        return (int) fis.getVariable("flowCount5").getValue();
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
        maxFlowCountForSetChart = this.getMaxFlowCount();
        jedis.publish("IdsPortScanAttack", "{\"time\": " + (System.currentTimeMillis() - 600000) + ",\"count\": " + maxFlowCountForSetChart + ",\"attack\": " + "false" + "}");
        //System.out.println(this + ": poslal som horne ohranicenia pre SLA web...");    
    }
    
    public void odosliNulaProbabilityPreSLA(){
        jedis.publish("IdsPortScanAttackProbability", "{\"time\": " + (System.currentTimeMillis() - 600000)+ ",\"count\": " + 0 + ",\"attack\": " + "false" + "}");
        //System.out.println(this + ": poslal som nula probability pre SLA web...");
    }
    /********************* SLA ************************/

    /**
     * Vyhodnotí roztriedenú prevádzku fuzzy podsystémom.
     * @param psSignTrafficList roztriedená prevádzka podľa charakteristík útoku typu Port Scan
     * @param reason dôvod vyhodnotenia
     */
    public void evaluate(LinkedList<PortScanSignTraffic> psSignTrafficList, int reason) {
        int flowCount;

        for (PortScanSignTraffic psSignTraffic : psSignTrafficList) {
            flowCount = psSignTraffic.getFlowCount();
            if (flowCount > maxFlowCount) {
                maxFlowCount = flowCount;
                maxTraffic = psSignTraffic;
            }
        }

        fis.setVariable("flowCount", maxFlowCount);
        fis.evaluate();
        if (maxFlowCount == 0) {
            attackProbability = 0;
        } else if (reason == Constants.AGGRES_EVAL) {
            attackProbability = 100;
        } else {
            attackProbability = fis.getVariable("traffic").getLatestDefuzzifiedValue();
        }

//        if (attackProbability <= Config.threshold) {
//            System.out.println(this + " evaluation:");
//            System.out.println(" output= " + attackProbability);
//            System.out.println(" flowCount= " + maxFlowCount);
//        }

        if (attackProbability > Config.threshold){
            attackDeteceted = true;
        }

        sendOutputToClient(maxTraffic.getTillMilis(), maxFlowCount);
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
                Logger.getLogger(PortScanDetector.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

        maxFlowCount = 0;
        attackProbability = 0;
        maxTraffic = null;
        attackDeteceted = false;
    }
    
    //private void sendOutputToClient(long time, int flowCount, double probability) {
    private void sendOutputToClient(long time, int flowCount) {
        if (isSLAWebClientConnected()) {
            //pri prvom volani nastavi cas vyhodnotenia
            if (lastEvalTime == 0) {
                lastEvalTime = time;
            }
            //v pripade, ze cas aktualneho vyhodnotenia prevadzky je mensi ako pri predoslom vyhodnotenii, upravi sa cas
            //toky od kolektora neprichadzaju v casovom poradi!!! 
            if (time <= lastEvalTime) {
                time = lastEvalTime + 10;
            }
            lastEvalTime = time;
            
            System.out.println(this + ": sending message to SLA web client");
            jedis.publish("IdsPortScanAttack", "{\"time\": " + time + ",\"count\": " + flowCount + ",\"attack\": " + attackDeteceted + "}");       
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
                time = lastEvalTime2 + 10;
            }
            lastEvalTime2 = time;
    
            System.out.println(this + ": sending message to SLA web client");
            jedis.publish("IdsPortScanAttackProbability", "{\"time\": " + time + ",\"count\": " + (int) probability + ",\"attack\": " + attackDeteceted + "}");
        } else {
            System.out.println(this + ": client nie je pripojeny.");
        }
    }
    
    private void sendMailToAdmin(){
        try {
            Application.getMessage().setText("\n"
                    + "Port scan attack detected by " + this + ". Please visit your analyzer. \n"
                    + "\n \n \n"
                    + "---------------------------------------------------------- \n"
                    + "  ATTACK details: \n"
                    + "---------------------------------------------------------- \n"
                    + "       Time since:  " + df.format(new Date(maxTraffic.getSinceMilis())) + "\n"
                    + "       Time till:  " + df.format(new Date(maxTraffic.getTillMilis())) + "\n"
                    + "       Attack probability:  " + (int) attackProbability + "%\n"
                    + "       Flow count:  " + maxFlowCount + "\n"
                    + "       Source IP:  " + maxTraffic.getSourceIP() + "\n"
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
//     * @param flowCount hodnota sledovanej charakteristiky útoku typu Port Scan
//     * @param probability pravdepodobnosť výskytu útoku
//     */
//    private void sendOutputToClient(long time, int flowCount, double probability) {
//        //pri prvom volani nastavi cas vyhodnotenia
//        if (lastEvalTime == 0) {
//            lastEvalTime = time;
//        }
//        //v pripade, ze cas aktualneho vyhodnotenia prevadzky je mensi ako pri predoslom vyhodnotenii, upravi sa cas
//        //toky od kolektora neprichadzaju v casovom poradi!!! 
//        if (time <= lastEvalTime) {
//            time = lastEvalTime + 10;
//        }
//        lastEvalTime = time;
//
//        if (server.getClient() != null) {
//            Message message = new Message();
//            message.setType(Flag.Data);
//            message.setTrafficInfo(new PortScanInfo(new Date(time), flowCount, probability));
//            if (attackProbability >= Config.threshold) {
//                message.setAttack(true);
//            }
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
        System.out.println("flowCount = " + maxFlowCount);
        System.out.println("source = " + maxTraffic.getSourceIP());
        System.out.println("destination = " + maxTraffic.getDestIP());
        System.out.println("--------------------------");

        //pri prvom detekovani utoku sa nastavi premenna criticalTraffic, aby nebola null pri dalsom porovnavani
        if (criticalTraffic == null) {
            //new attack
            //System.out.println("new attack");
            criticalTraffic = maxTraffic;
            insertAttackDataToDB();
        } else {
            if (maxTraffic.getSinceMilis() >= criticalTraffic.getTillMilis() + 5000) {
                //new attack
                //System.out.println("new attack");
                criticalTraffic = maxTraffic;
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
        String attackData = "'PortScan', " + "'" + new Timestamp(criticalTraffic.getSinceMilis()) + "'," + "'" + new Timestamp(criticalTraffic.getTillMilis()) + "'," + "'" + criticalTraffic.getDestIP() + "'," + "'" + criticalTraffic.getSourceIP() + "'," + criticalTraffic.getFlowCount() + "," + (int)attackProbability;
        String sql = "INSERT INTO public.ids_attacklogs(attacktype, starttime, endtime, destip, srcip, ps_flowcount, probability) VALUES( " + attackData + ");";
        stm.executeUpdate(sql);

        int id = 0;
        ResultSet rs = stm.executeQuery("SELECT currval('public.ids_attacklogs_id_seq');");
        if (rs.next()) {
            id = rs.getInt(1);
            criticalTraffic.setId(id);
        }
    }

    /**
     * Aktualizuje údaje o útoku v tabuľke. 
     * @throws SQLException 
     */
    private void updateAttackDataInDB() throws SQLException {
        Connection conn = database.getConn();

        //UPDATE main table - attack_logs
        String sql = "UPDATE public.ids_attacklogs SET endtime='" + new Timestamp(criticalTraffic.getTillMilis()) + "', ps_flowcount=" + criticalTraffic.getFlowCount() + ", probability=" + (int)criticalTraffic.getAttackProbability() + "WHERE id=" + criticalTraffic.getId() + ";";
        Statement stm = conn.createStatement();
        stm.executeUpdate(sql);
        //System.out.println("data updatovane");
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName();
    }

//    /**
//     * Odošle klientovi údaje o vyhodnotení nulových parametrov.
//     * @param time 
//     */
//    public void evaluateEmpty(long time) {
//        //System.out.println("empty eval");
//        sendOutputToClient(time, 0, 0);
//    }
    
    /**
     * Odošle klientovi údaje o vyhodnotení nulových parametrov.
     * @param time 
     */
    public void evaluateEmpty(long time) {
        //System.out.println("empty eval");
        sendOutputToClient(time, 0);
        sendOutputProbabilityToClient(time, 0);
    }
    
    
}
