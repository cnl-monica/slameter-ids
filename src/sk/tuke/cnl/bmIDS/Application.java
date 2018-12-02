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
 *  Subor: Application.java
 */
package sk.tuke.cnl.bmIDS;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
//import java.util.List;
//import java.util.logging.Level;
//import java.util.logging.Logger;
//import org.apache.log4j.BasicConfigurator;
import sk.tuke.cnl.bm.ACPapi.ACP;
import sk.tuke.cnl.bmIDS.detector.*;
import sk.tuke.cnl.bmIDS.processor.*;
//import sk.tuke.cnl.bmIDS.web.Server;
import sk.tuke.cnl.bmIDS.web.RedisServer;

import java.util.Properties;    
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

/**
 * Hlavná trieda, spúšťa aplikáciu, inicializuje všetky jej komponenty. 
 * @author Martin Ujlaky
 */
public class Application {

    private static final String version = "2.3";
    /** Zoznam procesorov pre spracovanie tokov.*/
    private static ArrayList<TrafficProcessor> processorList;
    /** Procesor pre spracovanie tokov podľa útok typu Port Scan.*/
    private static PortScanProcessor psProcessor;
    /** Procesor pre spracovanie tokov podľa útok typu SYN Flood.*/
    private static SynFloodProcessor sfProcessor;
    /** Procesor pre spracovanie tokov podľa útok typu UDP Flood.*/
    private static UdpFloodProcessor ufProcessor;
//    /** Procesor pre spracovanie tokov podľa útok typu ACK Flood.*/
//    private static AckFloodProcessor afProcessor;
    /** Procesor pre spracovanie tokov podľa útok typu RST Flood.*/
    private static RstFloodProcessor rfProcessor;
    /** Procesor pre spracovanie tokov podľa útok typu TTL expiry Flood.*/
    private static TTLFloodProcessor tfProcessor;
    /** Procesor pre spracovanie tokov podľa útok typu FIN Flood.*/
    private static FinFloodProcessor ffProcessor;
    /** Detektor pre útok typu Port Scan.*/
    private static PortScanDetector psDetector;
    /** Detektor pre útok typu SYN Flood.*/
    private static SynFloodDetector sfDetector;
    /** Detektor pre útok typu UDP Flood.*/
    private static UdpFloodDetector ufDetector;
//    /** Detektor pre útok typu ACK Flood.*/
//    private static AckFloodDetector afDetector;
    /** Detektor pre útok typu RST Flood.*/
    private static RstFloodDetector rfDetector;
    /** Detektor pre útok typu TTL expiry Flood.*/
    private static TTLFloodDetector tfDetector;
    /** Detektor pre útok typu FIN Flood.*/
    private static FinFloodDetector ffDetector;
    /** Komponent zabezpečujúci príjem tokov od kolektora.*/
    private static IPFlowReceiver ipFlowReciever;
    /** ACP rozhranie zabezpečujúce komunikáciu s kolektorom.*/
    private static ACP acp;
    /** Objekt zabezpečujúci funkciu servera.*/
//    private static Server server;
    /** Režim programu.*/
    
    //private Jedis jedis = new Jedis("localhost");
    //private static Komunikacia komunikacia;
    
    private static int mode = Constants.DETECTION_MODE;
    //private static int mode = Constants.LEARN_MODE;
    
    //****** MAIL data ******//
    private static Message message;
    


    /**
     * Hlavná metóda, ktorá inicializuje komponenty a spúšťa detekciu.
     * @param args argumenty príkazového riadku
     */
    public static void main(String[] args) throws UnsupportedEncodingException {
//        BasicConfigurator.configure();

        //check arguments
        String configFileArg = null;
        if (args.length > 0) {
            if (args.length == 1) {
                if (args[0].equals("-l")) {
                    mode = Constants.LEARN_MODE;
                } else {
                    configFileArg = args[0];
                }
            } else if (args.length == 2) {
                if (args[0].equals("-l")) {
                    mode = Constants.LEARN_MODE;
                    configFileArg = args[1];
                } else {
                    System.out.println("Incorrect parameters!");
                    System.exit(1);
                }
            } else {
                System.out.println("Too many parameters!");
                System.exit(1);
            }
        }

        // catching ctrl+c shortcut
        Thread shutdownHook = new Thread("ShutDown Hook") {

            @Override
            public void run() {
                Application.stop();
            }
        };
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        System.out.println("Starting bmIDS v" + version);

        //load configuration xml file
        Config.LoadData(configFileArg);
        System.out.println("Data from configuration file have been successfully loaded.");
        
    /************ Vypis configuracneho suboru START *************************/
        if (mode == Constants.DETECTION_MODE) {
            System.out.println("---------------------------------------");
            System.out.println("Loaded values from config file:");
            System.out.println("threshold: " + Config.threshold);
            System.out.println("dbIP: " + Config.dbIP);
            System.out.println("dbPort: " + Config.dbPort);
            System.out.println("dbName: " + Config.dbName);
            System.out.println("dbLogin: " + Config.dbLogin);
            System.out.println("dbPassword: " + Config.dbPassword);
            System.out.println("acpIP: " + Config.acpIP);
            System.out.println("acpPort: " + Config.acpPort);
            System.out.println("acpUser: " + Config.acpUser);
            System.out.println("acpPassword: " + Config.acpPassword);
            System.out.println("psMaxFlowCount: " + Config.psMaxFlowCount);
            System.out.println("sfMaxSynCount: " + Config.sfMaxSynCount);
            System.out.println("ufMaxPacketCount: " + Config.ufMaxPacketCount);
            System.out.println("rfMaxRstCount: " + Config.rfMaxRstCount);
            System.out.println("tfMaxTtlCount: " + Config.tfMaxTtlCount);
            System.out.println("ffMaxFinCount: " + Config.ffMaxFinCount);
            System.out.println("sendMail: " + Config.sendMail);
            System.out.println("mailFrom: " + Config.mailFrom);
            System.out.println("mailFromPwd: " + Config.mailFromPwd);
            System.out.println("mailTo: " + Config.mailTo);
            System.out.println("slawebDbIP: " + Config.slawebDbIP);
            System.out.println("slawebDbPort: " + Config.slawebDbPort);
            System.out.println("slawebDbName: " + Config.slawebDbName);
            System.out.println("slawebDbLogin: " + Config.slawebDbLogin);
            System.out.println("slawebDbPassword: " + Config.slawebDbPassword);
            System.out.println("---------------------------------------");
        }
    /************ Vypis configuracneho suboru END *************************/

        //learn mode
        if (mode == Constants.LEARN_MODE) {
            System.out.println("Starting LEARN MODE.");
            try {
                Learn.start();  
                System.out.println("Finished learning.");
                //System.exit(0);
                System.out.println("Should continue with detection?[y]");
                String choice = new BufferedReader(new InputStreamReader(System.in)).readLine();
                if (choice.equals("y")) {
                    System.out.println("Starting DETECTION MODE.");
                    mode = Constants.DETECTION_MODE;
                } else {
                    System.exit(0);
                }
            } catch (Exception ex) {
                System.out.println("Learning mode: problem with database!2");
                System.out.println(ex.getMessage());
                System.exit(1);
            }
        } else {
            System.out.println("Starting DETECTION MODE.");
        }
        
        //connect to collector using acp
        acp = new ACP();
        try {
            System.out.println("Connecting to collector...");
            acp.connectToCollector(Config.acpIP, Config.acpPort, Config.acpUser, Config.acpPassword);
            System.out.println("Connection to collector is successful.");
        } catch (Exception ex) {
            System.out.println("There is problem with connection to collector: " + ex.getMessage());
            System.exit(1);
        }
      
    /************************** REDIS START **************************************/    
        //System.out.println("Creating Redis server.");
        
        try{
            RedisServer redisServer = new RedisServer();
        
            //System.out.println("Starting redis server.");
            redisServer.start();                
        } catch (Exception ex) {
            System.out.println("There is problem to start Redis server");
            System.exit(1);
        }
        
//        try{ Thread.sleep(2000);} catch (InterruptedException ex) {
//            Logger.getLogger(Application.class.getName()).log(Level.SEVERE, null, ex);
//        }              
    /************************** REDIS END **************************************/
           
        
        
        
    /************************* MAIL START **************************/
        if(Config.sendMail.equals("true")){
            System.out.println("Message sending to " + Config.mailTo + " is enabled.");

            Properties props = new Properties();
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");

            try {
                Session session = Session.getInstance(props, new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        //return new PasswordAuthentication(fromUsername, fromPassword);
                        return new PasswordAuthentication(Config.mailFrom, Config.mailFromPwd);
                    }
                });

                // Create a default MimeMessage object.
                message = new MimeMessage(session);
                // Set From: header field of the header.
                message.setFrom(new InternetAddress(Config.mailFrom));

                // Set To: header field of the header.
                message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(Config.mailTo));
                // Set Subject: header field
                message.setSubject("IDS analyzer");
                // Now set the actual message
                //message.setText("Type a message.");

//                MimeBodyPart messageBodyPart = new MimeBodyPart();
//                Multipart multipart = new MimeMultipart();
//                messageBodyPart = new MimeBodyPart();
//                String file = "ids.jpg";
//                String fileName = "attachmentName";
//                DataSource source = new FileDataSource(file);
//                messageBodyPart.setDataHandler(new DataHandler(source));
//                messageBodyPart.setFileName(fileName);
//                multipart.addBodyPart(messageBodyPart);
//                message.setContent(multipart);

//                System.out.println("Sending");
//                message.setText("Ahoj, toto je uz cez konfiguracny subor");
//                Transport.send(message);
//                System.out.println("Done");

            } catch (MessagingException e) {
                //e.printStackTrace();
                System.out.println("MessagingException:");
                System.out.println(e.getMessage());
                System.out.println("There is problem with mail server autentification. Please check config file");
                System.exit(1);
            }
        } else {
            System.out.println("Message sending to " + Config.mailTo + " is disabled.");
        }
    /************************* MAIL END **************************/
        
        
//        //initialize components  
//        server = new Server();
        try {
            psDetector = new PortScanDetector();    // nacita sa ps.fcl subor
            sfDetector = new SynFloodDetector();    // nacita sa synf.fcl subor
            ufDetector = new UdpFloodDetector();    // nacita sa udpf.fcl subor
            rfDetector = new RstFloodDetector();    // nacita sa rstf.fcl subor
            tfDetector = new TTLFloodDetector();    // nacita sa ttlf.fcl subor
            ffDetector = new FinFloodDetector();    // nacita sa finf.fcl subor
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            System.exit(1);
        }
        
        psDetector.setLimits(Config.psMaxFlowCount);    // nastavuje sa fis
        sfDetector.setLimits(Config.sfMaxSynCount);     // nastavuje sa fis
        ufDetector.setLimits(Config.ufMaxPacketCount);  // nastavuje sa fis
        rfDetector.setLimits(Config.rfMaxRstCount);
        tfDetector.setLimits(Config.tfMaxTtlCount);
        ffDetector.setLimits(Config.ffMaxFinCount);

        psProcessor = new PortScanProcessor(psDetector);
        sfProcessor = new SynFloodProcessor(sfDetector);
        ufProcessor = new UdpFloodProcessor(ufDetector);
        rfProcessor = new RstFloodProcessor(rfDetector);
        tfProcessor = new TTLFloodProcessor(tfDetector);
        ffProcessor = new FinFloodProcessor(ffDetector);
        
        processorList = new ArrayList<TrafficProcessor>();
        processorList.add(psProcessor);
        processorList.add(sfProcessor);
        processorList.add(ufProcessor);
        processorList.add(rfProcessor);
        processorList.add(tfProcessor);
        processorList.add(ffProcessor);
        
        ipFlowReciever = new IPFlowReceiver(acp, processorList);

        //start detection
        psProcessor.start();
        sfProcessor.start();
        ufProcessor.start();
        rfProcessor.start();
        tfProcessor.start();
        ffProcessor.start();
        
        ipFlowReciever.start();
        
              
        //start server waiting for connections
        //server.start();


}


    /**
     * Ukončuje detekciu, všetky vlákna.
     */
    public static void stop() {
        System.out.println("\n");
        //stop reciever           
        if (ipFlowReciever != null && ipFlowReciever.isAlive()) {
            System.out.println("Shutting down " + ipFlowReciever + " thread..");
            ipFlowReciever.interrupt();
            try {
                ipFlowReciever.join();
                System.out.println(ipFlowReciever + " is finished.");
            } catch (InterruptedException ex) {
                System.out.println(ex.getMessage());
            }
        }
        //stop all processors
        if (processorList != null) {
            for (TrafficProcessor processor : processorList) {
                if (processor != null && processor.isAlive()) {
                    System.out.println("Shutting down " + processor.getClass().getSimpleName() + " thread..");
                    processor.interrupt();
                    try {
                        processor.join();
                        System.out.println(processor.getClass().getSimpleName() + " is finished.");
                    } catch (InterruptedException ex) {
                        System.out.println(ex.getMessage());
                    }
                }
            }
        }
        //stop server
//        if (server != null && server.isAlive()) {
//            System.out.println("Shutting down " + server + " thread..");
//            try {
//                server.getServerSocket().close();
//            } catch (IOException ex) {
//                System.out.println(ex.getMessage());
//            }
//            try {
//                server.join();
//                System.out.println(server + " is finished.");
//            } catch (InterruptedException ex) {
//                System.out.println(ex.getMessage());
//            }
//        }
        
        //jedis.close();
        System.out.println("bmIDS stopped.");
        //Runtime.getRuntime().halt(0);
    }

    /**
     * Vráti aktuálny režim programu.
     * @return aktuálny režim programu [učenie|detekcia]
     */
    public static int getMode() {
        return mode;
    }

    /**
     * Vráti detektor pre útok typu Port Scan.
     * @return detektor pre útok typu Port Scan
     */
    public static PortScanDetector getPsDetector() {
        return psDetector;
    }

    /**
     * Vráti detektor pre útok typu SYN Flood.
     * @return detektor pre útok typu SYN Flood
     */
    public static SynFloodDetector getSfDetector() {
        return sfDetector;
    }

    /**
     * Vráti detektor pre útok typu UDP Flood.
     * @return detektor pre útok typu UDP Flood
     */
    public static UdpFloodDetector getUfDetector() {
        return ufDetector;
    }
    
    /**
     * Vráti detektor pre útok typu RST Flood.
     * @return detektor pre útok typu RST Flood
     */
    public static RstFloodDetector getRfDetector() {
        return rfDetector;
    }
    
    /**
     * Vráti detektor pre útok typu TTL expiry Flood.
     * @return detektor pre útok typu TTL expiry Flood
     */
    public static TTLFloodDetector getTfDetector() {
        return tfDetector;
    }
    
    /**
     * Vráti detektor pre útok typu FIN Flood.
     * @return detektor pre útok typu FIN Flood
     */
    public static FinFloodDetector getFfDetector() {
        return ffDetector;
    }

//    /**
//     * Vráti objekt zabezpečujúci funkciu servera.
//     * @return objekt zabezpečujúci funkciu servera
//     */
//    public static Server getServer() {
//        return server;
//    }
    
//    /**
//     * Vráti objekt zabezpečujúci funkciu REDIS servera.
//     * @return objekt zabezpečujúci funkciu REDIS servera
//     */
//    public static Komunikacia getKomunikacia() {
//        return komunikacia;
//    }
    
    /**
     * Vráti objekt spravy pre poslanie mailu.
     * @return objekt spravy pre poslanie mailu
     */
    public static Message getMessage() {
        return message;
    }
}


