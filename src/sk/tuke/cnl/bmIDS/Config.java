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
 *  Subor: Config.java
 */
package sk.tuke.cnl.bmIDS;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

/**
 * Obsahujúca údaje z konfiguračného súboru a metódy pre čítanie a zápis údajov z/do xml súboru.
 * @author Martin Ujlaky
 */
public abstract class Config {

    //udaje z konfiguracneho suboru config.xml
    public static String confFile = "config.xml";
    public static int listenPort = 3000;
    public static String idsUser = "bmIDS";
    public static String idsPassword = "bmIDS";
    public static int threshold = 60;
    public static String dbIP = "192.168.1.99";    //* adresa databazoveho servera postgresql(Ubuntu)
    public static int dbPort = 5432;
    public static String dbName = "bmdb";
    public static String dbLogin = "bm";
    public static String dbPassword = "bm";
    public static String acpIP = "192.168.1.99";    //* adresa kde bezi kolektor 
    public static int acpPort = 2138;
    public static String acpUser = "bm";
    public static String acpPassword = "bm";
    public static int psMaxFlowCount = 10;
    public static int sfMaxSynCount = 30;
    public static long ufMaxPacketCount = 150;
    public static int rfMaxRstCount = 25;
    public static long tfMaxTtlCount = 15;
    public static int ffMaxFinCount = 25;
    private static Document doc;
    
    //Redis
//    public static String redisIP = "127.0.0.1";
//    public static int redisPort = 6379;
    //Mail
    public static String sendMail = "false";
    public static String mailFrom = "bmidsanalyzer@gmail.com";
    public static String mailFromPwd = "1271bmIDS";
    public static String mailTo = "lacke.g@gmail.com";
    //slaweb db
    public static String slawebDbIP = "127.0.0.1";    //* adresa databazoveho servera postgresql(Ubuntu)
    public static int slawebDbPort = 5432;
    public static String slawebDbName = "slaweb";
    public static String slawebDbLogin = "slawebuser";
    public static String slawebDbPassword = "slaweb";


    /**
     * Načíta údaje z konfiguračného súboru.
     * @param file názov súboru
     */
    public static void LoadData(String file) {
        DocumentBuilderFactory dbf;
        DocumentBuilder db;

        if (file == null) {
            System.out.println("No configuration file was given.");
            System.out.println("Loading data from configuration file from it's default location: " + confFile);
        } else {
            System.out.println("Loading data from given configuration file.");
            confFile = file;
        }

        try {
            dbf = DocumentBuilderFactory.newInstance();
            db = dbf.newDocumentBuilder();
            doc = db.parse(confFile);
            FillData(doc);
        } catch (XPathExpressionException ex) {
            System.out.println(ex.getMessage());
            System.exit(1);
        } catch (SAXException ex) {
            System.out.println("Could not load configuration file:  " + file + "  !\n" + ex);
            System.exit(1);
        } catch (IOException ex) {
            System.out.println("Could not load configuration file:  " + file + "  !\n" + ex);
            System.exit(1);
        } catch (ParserConfigurationException ex) {
            System.out.println(ex.getMessage());
            System.exit(1);
        }
    }

    /**
     * Naplní tento objekt údajmi z konfiguračné súboru.
     * @param doc
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws XPathExpressionException
     * @throws IOException 
     */
    private static void FillData(Document doc) throws ParserConfigurationException, SAXException, XPathExpressionException, IOException {
        XPath xpath = XPathFactory.newInstance().newXPath();
        XPathExpression expr;

        //DB setting for learning mode
        expr = xpath.compile("//databaseSetting/ip");
        dbIP = (expr.evaluate(doc, XPathConstants.STRING)).toString().trim();
        if (!validateIP(dbIP)) {
            throw new ParserConfigurationException("Configuration file contains invalid database IP address!");
        }

        expr = xpath.compile("//databaseSetting/port");
        try {
            dbPort = new Integer(expr.evaluate(doc, XPathConstants.STRING).toString().trim());
            if (dbPort < 0 || dbPort > 65535) {
                throw new ParserConfigurationException("Configuration file contains invalid database port number");
            }
        } catch (NumberFormatException nfe) {
            throw new ParserConfigurationException("Configuration file contains invalid database port number");
        }

        expr = xpath.compile("//databaseSetting/name");
        dbName = (expr.evaluate(doc, XPathConstants.STRING)).toString();

        expr = xpath.compile("//databaseSetting/login");
        dbLogin = (expr.evaluate(doc, XPathConstants.STRING)).toString();

        expr = xpath.compile("//databaseSetting/password");
        dbPassword = (expr.evaluate(doc, XPathConstants.STRING)).toString();


        //ACP setting
        expr = xpath.compile("//acpSetting/ip");
        acpIP = (expr.evaluate(doc, XPathConstants.STRING)).toString().trim();
        if (!validateIP(acpIP)) {
            throw new ParserConfigurationException("Configuration file contains invalid acp IP address!");
        }

        expr = xpath.compile("//acpSetting/port");
        try {
            acpPort = new Integer(expr.evaluate(doc, XPathConstants.STRING).toString().trim());
            if (acpPort < 0 || acpPort > 65535) {
                throw new ParserConfigurationException("Configuration file contains invalid acp port number!");
            }
        } catch (NumberFormatException nfe) {
            throw new ParserConfigurationException("Configuration file contains invalid acp port number!");
        }

        expr = xpath.compile("//acpSetting/user");
        acpUser = (expr.evaluate(doc, XPathConstants.STRING)).toString().trim();

        expr = xpath.compile("//acpSetting/password");
        acpPassword = (expr.evaluate(doc, XPathConstants.STRING)).toString().trim();


        //IDS setting
//        expr = xpath.compile("//serverSetting/listenPort");
//        try {
//            listenPort = new Integer(expr.evaluate(doc, XPathConstants.STRING).toString().trim());
//            if (listenPort < 1024 || listenPort > 65535) {
//                throw new ParserConfigurationException("Configuration file contains invalid server listenPort value!");
//            }
//        } catch (NumberFormatException nfe) {
//            throw new ParserConfigurationException("Configuration file contains invalid server listenPort value!");
//        }
//
//        expr = xpath.compile("//serverSetting/user");
//        idsUser = (expr.evaluate(doc, XPathConstants.STRING)).toString().trim();
//
//        expr = xpath.compile("//serverSetting/password");
//        idsPassword = (expr.evaluate(doc, XPathConstants.STRING)).toString().trim();
//        idsPassword = getMd5Digest(idsPassword);


        //attack report threshold
        expr = xpath.compile("//threshold");
        try {
            threshold = new Integer(expr.evaluate(doc, XPathConstants.STRING).toString().trim());
            if (threshold < 0 || threshold > 100) {
                throw new ParserConfigurationException("Configuration file contains invalid threshold value!");
            }
        } catch (NumberFormatException nfe) {
            throw new ParserConfigurationException("Configuration file contains invalid threshold value!");
        }
        
        
        //REDIS setting
//        expr = xpath.compile("//redisSetting/ip");
//        redisIP = (expr.evaluate(doc, XPathConstants.STRING)).toString().trim();
//        if (!validateIP(redisIP)) {
//            throw new ParserConfigurationException("Configuration file contains invalid redis IP address!");
//        }
//
//        expr = xpath.compile("//redisSetting/port");
//        try {
//            redisPort = new Integer(expr.evaluate(doc, XPathConstants.STRING).toString().trim());
//            if (redisPort < 0 || redisPort > 65535) {
//                throw new ParserConfigurationException("Configuration file contains invalid redis port number!");
//            }
//        } catch (NumberFormatException nfe) {
//            throw new ParserConfigurationException("Configuration file contains invalid redis port number!");
//        }
        
        
        //MAIL setting
        expr = xpath.compile("//mailSetting/sendMail");
        try {
            sendMail = (expr.evaluate(doc, XPathConstants.STRING)).toString().trim();
            if (!("true".equals(sendMail) || "false".equals(sendMail))) {
                throw new ParserConfigurationException("Configuration file contains invalid send mail command!");
            }
        } catch (Exception e) {
            throw new ParserConfigurationException("Configuration file contains invalid send mail command!");
        }

        expr = xpath.compile("//mailSetting/mailFrom");
        try {
            mailFrom = (expr.evaluate(doc, XPathConstants.STRING)).toString().trim();
            if (!(mailFrom.contains("@"))) {
                throw new ParserConfigurationException("Configuration file contains invalid mail From address!");
            }
        } catch (NumberFormatException nfe) {
            throw new ParserConfigurationException("Configuration file contains invalid send mail From address!");
        }

        expr = xpath.compile("//mailSetting/mailFromPwd");
        mailFromPwd = (expr.evaluate(doc, XPathConstants.STRING)).toString().trim();

        expr = xpath.compile("//mailSetting/mailTo");
        try {
            mailTo = (expr.evaluate(doc, XPathConstants.STRING)).toString().trim();
            if (!(mailTo.contains("@"))) {
                throw new ParserConfigurationException("Configuration file contains invalid mail To address!");
            }
        } catch (NumberFormatException nfe) {
            throw new ParserConfigurationException("Configuration file contains invalid send mail To address!");
        }
        
  
        
        //slaweb DB setting for save attack
        expr = xpath.compile("//slawebDatabaseSetting/ip");
        slawebDbIP = (expr.evaluate(doc, XPathConstants.STRING)).toString().trim();
        if (!validateIP(slawebDbIP)) {
            throw new ParserConfigurationException("Configuration file contains invalid database IP address for slawebDB!");
        }

        expr = xpath.compile("//slawebDatabaseSetting/port");
        try {
            slawebDbPort = new Integer(expr.evaluate(doc, XPathConstants.STRING).toString().trim());
            if (slawebDbPort < 0 || slawebDbPort > 65535) {
                throw new ParserConfigurationException("Configuration file contains invalid database port number for slawebDB");
            }
        } catch (NumberFormatException nfe) {
            throw new ParserConfigurationException("Configuration file contains invalid database port number for slawebDB");
        }

        expr = xpath.compile("//slawebDatabaseSetting/name");
        slawebDbName = (expr.evaluate(doc, XPathConstants.STRING)).toString();

        expr = xpath.compile("//slawebDatabaseSetting/login");
        slawebDbLogin = (expr.evaluate(doc, XPathConstants.STRING)).toString();

        expr = xpath.compile("//slawebDatabaseSetting/password");
        slawebDbPassword = (expr.evaluate(doc, XPathConstants.STRING)).toString();

        //Standard traffic
        expr = xpath.compile("//standardTraffic/portScan/maxFlowCount");
        try {
            psMaxFlowCount = new Integer(expr.evaluate(doc, XPathConstants.STRING).toString().trim());
        } catch (NumberFormatException ex) {
            throw new ParserConfigurationException("Configuration file contains invalid port scan value!");
        }

        expr = xpath.compile("//standardTraffic/synFlood/maxSynCount");
        try {
            sfMaxSynCount = new Integer(expr.evaluate(doc, XPathConstants.STRING).toString().trim());
        } catch (NumberFormatException ex) {
            throw new ParserConfigurationException("Configuration file contains invalid syn flood value!");
        }

        expr = xpath.compile("//standardTraffic/udpFlood/maxPacketCount");
        try {
            ufMaxPacketCount = new Integer(expr.evaluate(doc, XPathConstants.STRING).toString().trim());
        } catch (NumberFormatException ex) {
            throw new ParserConfigurationException("Configuration file contains invalid udp flood value!");
        }

        expr = xpath.compile("//standardTraffic/rstFlood/maxRstCount");
        try {
            rfMaxRstCount = new Integer(expr.evaluate(doc, XPathConstants.STRING).toString().trim());
        } catch (NumberFormatException ex) {
            throw new ParserConfigurationException("Configuration file contains invalid rst flood value!");
        }

        expr = xpath.compile("//standardTraffic/ttlFlood/maxTtlCount");
        try {
            tfMaxTtlCount = new Integer(expr.evaluate(doc, XPathConstants.STRING).toString().trim());
        } catch (NumberFormatException ex) {
            throw new ParserConfigurationException("Configuration file contains invalid ttl flood value!");
        }

        expr = xpath.compile("//standardTraffic/finFlood/maxFinCount");
        try {
            ffMaxFinCount = new Integer(expr.evaluate(doc, XPathConstants.STRING).toString().trim());
        } catch (NumberFormatException ex) {
            throw new ParserConfigurationException("Configuration file contains invalid rst flood value!");
        }
    }

    /**
     * Uloží údaje do konfiguračného súboru.
     */
    public static void saveData() {
        XPath xpath = XPathFactory.newInstance().newXPath();
        Node node;
        try {
            //findNodes and make change
            node = (Node) xpath.evaluate("//standardTraffic/portScan/maxFlowCount", doc, XPathConstants.NODE);
            node.setTextContent(String.valueOf(psMaxFlowCount));
            node = (Node) xpath.evaluate("//standardTraffic/synFlood/maxSynCount", doc, XPathConstants.NODE);
            node.setTextContent(String.valueOf(sfMaxSynCount));
            node = (Node) xpath.evaluate("//standardTraffic/udpFlood/maxPacketCount", doc, XPathConstants.NODE);
            node.setTextContent(String.valueOf(ufMaxPacketCount));
            node = (Node) xpath.evaluate("//standardTraffic/rstFlood/maxRstCount", doc, XPathConstants.NODE);
            node.setTextContent(String.valueOf(rfMaxRstCount));
            node = (Node) xpath.evaluate("//standardTraffic/ttlFlood/maxTtlCount", doc, XPathConstants.NODE);
            node.setTextContent(String.valueOf(tfMaxTtlCount));
            node = (Node) xpath.evaluate("//standardTraffic/finFlood/maxFinCount", doc, XPathConstants.NODE);
            node.setTextContent(String.valueOf(ffMaxFinCount));
            // save the result
            Transformer xformer = TransformerFactory.newInstance().newTransformer();
            xformer.transform(new DOMSource(doc), new StreamResult(new File(confFile)));
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
            System.exit(1);
        }
    }

    /**
     * Overí formát IP adresy.
     * @param ipAddress reťazec IP adresy
     * @return true, ak je formát IP adresy správny, inak false
     */
    private static boolean validateIP(String ipAddress) {
        String[] parts = ipAddress.split("\\.");
        int i;

        if (parts.length != 4) {
            System.out.println(parts.length);
            System.out.println("tu?");
            return false;
        }

        for (String s : parts) {
            try {
                i = Integer.parseInt(s);
            } catch (NumberFormatException ex) {
                System.out.println("chyba");
                return false;
            }
            if ((i < 0) || (i > 255)) {
                System.out.println("zly range?");
                return false;
            }
        }

        return true;
    }

    /**
     * Vytvára hash reprezentáciu údajov konfiguračného súboru.
     * @param input vstup   
     * @return hash odtlačok vstupu
     */
    public static String getMd5Digest(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(input.getBytes());
            BigInteger number = new BigInteger(1, messageDigest);
            return number.toString(16);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }//try-catch
    }
}
