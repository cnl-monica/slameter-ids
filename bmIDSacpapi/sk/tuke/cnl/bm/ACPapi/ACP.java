/* Copyright (C) 2013 MONICA Research Group / TUKE
 *
 * This file is part of ACPapi.
 *
 * ACPapi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.

 * ACPapi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with ACPapi; If not, see <http://www.gnu.org/licenses/>.
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
 *  Subor: ACP.java
 */


package sk.tuke.cnl.bm.ACPapi;

import sk.tuke.cnl.bm.SimpleFilter;
import org.apache.log4j.*;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Hashtable;
import java.util.concurrent.ArrayBlockingQueue;
import javax.naming.AuthenticationException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
/**
 * Trieda ktorá obsahuje metódy, umožňujúce nadviazanie spojenia s kolektorom, posielanie šablón,filtrov a typu prenosu, prijímanie a odosielanie riadiacich správ a prijímanie dát.
 * @author Adrián Pekár
 */
public class ACP extends Thread implements IACP {
    //premenná pre logovanie
    private static Logger log = Logger.getLogger(ACP.class.getName());
     
    //premenné pre nadviazanie spojenia a prenosu údajov
    Socket socket;
    InputStreamReader inStrRd;
    DataInputStream datInStr;
    BufferedInputStream buffInStr;
    OutputStreamWriter outStrWr;
    DataOutputStream datOutStr;
    ObjectOutputStream ObjOutStr;
    ObjectInputStream OInpS;
    //premenné pre kontrolu pripojenia, pozastavenie, a ukončenia prenosu/spojenia
    boolean connected = false;
    boolean finished = false;
    boolean paused = false;
    boolean isReceiving;

    
    //FIFO pre typy správ odoslaných kolektoru (podľa toho sa dekódujú návratové hodnoty)
    private ArrayBlockingQueue<Integer> sentContInfQueue = new ArrayBlockingQueue<Integer>(QUEUE_LENGTH);
    //pole intov, kde sa ukladajú id informačných elemntov zo šablóny
    int[] fieldsToReadACP = null;
    //FIFO pre filter, pre kontrolu poslaného a prijatého filtra
    private ArrayBlockingQueue<SimpleFilter> sentFilterQueue = new ArrayBlockingQueue<SimpleFilter>(QUEUE_LENGTH);
    //Hash tabuľka pre ulozenie IE z .xml súboru (Názov IE-ID IE)
    private Hashtable elements = new Hashtable();
    
    /**
     * Vytvorí nový objekt ACP
     */
    public ACP() {
        super("ACP thread");
    }

    /**
     * Metóda, ktorá slúži na zašifrovanie logina a hesla.
     * @param input Vstupný string, ktorý sa má zašiforvať.
     * @return Výstupný string v zašifrovanej MD5 podobe.
     * @throws java.security.NoSuchAlgorithmException partikulárný kryptografický algoritmus nie je voľný pre dané prostredie
     */
    public String getMd5Digest(String input) throws NoSuchAlgorithmException {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(input.getBytes());
            BigInteger number = new BigInteger(1, messageDigest);
            return number.toString(16);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage());
        }//try-catch
    }//getMd5Digest()

    /**
     * Metóda, ktorá zrealizuje pripojenie na kolektor.
     * @param host nazov hostitela, resp. IP adresa kolektora
     * @param port port, na ktorom bezi kolektor
     * @param username login s ktorym sa ma autentifikovat analyzer na vytvorenie spojenia.
     * @param password heslo s ktorym sa ma autentifikovat analyzer na vytvorenie spojenia.
     * @throws java.io.IOException vstupno/výstupná chyba. {@link java.io.OutputStream#flush OutputStream.flush}
     * @throws javax.naming.AuthenticationException neúspešná autentifikácia.
     */
    public void connectToCollector(String host, int port, String username, String password) throws AuthenticationException, IOException {

        try {
            //1. vytvorenie soketu pre spojenie s kolektorom
            socket = new Socket(host, port);                  
            log.debug("Connecting to " + host + " in port " + port + "...");
            socket.setSoTimeout(10000);
            if (socket.isConnected() == true) {
                log.info("Connection established!");
            }

            //2. získanie input a output tokov
            datInStr = new DataInputStream(socket.getInputStream());
            inStrRd = new InputStreamReader(socket.getInputStream());
            buffInStr = new BufferedInputStream(socket.getInputStream());
            outStrWr = new OutputStreamWriter(socket.getOutputStream());
            datOutStr = new DataOutputStream(socket.getOutputStream());
            ObjOutStr = new ObjectOutputStream(socket.getOutputStream());
            OInpS = new ObjectInputStream(socket.getInputStream());
            
            //3. posielanie utentifikačných údajov
            outStrWr.write(getMd5Digest(username) + "\n" + getMd5Digest(password) + "\n");
            log.info("Sending authentication data... ");
            outStrWr.flush();
            log.info("Sent.");
            
            
            //4. prijímanie odpovede na autentifikáciu
            int i = datInStr.readInt();
            log.debug("Authentication request message from collector : " + i);
            if (i == 1) {
                log.info("Authentication quarantied.");
                connected = true;
                socket.setSoTimeout(0);
            } else if (i == 0){
                throw new AuthenticationException("Wrong login or password. Authentication failed.");
            } else {
                throw new AuthenticationException("Unknown message received. Authentication failed.");
            }
//                        Object tempFilter = OInpS.readObject();
//            
//            if (tempFilter==null){
//            if (tempFilter instanceof ObjectMoj) {
//               objekt = (ObjectMoj) tempFilter;
//                    }
//            }
//            objekt.printAllValues();
        } catch (NoSuchAlgorithmException ex) {
            log.error(ex.getMessage());
        } catch (EOFException e) {
            log.error(e.getMessage());
            throw new AuthenticationException("Authentication failed.");
        }//try-catch
    }//connectToCollector()

    /**
     * Metóda, ktorá slúži na dohodnutie formátu údajov, posielané kolektorom.
     * @param fieldsToRead Polia (id atribútov), ktoré sa majú čítať zo šablóny.
     * @throws java.io.IOException vstupno/výstupná chyba.  {@link java.io.OutputStream#flush OutputStream.flush}
     * @throws java.lang.InterruptedException {@link java.util.concurrent.ArrayBlockingQueue#put ArrayBlockingQueue.put}
     */
    public void sendTemplate(int[] fieldsToRead) throws IOException, InterruptedException {
        //log.debug("--------------------TEMPLATE--------------------");
        if (fieldsToRead == null) {
            throw new NullPointerException("fieldsToRead array is set to null.");
        }
        if (!connected) {
            throw new IOException("Not connected to collector.");
        } else {
            try {
                fieldsToReadACP = fieldsToRead; //uložíme id atribútov, ktoré sa majú zo šablóny čítať
                log.info("Sending message type 0, to inform the collector, that the analyzer is going to send Template definition message.");
                datOutStr.writeInt(TEMPLATE_MSG);
                datOutStr.flush();
                log.info("Sending Template definition message to inform the collector about the required data format.");
                int a = fieldsToRead.length;
                log.debug("IPFIX Template ids:");
                //log.info(a);
                datOutStr.writeInt(a);
                for (int i = 0; i < a; i++) {
                    datOutStr.writeInt(fieldsToRead[i]);
                    log.debug(fieldsToRead[i]);
                }
                datOutStr.flush();
                
                sentContInfQueue.put(new Integer(TEMPLATE_MSG)); //uložíme kódy typov správ odoslaných kolektoru
               
            } catch (InterruptedException e) {
                log.fatal(e.getMessage());
                throw e;
            }//try-catch
        }
    }//sendTemplate()

    /**
     * Metóda, ktorá slúži na nastavenie filtra
     * @param filter údaje, ktoré sa majú posielať na vyhodnocovanie. Zatiaľ sú podporované nasledujúce kritéria : IPv4 adresa/maska meraciaho bodu, zdrojová a cieľová IPv4 adresa/maska, číslo zdrojového a cieľového portu, číslo protokolu.
     * @throws java.io.IOException vstupno/výstupná chyba.  {@link java.io.OutputStream#flush OutputStream.flush}
     * @throws java.lang.InterruptedException {@link java.util.concurrent.ArrayBlockingQueue#put ArrayBlockingQueue.put}
     */
    public void sendFilter(SimpleFilter filter) throws IOException, InterruptedException {
        //log.debug("--------------------FILTER--------------------");
        if (filter == null) {
            throw new NullPointerException("Filter rule is set to null.");
        }
        if (!connected) {
            throw new IOException("Not connected to collector.");
        } else {
            try {
                log.info("Sending message type 1, to inform the collector, that the analyzer is going to send Filter set message.");
                datOutStr.writeInt(FILTER_MSG);
                datOutStr.flush();
                log.info("Sending SimpleFilter.");
                log.debug("Sent Filter :\n" + filter);
                ObjOutStr.writeObject((Object) filter);
                ObjOutStr.flush();
                sentContInfQueue.put(new Integer(FILTER_MSG)); //uložíme kódy typov správ odoslaných kolektoru
                sentFilterQueue.put(filter); //uložíme filtre odoslané kolektoru
                
            } catch (InterruptedException e) {
                log.fatal(e.getMessage());
                throw e;
            }//try-catch
        }
    }//sendFilter()

    /**
     * Metóda, ktorá slúži na pozastavenie posielania údajov.
     * @throws java.io.IOException vstupno/výstupná chyba.  {@link java.io.OutputStream#flush OutputStream.flush}
     * @throws java.lang.InterruptedException {@link java.util.concurrent.ArrayBlockingQueue#put ArrayBlockingQueue.put}
     */
    public void sendPause() throws IOException, InterruptedException {
        //log.debug("--------------------PAUSE--------------------");
        if (!connected) {
            throw new IOException("Not connected to collector.");
        } else {
            sentContInfQueue.put(new Integer(PAUSE_MSG));//uložíme kódy typov správ odoslaných kolektoru
            datOutStr.writeInt(PAUSE_MSG);
            datOutStr.flush();
            log.info("Pause request sent!");
            }
    }//sendPause()

    /**
     * Metóda, ktorá slúži na obnovenie posielania údajov.
     * @throws java.io.IOException vstupno/výstupná chyba.  {@link java.io.OutputStream#flush OutputStream.flush}
     * @throws java.lang.InterruptedException {@link java.util.concurrent.ArrayBlockingQueue#put ArrayBlockingQueue.put}
     */
    public void sendUnPause() throws IOException, InterruptedException{
        //log.debug("--------------------UNPAUSE--------------------");
            if (!connected) {
                throw new IOException("Not connected to collector.");
            } else if (!paused) {
               log.warn("Cannot send unpause while transfer is not paused...");
            } else {
                sentContInfQueue.put(new Integer(UNPAUSE_MSG));//uložíme kódy typov správ odoslaných kolektoru
                datOutStr.writeInt(UNPAUSE_MSG);
                datOutStr.flush();
                paused = false;
                log.info("Unpause request sent!");
                
            }
    }//sendUnPause()
   
    /**
     * Metóda, ktorá umožňuje nastavenie požadovaného spôsobu posielania údajov kolektorom. Ak sa táto správa nepošle tak sa nastaví automaticky na hodnotu 1. A kollektor bude posielať údaje po n-ticiach.
     * @param TransferType typy spôsobu preposielania. <br> Zatial sú známe nasledujúce prenosy:<br>
     * 1 - One-by-N (po n-ticiach, kde n je počet nastavených šablón)<br>
     * 2 - One-by-One (po jednom)
     * @throws java.io.IOException vstupno/výstupná chyba.  {@link java.io.OutputStream#flush OutputStream.flush}
     * @throws java.lang.InterruptedException {@link java.util.concurrent.ArrayBlockingQueue#put ArrayBlockingQueue.put}
     */
//    public void sendTransferType(int TransferType) throws IOException, InterruptedException{
//        //log.debug("--------------------TRANSFER TYPE--------------------");
//        transferType = TransferType; // a mam transfertype
//            if (!connected) {
//                throw new IOException("Not connected to collector.");
//            } else if (paused) {
//               log.warn("Cannot set transfer type while transfer is paused...");
//            }
//            else {
//                datOutStr.writeInt(TRANSFER_TYPE_MSG);
//                datOutStr.writeInt(TransferType);
//                datOutStr.flush();
//                log.info("Transfer type request sent!");                
//                sentContInfQueue.put(new Integer(TRANSFER_TYPE_MSG));//uložíme kódy typov správ odoslaných kolektoru
//                
//            }
//       }//sendTransferType()

    /**
     * Metóda, ktorá slúži na správne ukončenie preposielania údajov pomocou protokolu ACP a následné ukončenie spojenia.
     */
    public void quit() {
        finished = true;
        try {
            socket.close();
            if (socket.isClosed()) {
                log.debug("Socket closed.");
            }
        } catch (IOException e) {
            log.error(e.getMessage());
        }//try-catch
    }//quit()

        
    /**
     * Metóda slúži na parsovanie elementov s XML suboru a uloženie do Hash tabuľky
     */
    public void parseElementsFromXML(){
    try {
        String xmlFile = "/etc/jxcoll/ipfixFields.xml";
        File file = new File(xmlFile);
        if(file.exists()){
         
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(xmlFile);
            NodeList list = doc.getElementsByTagName("field");
            
        for (int i=0; i<list.getLength(); i++) { 
            Node nNode = list.item(i);  
            if (nNode.getNodeType() == Node.ELEMENT_NODE) {                
            Element eElement = (Element) nNode;
            if(eElement.getAttribute("beemSupported").toString().equals("true")){
            String id = eElement.getAttribute("elementId");
            String name = eElement.getAttribute("name").toString();          
            getElements().put(name, Integer.parseInt(id));}
            }
          }  
        }else{log.debug("Súbor /etc/jxcoll/ipfixFields.xml neexistuje ");}
          }catch (Exception e) {e.printStackTrace(); System.exit(1);}
    }
    
    /**ACP
     * Metóda, ktorá slúži na čítanie odpovedí od kolektora, ktorý reaguje na riadiace správy.
     * @throws cnl.bm.acpapi.ACPException ak pri komunikácii s kolektorom príde neznáma, alebo neočakávaná správa.
     * @throws java.io.IOException vstupno/výstupná chyba.  {@link java.io.OutputStream#flush OutputStream.flush}
     */
    public void readCollectorAnswers() throws ACPException, IOException {
        //log.debug("--------------------READING COLLECTOR MESSAGES--------------------");
            int messageSentByCollector; //správa ktorú poslal kolektor
            log.debug("sprava ------"+sentContInfQueue.toString());
            int messageTypeSentByAnalyzer = sentContInfQueue.poll().intValue(); //typ odoslanej správy analyzerom, aby sa vedelo na akú správu reaguje kolektor
            log.debug("sprava ------"+messageTypeSentByAnalyzer);
            switch (messageTypeSentByAnalyzer) {
                case TEMPLATE_MSG:
                    //log.debug("--------------------READING COLLECTOR MESSAGES - TEMPLATE--------------------");
                    switch (messageSentByCollector = datInStr.readInt()) { //odpoveď, ktorá bola poslaná kolektorom
                        case 0: //ak šablóna bola odmietnutá

                            log.debug("Collector answer : " + messageSentByCollector);
                             log.error("Template rejected!");
                            throw new ACPException("Template rejected.");
                            //break;

                        case 1: //ak šablóna bola prijatá
                            log.debug("Collector answer : " + messageSentByCollector);
                            log.info("Template accepted!");
                            break;
                        case 10:
                        case 11:
                        case 20:
                        case 21:
                        case 30:
                        case 31:
                        case 40:
                        case 41:
                            throw new ACPException("This message was not expected. (" + messageSentByCollector + ")");
                        default:
                            throw new ACPException("Unknown reply message received. (" + messageSentByCollector + ")");
                    }
                    break;
                case FILTER_MSG:
                    //log.debug("--------------------READING COLLECTOR MESSAGES - FILTER--------------------");
                    switch (messageSentByCollector = datInStr.readInt()) { //odpoveď, ktorá bola poslaná kolektorom
                        case 10: // ak filter bol odmietnutý
                            log.debug("Collector answer : " + messageSentByCollector);
                            log.error("Filter rule :\n" + ((SimpleFilter) sentFilterQueue.poll()).toString() + "\nrejected!");
                            throw new ACPException("Filter rejected.");
                            //break;

                        case 11: //ak filter bol prijatý
                            log.debug("Collector answer : " + messageSentByCollector);
                            log.info("Filter rule :\n" + ((SimpleFilter) sentFilterQueue.poll()).toString() + "\naccepted!");
                            break;
                        case 0:
                        case 1:
                        case 20:
                        case 21:
                        case 30:
                        case 31:
                        case 40:
                        case 41:
                            throw new ACPException("This message was not expected. (" + messageSentByCollector + ")");
                        default:
                            throw new ACPException("Unknown reply message received. (" + messageSentByCollector + ")");
                    }
                    break;
                case PAUSE_MSG:
                    //log.debug("--------------------READING COLLECTOR MESSAGES - PAUSE--------------------");
                    switch (messageSentByCollector = datInStr.readInt()) {
                        case 20:
                            log.debug("Collector answer : " + messageSentByCollector);
                            log.error("Pause rejected!");
                            throw new ACPException("Pause rejected.");
                            //break;
                        case 21:
                            log.debug("Collector answer : " + messageSentByCollector);
                            log.info("Pause accepted!");
                            paused = true;
                            while (datInStr.available() > 0) {
                                log.debug("Reading data after pause");
                                log.debug(datInStr.readInt());
                                byte[] buff = new byte[60];
                                datInStr.read(buff);
                                log.debug("Data received : " + new String(buff));
                            }
                            break;
                        case 0:
                        case 1:
                        case 10:
                        case 11:
                        case 30:
                        case 31:
                        case 40:
                        case 41:
                            throw new ACPException("This message was not expected. (" + messageSentByCollector + ")");
                        default:
                            throw new ACPException("Unknown reply message received. (" + messageSentByCollector + ")");
                    }
                    break;
                case UNPAUSE_MSG:
                    //log.debug("--------------------READING COLLECTOR MESSAGES - UNPAUSE--------------------");
                    switch (messageSentByCollector = datInStr.readInt()) {
                        case 30:
                            log.debug("Collector answer : " + messageSentByCollector);
                            log.error("Unpause rejected!");
                            paused = true;
                            throw new ACPException("Unpause rejected.");
                            //break;
                        case 31:
                            log.debug("Collector answer : " + messageSentByCollector);
                            log.info("Unpause accepted!");
                            //paused = false;
                            break;
                        case 0:
                        case 1:
                        case 10:
                        case 11:
                        case 20:
                        case 21:
                        case 40:
                        case 41:
                            throw new ACPException("This message was not expected. (" + messageSentByCollector + ")");
                        default:
                            throw new ACPException("Unknown reply message received. (" + messageSentByCollector + ")");
                    }
                    break;
                 case 4:
                     
                       
                          
                    
                   switch (messageSentByCollector = datInStr.readInt()) {
                        case 41:  System.out.println("ukoncujem to :-)"); quit(); break; 
                        case 30:
                        case 31:
                        case 0:
                        case 1:
                        case 10:
                        case 11:
                        case 20:
                        case 21:
                        case 40:
                            throw new ACPException("This message was not expected. (" + messageSentByCollector + ")");
                        default:
                            throw new ACPException("Unknown reply message received. (" + messageSentByCollector + ")");
                    }
                    break;
//                case TRANSFER_TYPE_MSG:
//                    switch (messageSentByCollector = datInStr.readInt()) {
//                        case 40:
//                            log.error("Collector answer : " + messageSentByCollector);
//                            log.error("Unknown Transfer Type!");
//                            throw new ACPException("Unknown Transfer Type!");
//                            //break;
//                        case 41:
//                            log.debug("Collector answer : " + messageSentByCollector);
//                            if (transferType == 1) {
//                                log.info("Transfer type set to : One-by-N");
//                            }
//                            if (transferType == 2) {
//                                log.info("Transfer type set to : One-by-One");
//                            }
//                            break;
//                        case 0:
//                        case 1:
//                        case 10:
//                        case 11:
//                        case 20:
//                        case 21:
//                        case 30:
//                        case 31:
//                            throw new ACPException("This message was not expected. (" + messageSentByCollector + ")");
//                        default:
//                            throw new ACPException("Unknown reply message received. (" + messageSentByCollector + ")");
//                    }
//                    break;

                default:
                    log.fatal("Unknown message value in sentOpQueue.");
            }
    }//readCollectorAnswers()

    /**
     * Metóda pre prístup k zisteniu stavu prenosu
     * @return true/false podľa aktuálneho stavu prenosu údajov
     */
    public boolean getIsReceiving(){
        return isReceiving;
    }
    
    /**
     * Metóda pre nastavenie stavu prenosu pre správne volanie funkcie pozastavenia a obnovenia prenosu
     * @param state aktuálny stav prenosu
     */
     public void isReceiving(boolean state){
        isReceiving = state;
    }

    /**
     * Metóda pre prístup k input streamom
     * @return datInStr Prichadzajúci tok spojenia
     */
    public DataInputStream getDatInStr() {
        return datInStr;
    }//getDatInStr()
    
    /**
     * Metóda pre prístup k output streamom
     * @return datOutStr Odchadzajúci tok spojenia
     */
    public DataOutputStream getDatOutStr() {
        return datOutStr;
    }//getDatOutStr()

    public ObjectInputStream getObjectInput(){
        return OInpS;
    }
    /**
     * Metóda, ktorá slúži na zistenie aktuálneho socketu.
     * @return aktuálne otvorený socket.
     */
    public Socket getSocket() {
        return socket;
    }//getSocket()

    /**
     * Metóda, ktorá slúži na zistenie id v šablóne.
     * @return pole typu int, ktorá obsahuje id poslané kolektoru v šablóne.
     */
    public int[] getFieldsToReadACP() {
        return fieldsToReadACP;
    }//getFieldsToReadACP()

    /**
     * Metóda, ktorá slúži na zistenie stavu spojenia s kolektorom.
     * @return hodnota true/false na základe toho, či spojenie je aktívne alebo nie.
     */
    public boolean isConnected() {
        return connected;
    }//isConnected()

    /**
     * Metóda, ktorá slúži na zistenie stavu posielania údajov.
     * @return true/false na základe toho, či posielanie údajov kolektorom je pozastavené alebo aktívne.
     */
    public boolean isPaused() {
        return paused;
    }//isPaused()

    /**
     * Metóda, ktorá slúži na zistenie stavu posielania údajov.
     * @return true/false na základe toho, či posielanie údajov kolektorom je ukončené alebo aktívne.
     */
    public boolean isFinished() {
        return finished;
    }//isFinished()

//    /**
//     * Metóda, ktorá slúži na zistenie typu prenosu údajov.
//     * @return <br>
//     * 1 - One-by-N (po n-ticiach, kde n je počet nastavených šablón) - defaultne<br>
//     * 2 - One-by-One (po jednom)
//     */
//    public int getTransferType() {
//        return transferType;
//    }//getTransferType()

    /**
     * @return the elements
     */
    public Hashtable getElements() {
        return elements;
    }

}