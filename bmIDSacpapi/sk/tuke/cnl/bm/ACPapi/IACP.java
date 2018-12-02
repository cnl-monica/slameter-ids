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
 *  Subor: IACP.java
 */









package sk.tuke.cnl.bm.ACPapi;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import sk.tuke.cnl.bm.SimpleFilter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.Hashtable;
import javax.naming.AuthenticationException;

/**
 * Rozhranie reprezentujúce deklaraciu metód aplikačného rozhrania, a konštant riadiacich správ protokolu ACP
 * @author Adrián Pekár
 */
public interface IACP {
    //implicitne su public static final ...
    //Protokolom ACP sa posielajú dve typy správ. Tieto správy sú dátove a riadiace.

    /**
     * Riadiaca správa protokolu ACP.
     * COL_ANSW_MSG je správa poslaná kolektorom, ktorá naznačuje, že sa bude posielať odpoveď na riadiacu správu
     */
    int COL_ANSWER_MSG = 1;
    //
    
    /**
     * Riadiaca správa protokolu ACP.
     * COL_DATA_MSG je spravá poslaná kolektorom, ktorá naznačuje, že sa budú posielať dáta
     */
    int COL_DATA_MSG = 0;
    //

    /**
     * Riadiaca správa protokolu ACP.
     * Správa, ktorá naznačuje, že sa bude posielať šablóna
     */
    int TEMPLATE_MSG = 0;
    //
    /**
     * Riadiaca správa protokolu ACP.
     * Správa, ktorá naznačuje, že sa bude posielať filter
     */
    int FILTER_MSG = 1;
    //
    /**
     * Riadiaca správa protokolu ACP.
     * Správa, ktorá oznamuje kolektoru žiadosť pozastavenia posielania údajov.
     */
    int PAUSE_MSG = 2;
    //
    /**
     * Riadiaca správa protokolu ACP.
     * Správa, ktorá oznamuje kolektoru žiadosť obnovy posielania údajov.
     */
    int UNPAUSE_MSG = 3;
    
    //
    /**
     * Riadiaca správa protokolu ACP.
     * Správa, ktorá oznamuje kolektoru akým spôsobom ma posielať požadované údaje.
     * Zatial sú známe nasledujúce prenosy:
     * 1 - One-by-N (po jednom)
     * 2 - One-by-One (po n-ticiach, kde n je počet nastavených šablón)
     */
    //int TRANSFER_TYPE_MSG = 4;
    //

    /**
     * Riadiaca správa protokolu ACP.
     * Správa, ktorá potvrdzuje príjem dát od Kolektora.
     */
    int COL_DATA_RECEIVED = 5;
    //

    /**
     * Dĺžka FIFO, podľa ktorej sa ukladajú riadiace správy alebo filtračné kritéria.
     */
    int QUEUE_LENGTH = 8;
    //

    /* Metóda, ktorá slúži na zašifrovanie logina a hesla.*/
    String getMd5Digest(String input) throws NoSuchAlgorithmException;
    
    /* Metóda, ktorá zrealizuje pripojenie na kolektor.*/
    void connectToCollector(String host, int port, String username, String password) throws AuthenticationException, IOException;

    /* Metóda, ktorá slúži na dohodnutie formátu údajov, posielané kolektorom.*/
    void sendTemplate(int[] fieldsToRead) throws IOException, InterruptedException ;

    /* Metóda, ktorá slúži na nastavenie filtra*/
    void sendFilter(SimpleFilter filter) throws IOException, InterruptedException;

    /* Metóda, ktorá slúži na pozastavenie posielania údajov.*/
    void sendPause() throws IOException, InterruptedException;

    /* Metóda, ktorá slúži na obnovenie posielania údajov.*/
    void sendUnPause() throws IOException, InterruptedException;

     /* Metóda, ktorá slúži na oznámenie spôsoby prijímania údajov posielané kolektorom.*/
    //void sendTransferType(int TransferType) throws IOException, InterruptedException;

    /* Metóda, ktorá slúži na čítanie správ, poslaných kolektorom.*/
    void readCollectorAnswers() throws IOException, ACPException;

    /* Metóda, ktorá slúži na správne ukončenie preposielania údajov pomocou protokolu ACP.*/
    void quit();
     
    /*Metóda pre prístup k zisteniu stavu prenosu*/
    public boolean getIsReceiving();

    /*Metóda pre nastavenie stavu prenosu pre správne volanie funkcie pozastavenia a obnovenia prenosu*/
    void isReceiving(boolean state);

    /* Metóda pre prístup k input streamom*/
    DataInputStream getDatInStr();
    
    /*Metóda pre prístup k output streamom*/
    DataOutputStream getDatOutStr();

    /*Metóda pre prístup k input object streamu*/
    ObjectInputStream getObjectInput();
            
    /*Metóda, ktorá slúži na zistenie aktuálneho socketu.*/
    Socket getSocket();

    /* Metóda, ktorá slúži na zistenie id v šablóne.*/
    int[] getFieldsToReadACP();

    /* Metóda, ktorá slúži na zistenie stavu spojenia s kolektorom.*/
    boolean isConnected();

    /* Metóda, ktorá slúži na zistenie stavu posielania údajov.*/
    boolean isPaused();

    /* Metóda, ktorá slúži na zistenie stavu posielania údajov.*/
    boolean isFinished();
    
     /* Metóda, ktorá slúži na parsovanie a uloženie IE do hašovacej tabuľky.*/
    void parseElementsFromXML();
    
    /* Metóda, ktorá slúži na ziskanie podporovaných IE v hašovacej tabuľke.*/
    Hashtable getElements();
    
//    /* Metóda, ktorá slúži na zistenie typu prenosu údajov.*/
//    int getTransferType();

}
