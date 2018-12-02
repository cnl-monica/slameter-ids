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
 *  Subor: FuzzyDetector.java
 */
package sk.tuke.cnl.bmIDS.detector;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import redis.clients.jedis.Jedis;
import sk.tuke.cnl.bmIDS.Application;
import sk.tuke.cnl.bmIDS.Config;
import sk.tuke.cnl.bmIDS.DBClient;

/**
 * Abstraktná trieda pre všetky detektory. 
 * @author Martin Ujlaky
 */
public abstract class FuzzyDetector {

//    /** Objekt zabezpečujúci funkciu servera.*/
//    protected static Server server;
    /** Objekt zabezpečujúci prístup k databáze.*/
    protected static DBClient database;
    /** Príznak, či je pripojená webová aplikácia.*/
    protected boolean webClientConnected = false;
    
    /** Príznak, či je pripojená SLA webová aplikácia.*/
    protected boolean webSLAclientConnected = false;
    
    protected static Jedis jedis;
    
    //zatial, iba pre vypisy na konzolu
    protected static DateFormat df = new SimpleDateFormat("dd.MM.yy hh:mm:ss");

    /**
     * Vytvorí objekt detektora.
     */
    public FuzzyDetector() {
        database = new DBClient();
        //jedis = new Jedis("localhost");
        //jedis = new Jedis(Config.redisIP, Config.redisPort);
        jedis = new Jedis("localhost", 6379, 180);
    }
}
