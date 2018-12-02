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
 *  Subor: DBClient.java
 */
package sk.tuke.cnl.bmIDS;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Zabezpečuje spojenie s databázou. 
 * @author Martin Ujlaky
 */
public class DBClient {

    /** Spojenie s databázou.*/
    private Connection conn;
    
// SLAweb
    private Connection slawebConn;

    /**
     * Konštruktor.
     */
    public DBClient() {
        try {
            Class.forName("org.postgresql.Driver");
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(DBClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

//    /**
//     * Vytvorí spojenie s databázou.
//     */
//    public void connect() {
//        try {
//            String url = "jdbc:postgresql://" + Config.dbIP + ":" + Config.dbPort + "/" + Config.dbName;
//            conn = DriverManager.getConnection(url, Config.dbLogin, Config.dbPassword);
//        } catch (SQLException ex) {
//            Logger.getLogger(DBClient.class.getName()).log(Level.SEVERE, null, ex);
//        }
//    }

    /**
     * Vytvorí spojenie s slaweb databázou.
     */
    public void connect() {
        try {
            String url = "jdbc:postgresql://" + Config.slawebDbIP + ":" + Config.slawebDbPort + "/" + Config.slawebDbName;
            conn = DriverManager.getConnection(url, Config.slawebDbLogin, Config.slawebDbPassword);
        } catch (SQLException ex) {
            Logger.getLogger(DBClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * Ukončí spojenie s databázou.
     */
    public void disconnect() {
        try {
            conn.close();
        } catch (SQLException ex) {
            Logger.getLogger(DBClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Testuje spojenie s databázou.
     * @return true, ak je spojenie úspešne vytvorené, inak false
     */
    public boolean isConnected() {
        if (conn != null) {
            try {
                if (conn.isClosed()) {
                    return false;
                } else {
                    return true;
                }
            } catch (SQLException ex) {
                Logger.getLogger(DBClient.class.getName()).log(Level.SEVERE, null, ex);
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Vráti spojenie k databáze.
     * @return pojenie k databáze
     */
    public Connection getConn() {
        if (!isConnected()) {
            connect();
        }
        return conn;
    }
}
