/*  Copyright (2012) Martin Ujlaky.
 *  This file is part of bmIDSapi.
 *  bmIDSapi is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  bmIDSapi is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with bmIDSapi.  If not, see <http://www.gnu.org/licenses/>.
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
 *  Subor: Authentication.java
 */
package sk.tuke.cnl.bmIDS.api;

import java.io.Serializable;

/**
 * Objekt tejto triedy obsahuje autentifikačné údaje pre pripojenie aplikácie bmIDSweb k aplikácii bmIDSanalyzer.
 * @author Martin Ujlaky
 */
public class Authentication implements Serializable {

    /** meno používateľa*/
    private String user;
    /** heslo používateľa*/
    private String password;
    /** príznak výsledku autentifikačného procesu*/
    private boolean authenticated = false;

    /**
     * Konštruktor pre vytvorenie objektu autentifikačných údajov.
     * @param user meno používateľa
     * @param password heslo používateľa
     */
    public Authentication(String user, String password) {
        this.user = user;
        this.password = password;
    }

    /**
     * Vráti true, ak je autentifikácia úspešná.
     * @return true, ak je autentifikácia úspešná, inak false
     */
    public boolean isAuthenticated() {
        return authenticated;
    }

    /**
     * Nastaví príznak výsledku autentifikačného procesu podľa parametra.
     * @param authenticated príznak výsledku autentifikačného procesu
     */
    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }

    /**
     * Vráti heslo používateľa. 
     * @return heslo používateľa
     */
    public String getPassword() {
        return password;
    }

    /**
     * Nastaví heslo používateľa podľa parametra.
     * @param password heslo používateľ
     */
    public void setPassword(String password) {
        this.password = password;
    }

    /**
     * Vráti meno používateľa. 
     * @return meno používateľa. 
     */
    public String getUser() {
        return user;
    }

    /**
     * Nastaví meno používateľa podľa parametra. 
     * @param user meno používateľa
     */
    public void setUser(String user) {
        this.user = user;
    }
}
