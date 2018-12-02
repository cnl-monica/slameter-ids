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
 *  Subor: Message.java
 */
package sk.tuke.cnl.bmIDS.api;

import java.io.Serializable;

/**
 * Reprezentuje správu, do ktorej sa zapuzdrujú údaje prenášané medzi aplikáciami bmIDSanalyzer a bmIDSweb.
 * @author Martin Ujlaky
 */
public class Message implements Serializable {

    /** Typ správy.*/
    private Flag type;
    /** Objekt údajovej správy.*/
    private TrafficInfo trafficInfo;
    /** Objekt s autentifikačnými údajmi.*/
    private Authentication authentication;
    /** Objekt s údajmi o útoku.*/
    private AttackInfo attackInfo;
    /** Príznak definujúci, či správa obsahuje útok.*/
    private boolean attack = false;

    /**
     * Konštruktor pre vytvorenie objektu správy.
     */
    public Message() {
    }

    /**
     * Vráti typ správy.
     * @return typ správy
     */
    public Flag getType() {
        return type;
    }

    /** Nastaví typ správy podľa parametra.
     * 
     * @param flag flag označujúci typ správy
     */
    public void setType(Flag flag) {
        this.type = flag;
    }

    /**
     * Vráti objekt údajovej správy.
     * @return objekt údajovej správy
     */
    public TrafficInfo getTrafficInfo() {
        return trafficInfo;
    }

    /**
     * Nastaví objekt údajovej správy podľa parametra.
     * @param trafficInfo objekt údajovej správy
     */
    public void setTrafficInfo(TrafficInfo trafficInfo) {
        this.trafficInfo = trafficInfo;
    }

    /**
     * Vráti objekt správy o útoku.
     * @return objekt správy o útoku
     */
    public AttackInfo getAttackInfo() {
        return attackInfo;
    }

    /**
     * Nastaví objekt správy o útoku podľa parametra.
     * @param attackInfo objekt správy o útoku
     */
    public void setAttackInfo(AttackInfo attackInfo) {
        this.attackInfo = attackInfo;
    }

    /**
     * Vráti true, ak správa obsahuje údaje o útoku.
     * @return true, ak správa obsahuje údaje o útoku, inak false
     */
    public boolean isAttack() {
        return attack;
    }

    /**
     * Nastaví príznak, či správa obsahuje údaje o útoku.
     * @param attack príznak útoku
     */
    public void setAttack(boolean attack) {
        this.attack = attack;
    }

    /**
     * Vráti objekt autentifikačných údajov.
     * @return objekt autentifikačných údajov
     */
    public Authentication getAuthentication() {
        return authentication;
    }

    /**
     * Nastaví objekt autentifikačných údajov.
     * @param authentication objekt autentifikačných údajov
     */
    public void setAuthentication(Authentication authentication) {
        this.authentication = authentication;
    }
}
