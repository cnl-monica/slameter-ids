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
 *  Subor: AttackInfo.java
 */
//temporary not used
package sk.tuke.cnl.bmIDS.api;

import java.io.Serializable;
import java.util.LinkedList;
import java.util.Date;

/**
 * Reprezentuje údaje o útoku.
 * @author MartinUjlaky
 */
public class AttackInfo implements Serializable {

    private AttackType attackType;
    private Date time;
    private String destIP;
    private String srcIP;
    private LinkedList<String> sourceIPList;

    public AttackInfo(AttackType attackType, Date time, String destIP) {
        this.attackType = attackType;
        this.time = time;
        this.destIP = destIP;
    }

    public AttackInfo(AttackType attackType, Date time, String destIP, String srcIP) {
        this(attackType, time, destIP);
        this.srcIP = srcIP;
    }

    public AttackInfo(AttackType attackType, Date time, String destIP, LinkedList<String> sourceIPList) {
        this(attackType, time, destIP);
        this.sourceIPList = sourceIPList;
    }

    public AttackType getAttackType() {
        return attackType;
    }

    public String getDestIP() {
        return destIP;
    }

    public String getSrcIP() {
        return srcIP;
    }

    public LinkedList<String> getSourceIPList() {
        return sourceIPList;
    }

    public Date getTime() {
        return time;
    }
}
