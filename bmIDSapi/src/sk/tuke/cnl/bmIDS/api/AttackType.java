/*  Copyright (2013) Martin Ujlaky, Ladislav Berta
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
 *  Subor: AttackType.java
 */
package sk.tuke.cnl.bmIDS.api;

/**
 * Predstavuje typ útoku.
 * @author Martin Ujlaky
 */
public enum AttackType {

    /** Útok typu Port Scan.*/
    PortScan,
    /** Útok typu SYN Flood.*/
    SynFlood,
    /** Útok typu UDP Flood.*/
    UdpFlood,
    /** Útok typu RST flood.*/
    RstFlood,
    /** Útok typu TTL Expiry flood.*/
    TTLFlood,
    /** Útok typu FIN flood.*/
    FinFlood,
}
