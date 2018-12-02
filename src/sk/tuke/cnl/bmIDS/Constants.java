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
 *  Subor: Constants.java
 */
package sk.tuke.cnl.bmIDS;

/**
 * Spoločné konštanty používané v programe.
 * @author Martin Ujlaky
 */
public interface Constants {

    /** Režim učenia.*/
    public static final int LEARN_MODE = 0;
    /** Režim detekcie.*/
    public static final int DETECTION_MODE = 1;
    /** Režim normalného vyhodnocovania.*/
    public static final int NORMAL_EVAL = 0;
    /** Režim rýchlejšieho vyhodnocovania.*/
    public static final int AGGRES_EVAL = 1;
}
