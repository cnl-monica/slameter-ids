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
 *  Zdrojove texty:
 *  Subor: ACPException.java
 */


/**
 * Trieda reprezentujúca informačné elementy priamym pripojenim
 * @author Adrián Pekár
 */


package sk.tuke.cnl.bm.ACPapi;


/**
 * Vzniká, ak pri komunikácii s kolektorom príde neznáma, alebo neočakávaná správa.
 */
public class ACPException extends java.lang.Exception {
  
  /**
   * Vytvorí novú inštanciu <code>ACPException</code> bez detailnejšieho popisu.
   */
  public ACPException() {
  }
  
  
  /**
   * Vytvorí inštanciu <code>ACPException</code> so špecifikovaným popisom.
   * @param msg popis
   */
  public ACPException(String msg) {
    super(msg);
  }
}
