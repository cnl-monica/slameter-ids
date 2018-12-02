/* Copyright (C) 2013 MONICA Research Group / TUKE
*
* This file is part of JXColl.
*
* JXColl is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 3 of the License, or
* (at your option) any later version.

* JXColl is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.

* You should have received a copy of the GNU General Public License
* along with JXColl; If not, see <http://www.gnu.org/licenses/>.
*/

package sk.tuke.cnl.bm;


/**
 * Vzniká, ak pravidlo filtra nemá požadovaný formát.
 */
public class InvalidFilterRuleException extends java.lang.Exception {
  
  /**
   * Vytvorí novú inštanciu <code>InvalidFiterRuleException</code> bez detailnejšieho popisu.
   */
  public InvalidFilterRuleException() {
  } //InvalidFilterRuleException()
  
  /**
   * Vytvorí inštanciu <code>InvalidFilterRuleException</code> so špecifikovaným popisom.
   * @param msg popis
   */
  public InvalidFilterRuleException(String msg) {
    super(msg);
  } //InvalidFilterRuleException()
  
} //InvalidFilterRuleException