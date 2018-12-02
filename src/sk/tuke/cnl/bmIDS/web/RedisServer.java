/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.tuke.cnl.bmIDS.web;
import java.util.logging.Level;
import java.util.logging.Logger;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPubSub;
import redis.clients.jedis.exceptions.JedisConnectionException;
import sk.tuke.cnl.bmIDS.Application;
import sk.tuke.cnl.bmIDS.Config;
/**
 *
 * @author lacke
 */

public class RedisServer extends Thread {
//public class RedisServer implements Runnable {
    
    //private final Jedis jedis = new Jedis("localhost", 6379);
    private final Jedis jedis = new Jedis("127.0.0.1", 6379);
    //private final Jedis jedis = new Jedis(Config.redisIP, Config.redisPort);
            
    public RedisServer(){
        //System.out.println("Redis server succesfully created.");
    }
    
    @Override
    public void run() {
        try {
            System.out.println("Redis server running...");
            //citam z kanala IDS prichadzajuce spravy
            jedis.subscribe(new JedisPubSubImpl(), "IDS");
        } catch (JedisConnectionException ex) {
            System.out.println("Redis: " + ex);
            jedis.close();
            System.exit(1);
        }
    }
    
private class JedisPubSubImpl extends JedisPubSub {

        public JedisPubSubImpl() {
            //System.out.println("Redis server waiting for incoming messages...");
        }

        @Override
        public void onMessage(String arg0, String arg1) {
            //ked pride stop na kanal, nastavia sa detektory
            if (arg1.endsWith("stop")) {
//                System.out.println("  JEDIS_PUB/SUB: Dostal som spravu: STOP");
//                if (arg1.startsWith("IdsSynFloodAttack")) {
//                    System.out.println("  JEDIS_PUB/SUB: Dostal som to od SynFloodAttack modulu SLA");
//                    Application.getSfDetector().setSLAWebClientConnected(false);
//                } else if (arg1.startsWith("IdsUdpFloodAttack")) {
//                    System.out.println("  JEDIS_PUB/SUB: Dostal som to od UdpFloodAttack modulu SLA");
//                    Application.getUfDetector().setSLAWebClientConnected(false);
//                } else if (arg1.startsWith("IdsPortScanAttack")) {
//                    System.out.println("  JEDIS_PUB/SUB: Dostal som to od PortScanAttack modulu SLA");
//                    Application.getPsDetector().setSLAWebClientConnected(false);
//                } else if (arg1.startsWith("IdsRstFloodAttack")) {
//                    System.out.println("  JEDIS_PUB/SUB: Dostal som to od RstFloodAttack modulu SLA");
//                    Application.getRfDetector().setSLAWebClientConnected(false);
//                } else if (arg1.startsWith("IdsTtlFloodAttack")) {
//                    System.out.println("  JEDIS_PUB/SUB: Dostal som to od TtlFloodAttack modulu SLA");
//                    Application.getTfDetector().setSLAWebClientConnected(false);
//                } else if (arg1.startsWith("IdsFinFloodAttack")) {
//                    System.out.println("  JEDIS_PUB/SUB: Dostal som to od FinFloodAttack modulu SLA");
//                    Application.getFfDetector().setSLAWebClientConnected(false);
//                }
            //ked pride start, nastavia sa detektory a zacnu posielat vyhodnotene data
            } else if (arg1.endsWith("start")) {

                //System.out.println("  JEDIS_PUB/SUB: Dostal som spravu: START");
                if (arg1.startsWith("IdsSynFloodAttack")) {
                    try{ Thread.sleep(50);} catch (InterruptedException ex) {
                        Logger.getLogger(Application.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    //System.out.println("  JEDIS_PUB/SUB: Dostal som to od SynFloodAttack modulu SLA");
                    Application.getSfDetector().setSLAWebClientConnected(true);
                    Application.getSfDetector().odosliOhraniceniaPreSLA();
                    Application.getSfDetector().odosliNulaProbabilityPreSLA();
                    try{ Thread.sleep(50);} catch (InterruptedException ex) {
                        Logger.getLogger(Application.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    
                } else if (arg1.startsWith("IdsUdpFloodAttack")) {
                    //System.out.println("  JEDIS_PUB/SUB: Dostal som to od UdpFloodAttack modulu SLA");
                    Application.getUfDetector().setSLAWebClientConnected(true);
                    Application.getUfDetector().odosliOhraniceniaPreSLA();
                    Application.getUfDetector().odosliNulaProbabilityPreSLA();
                    try{ Thread.sleep(50);} catch (InterruptedException ex) {
                        Logger.getLogger(Application.class.getName()).log(Level.SEVERE, null, ex);
                    }

                }
                else if (arg1.startsWith("IdsPortScanAttack")) {
                    //System.out.println("  JEDIS_PUB/SUB: Dostal som to od PortScanAttack modulu SLA");
                    Application.getPsDetector().setSLAWebClientConnected(true);
                    Application.getPsDetector().odosliOhraniceniaPreSLA();
                    Application.getPsDetector().odosliNulaProbabilityPreSLA();
                    try{ Thread.sleep(50);} catch (InterruptedException ex) {
                        Logger.getLogger(Application.class.getName()).log(Level.SEVERE, null, ex);
                    }

                } else if (arg1.startsWith("IdsRstFloodAttack")) {
                    //System.out.println("  JEDIS_PUB/SUB: Dostal som to od RstFloodAttack modulu SLA");
                    Application.getRfDetector().setSLAWebClientConnected(true);
                    Application.getRfDetector().odosliOhraniceniaPreSLA();
                    Application.getRfDetector().odosliNulaProbabilityPreSLA();
                    try{ Thread.sleep(50);} catch (InterruptedException ex) {
                        Logger.getLogger(Application.class.getName()).log(Level.SEVERE, null, ex);
                    }

                } else if (arg1.startsWith("IdsTtlFloodAttack")) {
                    //System.out.println("  JEDIS_PUB/SUB: Dostal som to od UdpFloodAttack modulu SLA");
                    Application.getTfDetector().setSLAWebClientConnected(true);
                    Application.getTfDetector().odosliOhraniceniaPreSLA();
                    Application.getTfDetector().odosliNulaProbabilityPreSLA();
                    try{ Thread.sleep(50);} catch (InterruptedException ex) {
                        Logger.getLogger(Application.class.getName()).log(Level.SEVERE, null, ex);
                    }

                } else if (arg1.startsWith("IdsFinFloodAttack")) {
                    //System.out.println("  JEDIS_PUB/SUB: Dostal som to od FinFloodAttack modulu SLA");
                    Application.getFfDetector().setSLAWebClientConnected(true);
                    Application.getFfDetector().odosliOhraniceniaPreSLA();
                    Application.getFfDetector().odosliNulaProbabilityPreSLA();
                    try{ Thread.sleep(50);} catch (InterruptedException ex) {
                        Logger.getLogger(Application.class.getName()).log(Level.SEVERE, null, ex);
                    }

                }
                //else {System.out.println("  JEDIS_PUB/SUB: Dostal som spravu od SLA :)");}
            }
        }

        @Override
        public void onPMessage(String arg0, String arg1, String arg2) {
        }

        @Override
        public void onSubscribe(String arg0, int arg1) {
            //throw new UnsupportedOperationException("Not supported yet."); 
        }

        @Override
        public void onUnsubscribe(String arg0, int arg1) {
            //throw new UnsupportedOperationException("Not supported yet."); 
        }

        @Override
        public void onPUnsubscribe(String arg0, int arg1) {
            //throw new UnsupportedOperationException("Not supported yet."); 
        }

        @Override
        public void onPSubscribe(String arg0, int arg1) {
            //throw new UnsupportedOperationException("Not supported yet."); 
        }
    }    
}
