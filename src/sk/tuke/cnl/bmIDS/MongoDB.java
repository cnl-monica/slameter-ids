/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.tuke.cnl.bmIDS;

import com.mongodb.MongoClient;
import com.mongodb.MongoException;
import com.mongodb.WriteConcern;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.BasicDBObject;
import com.mongodb.DBObject;
import com.mongodb.DBCursor;
import com.mongodb.ServerAddress;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;
import org.bson.types.ObjectId;

/**
 *
 * @author lacke
 */
//public class MongoDBJDBC{
public class MongoDB {
    
    //private String myUserName = "ahoj";
    //private String myPassword = "ahoj";
   
    public static void main( String args[] ){
    //public MongoDB(){
        
        try{   
            // To connect to mongodb server
            MongoClient mongoClient = new MongoClient( "localhost" , 27017 );
            // Now connect to your databases
            DB db = mongoClient.getDB( "bmIDS" );
            System.out.println("Connect to database successfully");
            boolean auth = db.authenticate("bmIDS", "bmIDS".toCharArray());
            System.out.println("Authentication: " + auth);

            
            if(db.getCollection("attack_logs") == null){
                //DBCollection coll = db.createCollection("mycol", new BasicDBObject()); //db.createCollection("mycol");
                //DBCollection coll_1 = db.createCollection("attack_logs", new BasicDBObject());
                db.createCollection("attack_logs", new BasicDBObject());
                System.out.println("Collection attack_logs created successfully");
            } else {
                System.out.println("Collection attack_logs already exist");
            }
            
            if(db.getCollection("attack_details") == null){
                //DBCollection coll_2 = db.createCollection("attack_details", new BasicDBObject());
                db.createCollection("attack_details", new BasicDBObject());
                System.out.println("Collection attack_details created successfully");
            } else {
                System.out.println("Collection attack_details already exist");
            }
            

            //DBCollection coll = db.getCollection("mycol");
            DBCollection attackLogs;
            if((attackLogs = db.getCollection("attack_logs")) != null){
                System.out.println("Collection attack_logs selected successfully");
            
                BasicDBObject docAttackLogs = new BasicDBObject("attacktype", "SYN flood").
                                                append("starttime", new Date(System.currentTimeMillis())).
                                                append("endtime", new Date(System.currentTimeMillis())).
                                                append("destip", "192.168.4.231").
                                                append("srcip", "157.589.64.357").
                                                append("destport", 2356).
                                                append("ps_flowcount", "NULL").
                                                append("sf_syncount", 15).
                                                append("uf_packetcount", "NULL").
                                                append("rf_rstcount", "NULL").
                                                append("tf_ttlcount", "NULL").
                                                append("ff_fincount", "NULL").
                                                append("probability", 60.0);
                attackLogs.insert(docAttackLogs);
                System.out.println("Document inserted successfully");
                        
            
                DBCollection attackDetails;
                if((attackDetails = db.getCollection("attack_details")) != null){
                    System.out.println("Collection attack_details selected successfully");

                    BasicDBObject docAttackDetails = new BasicDBObject("attack_id", (ObjectId)docAttackLogs.get( "_id" )).
                                                    append("since", new Date(System.currentTimeMillis())).
                                                    append("till", new Date(System.currentTimeMillis())).
                                                    append("probability", 75.0).
                                                    append("sf_syncount", 26).
                                                    append("uf_packetcount", "NULL").
                                                    append("rf_rstcount", "NULL").
                                                    append("tf_ttlcount", "NULL").
                                                    append("ff_fincount", "NULL");
                    attackDetails.insert(docAttackDetails);

//                    ObjectId id = (ObjectId)docAttackDetails.get( "_id" );
//                    System.out.println("Object ID is: " + id);
                    System.out.println("Document inserted successfully.");
                }
            }
            
            
//            
//            DBCollection attackLogs;
//            if((attackLogs = db.getCollection("attack_logs")) != null){
//                System.out.println("Collection attack_logs selected successfully");
//            
//                BasicDBObject doc = new BasicDBObject("attacktype", "NULL").
//                                                append("starttime", "NULL").
//                                                append("endtime", "NULL").
//                                                append("destip", "NULL").
//                                                append("srcip", "NULL").
//                                                append("destport", "NULL").
//                                                append("ps_flowcount", "NULL").
//                                                append("sf_syncount", "NULL").
//                                                append("uf_packetcount", "NULL").
//                                                append("rf_rstcount", "NULL").
//                                                append("tf_ttlcount", "NULL").
//                                                append("ff_fincount", "NULL").
//                                                append("probability", "NULL");
//                attackLogs.insert(doc);
//                System.out.println("Document inserted successfully");
//            }
//            
//            
//            DBCollection attackDetails;
//            if((attackDetails = db.getCollection("attack_details")) != null){
//                System.out.println("Collection attack_details selected successfully");
//            
//                BasicDBObject doc = new BasicDBObject("attack_id", "NULL").
//                                                append("since", "NULL").
//                                                append("till", "NULL").
//                                                append("probability", "NULL").
//                                                append("sf_syncount", "NULL").
//                                                append("uf_packetcount", "NULL").
//                                                append("rf_rstcount", "NULL").
//                                                append("tf_ttlcount", "NULL").
//                                                append("ff_fincount", "NULL");
//                attackDetails.insert(doc);
//
//                ObjectId id = (ObjectId)doc.get( "_id" );
//                System.out.println("Object ID is: " + id);
//                System.out.println("Document inserted successfully.");
//            }
//
//            try {
//                synchronized(mongoClient){
//                    System.out.println("Object ID is: ");
//                }
//            } catch (MongoException ex){
//                System.out.println("There is problem with synchronize database: " + ex.getMessage());
//            }
            
//            DBCursor cursor = coll.find();
//            int i=1;
//            while (cursor.hasNext()) { 
//               System.out.println("Inserted Document: "+i); 
//               System.out.println(cursor.next()); 
//               i++;
//            }
            
//            DBCursor cursor = coll.find();
//            while (cursor.hasNext()) { 
//               DBObject updateDocument = cursor.next();
//               updateDocument.put("likes","200");
//               coll.update(updateDocument); 
//            }
//            System.out.println("Document updated successfully");
//            cursor = coll.find();
//            int i=1;
//            while (cursor.hasNext()) { 
//               System.out.println("Updated Document: "+i); 
//               System.out.println(cursor.next()); 
//               i++;
//            }
            
        }catch(Exception e){
	    System.err.println( e.getClass().getName() + ": " + e.getMessage() );
	}
   }
}
