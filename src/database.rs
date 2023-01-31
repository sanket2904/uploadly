
use std::sync::Arc;
use bson::{ Document};
use futures::{executor::{block_on}};
use mongodb::{Client, Collection,options::{ClientOptions, UpdateModifications}};
use redis::{Commands, Connection};
use serde::{Serialize, de::DeserializeOwned};
use crate::datastructures::{Session,Account,File};
extern crate redis;

pub struct MongoDB {
    pub accounts: Collection<Account>,
    pub sessions: Collection<Session>,
    pub files: Collection<File>,
    // pub redis: Connection
}


// adding functionality to the mongodb Collection
impl MongoDB {
    pub async fn new(uri: &str) -> Result<Self, mongodb::error::Error> {
        let client_options =  ClientOptions::parse(uri).await.unwrap();
        let client = Client::with_options(client_options).unwrap();
        let accounts = client.database("mydb").collection("accounts");
        let sessions = client.database("mydb").collection("sessions");
        let files = client.database("mydb").collection("files");
        // let redis = RedisDB::new(&std::env::var("REDIS_URI").unwrap()).await.connection;
        Ok(MongoDB {accounts,sessions,files})
    }
    // inserting a <T> into a collection along with in redis db for caching
    // 
    
}

pub trait RedisMongo<T> {
    // get redis connection
    fn get_redis(&self) -> Connection;
    fn insert_cache(&self, key: &str, value: T) -> Result<(), mongodb::error::Error> where T: Serialize  + std::marker::Send + std::marker::Sync + 'static;
    fn get_cache(&self, key: &str, query: Document) -> Result<Option<T>, mongodb::error::Error> where T: Serialize + DeserializeOwned+  Unpin + std::marker::Send + Sync;
    // update cache and mongodb 
    fn update_cache(&self, key: &str, query: Document, update: impl Into<UpdateModifications>,value: &T) -> Result<(), mongodb::error::Error> where T: Serialize;
    // delete cache and mongodb
    fn delete_cache(&self, key: String, query: Document) -> Result<(), mongodb::error::Error>;
} 

impl<T> RedisMongo<T> for Collection<T> where T:Serialize {
    fn insert_cache(&self, key: &str, value: T) -> Result<(), mongodb::error::Error> where T: Serialize + std::marker::Send + std::marker::Sync + 'static  {
        // creating a multi threaded runtime
        let strr = serde_json::to_string(&value).unwrap();
        let arc_self = self.clone();
        let data = Arc::new(value);
        let key = key.to_string();
        let mut redis = self.get_redis();
       

        let redis_thread = std::thread::spawn( move ||  {
            
            let _red: () =  redis.set_ex( key, strr,7*86400).expect("redis error 42");
        });
        redis_thread.join().expect("thread failed");
            // pooling mongodb
        let _res = block_on(arc_self.insert_one(data, None));
        
       
        
        Ok(())
    }
    fn get_redis(&self) -> Connection {
        let redis = redis::Client::open(std::env::var("REDIS_URI").unwrap()).expect("no uri").get_connection().expect("no connection");
        redis
    }
    fn get_cache(&self, key: &str, query: Document) -> Result<Option<T>, mongodb::error::Error> where T: Serialize + DeserializeOwned +  Unpin + std::marker::Send + Sync 
    {
        // check if it exists in redis
        let mut redis = self.get_redis();
        let res = redis.get::<&str,String>(key);
        // if it exists return it
        if !res.is_err() {
            let res: T = serde_json::from_str(&res.unwrap()).unwrap();
           
            return Ok(Some(res));
        }
        // if it doesn't exist get it from mongodb and insert it into redis
        
        let res:Result<Option<T>, mongodb::error::Error> = block_on(self.find_one(query, None));
        match res {
            Ok(Some(value)) => {
                // adding to redis 
                let _red: () =  redis.set_ex(key,serde_json::to_string(&value).unwrap(),86400 * 7).expect("redis error 74");
                Ok(Some(value))
            }
            Err(e) => Err(e),
            _ => Ok(None)
        }

        
       


       
    }
    fn update_cache(&self, key: &str, query: Document, update: impl Into<UpdateModifications>, value: &T) -> Result<(), mongodb::error::Error> where T: Serialize {
        // update mongodb
        let _res = block_on(self.update_one(query, update, None));
        // update redis
        let mut redis = self.get_redis();
        let _red: () =  redis.set_ex(key,serde_json::to_string(value).unwrap(),86400).expect("redis error 74");
        Ok(())
    }
    fn delete_cache(&self, key: String, query: Document) -> Result<(), mongodb::error::Error> {
        // delete from mongodb
        
        // delete from redis
        let key = key.to_string();
        println!("{}", key);
        let mut redis = self.get_redis();
        // creating a multi threaded runtime
        let redis_thead = std::thread::spawn( move ||  {
            let _red: () =  redis.del(key).expect("redis error 74");
        });
        redis_thead.join().expect("thread failed");
        let _res = block_on(self.delete_one(query, None));
        Ok(())
    }

}


// creating a redis db manager which chaches the mongodb data and uses it to serve the requests 
// impl RedisDB {
//     pub fn new(uri: &str) -> Self {
//         let client = redis::Client::open(uri).expect("no uri");
//         let connection = client.get_connection().expect("no connection");
//         RedisDB {client,connection}
//     }
    
// }