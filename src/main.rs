mod datastructures;
mod macromine;
mod database;
#[macro_use]
extern crate serde_json;

use std::{future::{ready, Ready}};
use chrono::serde::ts_seconds;
use bson::{doc};
use crate::database::RedisMongo;
use chrono::DateTime;
use mongodb::bson::oid::ObjectId;
use datastructures::{Account,Session};
use actix_web::{web, HttpResponse,HttpServer ,App, dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},Error};
use argon2::{self, Config};
use futures::{future::LocalBoxFuture};
use chrono::{Utc, Duration};
use database::MongoDB;

use jsonwebtoken::{encode, Header, EncodingKey, Validation, DecodingKey, decode};
use serde::{Deserialize, Serialize};



#[derive(Deserialize)]
struct Info {
    username: String,
    password: String,
}


// struct JWTVerifier;
#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    #[serde(with = "ts_seconds")]
    exp:DateTime<Utc>,
    account_id: ObjectId,
    session_id: ObjectId,
    user_name: String,
}



#[actix_web::post("/api/create_account")]
async fn create_account(data:web::Json<Info>,db:web::Data<MongoDB>) -> HttpResponse {
    let now =  Utc::now();
    // checking if the user exists already in the db
    let account = db.accounts.find_one(doc! {"user_name":data.username.clone()},None).await.unwrap();
    if account.is_some() {
        return HttpResponse::BadRequest().json(json!({"error":"user already exists"}));
    }
    let mut account:Account = Account {
        _id: ObjectId::new(),
        user_name: data.username.clone(),
        password: argon2::hash_encoded(data.password.as_bytes(),b"somerandomsalt",&Config::default()).unwrap(),
        role:"User".to_string(),
        created: now,
        updated:now,
        active:None,
        email:None,
        files:None,
        first_name:None,
        last_name:None,
        session: None,
        max_usage:1024,
        usage:None,
    };
    let session_id = ObjectId::new();
    let exp = Utc::now() + Duration::days(7);
    let claims =  Claims {
            exp: (Utc::now() + Duration::days(7)),
            account_id:account._id,
            session_id: session_id,
            user_name: account.user_name.clone()
    };
    let key = std::env::var("JWT_SECRET").unwrap();
    let key = EncodingKey::from_secret(key.as_ref());
    let token = encode(&Header::default(),&claims, &key).unwrap();
    let ssn = Session {
        _id: session_id,token: token,account_id:account._id,created_at: Utc::now(),active: true, expire_at: exp,
    };
    account.session = Some(ssn.clone());
    
    
    db.accounts.insert_cache(&account.user_name, account.clone()).expect("failed to insert account");
    db.sessions.insert_cache(&ssn._id.to_hex(), ssn.clone() ).expect("failed to insert session");
    HttpResponse::Created().json(json!({"token": ssn.token,"created_at": ssn.created_at,"active": ssn.active,"expire_at": ssn.expire_at}))
   
}


// redis caching done for the login route
// creating the login route
#[actix_web::post("/api/login")] 
async fn login_account(data:web::Json<Info>,db:web::Data<MongoDB>) -> HttpResponse {
    // let now =  Utc::now();
    // checking if the user exists already in the db // using redis now
    // manage insert first 
    // let account = db.accounts.get_cache()

    let account = db.accounts.get_cache(&data.username.clone(),doc! {"user_name":data.username.clone()}).unwrap();
    
    // let account = db.accounts.find_one(doc! {"user_name":data.username.clone()},None).await.unwrap();
    if account.is_some() {
        // checking if the password is correct
        let mut account = account.unwrap();
        let match_password = argon2::verify_encoded(&account.password,data.password.as_bytes()).unwrap();
        let old_session_id = account.clone().session.unwrap()._id;
        if !match_password {
            return HttpResponse::BadRequest().json(json!({"error":"password is incorrect"}));
        }
        let session_id = ObjectId::new();
        let exp = Utc::now() + Duration::days(7);
        let claims = Claims {
                exp: exp,
                account_id:account._id,
                session_id: session_id,
                user_name: account.user_name.clone()
        };
        // creating a new seesion and deleting the old session as well as attaching it to the account
        let key = std::env::var("JWT_SECRET").unwrap();
        let key = EncodingKey::from_secret(key.as_ref());
        let token = encode(&Header::default(),&claims, &key).unwrap();
        let ssn = Session {
            _id: session_id,token: token,account_id:account._id,created_at: Utc::now(),active: true, expire_at: exp,
        };
        account.session = Some(ssn.clone());
        // deleting the old session
        
        db.sessions.delete_cache(old_session_id.to_hex(),doc! {"accocunt_id":account._id}).expect("failed to delete session");
        // inserting the new session
        // testing if I can create this a multithreaded process
        // if let test = ssn.clone() {
        // }
        // let db_clone = db.clone();
        // let insertion_process = std::thread::spawn( move || {
        //     db_clone.sessions.insert_cache(&ssn._id.to_hex(),test).expect("failed to insert session")
        // });
        // insertion_process.join().expect("failed to join thread");
        db.sessions.insert_cache(&ssn._id.to_hex(),ssn.clone()).expect("failed to insert session");
        // updating the account with the new session    
        db.accounts.update_cache(&account.user_name,doc! {"user_name":data.username.clone()}, doc! {"$set": {"session": bson::to_bson(&ssn).unwrap()}},&account).expect("failed to update account");
        return HttpResponse::Created().json(json!({
        "token": ssn.token,
        "created_at": ssn.created_at,
        "active":ssn.active,
        "expire_at": ssn.expire_at,
        }))
    } else {
        return HttpResponse::BadRequest().json(json!({"error":"user does not exist"}));
    };

    
}


pub struct SayHi;

// Middleware factory is `Transform` trait
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for SayHi
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SayHiMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SayHiMiddleware { service }))
    }
}

pub struct SayHiMiddleware<S> {
    service: S,
}


// implementaint the clone for ServiceRequest



impl<S, B> Service<ServiceRequest> for SayHiMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static, 
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>; 
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {        // creating now the token verification middleware
        
       
        // creating a copy of req
        // creating a new service request for making the copy
        let headers = req.headers().clone();
        let app_data = req.app_data::<web::Data<MongoDB>>().unwrap().clone();
        let fut = self.service.call(req);
    
        Box::pin(async move {
            // Get the session cookie value, if it exists. 
            let token = headers.get("Authorization");
            if token.is_none() {
                return Err(actix_web::error::ErrorUnauthorized("No token present"));
            }
            let token = token.unwrap().to_str().unwrap();
            // if the Authtoken is not present
            let token = token.replace("Bearer ", "");
            let key = std::env::var("JWT_SECRET").unwrap();
            let decoded = decode::<Claims>(&token, &DecodingKey::from_secret(key.as_ref()), &Validation::new(jsonwebtoken::Algorithm::HS256)).unwrap().claims;
            let session = app_data.sessions.get_cache(&decoded.session_id.to_hex(),doc! {"_id":decoded.session_id}).unwrap();
            if !session.is_some() {
                return Err(actix_web::error::ErrorUnauthorized("Unauth"));
            }
            // check if the session is active and if the account exists
            let session = session.unwrap();
            let account = app_data.accounts.get_cache(&decoded.user_name.clone(),doc! {"_id":decoded.account_id}).unwrap();
            if !account.is_some() {
                return Err(actix_web::error::ErrorUnauthorized("Unauthorized"));
            }
            
            let account = account.unwrap();
            let a = account.session.unwrap().eq(&session);
            if !session.active {
                return Err(actix_web::error::ErrorUnauthorized("Unauthorized"));
            }
            if !a {
                return Err(actix_web::error::ErrorUnauthorized("Unauthorized"));
            }
            // passing the account id and the session id to the request 
            
            let resss = fut.await?;
            return Ok(resss);
        })
        
    
    }
}


// test service for middleware get request

async fn test() -> HttpResponse {
    HttpResponse::Ok().body("test")
}

#[actix_web::main]
async fn main()  -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();
    
    let db = MongoDB::new(&std::env::var("MONGO_URI").unwrap()).await.unwrap();
    let db_data = web::Data::new(db);
    HttpServer::new( move || {
        App::new().app_data(db_data.clone())
            .service(create_account).service(login_account).route("/test", web::get().to(test).wrap(SayHi))
    })
    .bind(("127.0.0.1", 1337))?
    .run()
    .await

 
}