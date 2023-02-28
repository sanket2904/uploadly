mod datastructures;
mod macromine;
mod database;
#[macro_use]
extern crate serde_json;
use std::{future::{ready, Ready}, rc::Rc, vec};
use chrono::serde::ts_seconds;
use bson::{doc};

use rusoto_s3::{S3Client, S3, PutObjectRequest};
use rusoto_core::{Region,ByteStream, credential::AwsCredentials};
use crate::database::RedisMongo;
use chrono::DateTime;
use mongodb::bson::oid::ObjectId;
use datastructures::{Account,Session,File,Claims};
use actix_web::{web, HttpResponse,HttpServer ,App, dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},Error, HttpMessage, Responder};
use argon2::{self, Config};
use futures::{future::LocalBoxFuture, TryStreamExt, StreamExt};
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


pub struct SayHi ;



// Middleware factory is `Transform` trait
// `S` - type of the next service
// `B` - type of response's body
impl<S, B> Transform<S, ServiceRequest> for SayHi
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static ,
   
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = SayHiMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SayHiMiddleware { service: Rc::new(service) }))
    }
}

pub struct SayHiMiddleware<S> {
    service: Rc<S>,
}


// implementaint the clone for ServiceRequest



impl<S, B> Service<ServiceRequest> for SayHiMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static  , 
   
{
    type Response = ServiceResponse<B>; 
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {        // creating now the token verification middleware
        
        let srv = self.service.clone();
        Box::pin(async move {
            // Get the session cookie value, if it exists. 
            let headers = req.headers().clone();
            let app_data = req.app_data::<web::Data<MongoDB>>().unwrap().clone();   
            let token = headers.get("Authorization");
            if token.is_none() {
                return Err(actix_web::error::ErrorUnauthorized("No token present"));
            }
            let token = token.unwrap().to_str().unwrap();
            // if the Authtoken is not present
            let token = token.replace("Bearer ", "");
            let key = std::env::var("JWT_SECRET").unwrap();
            let decoded = decode::<Claims>(&token, &DecodingKey::from_secret(key.as_ref()), &Validation::new(jsonwebtoken::Algorithm::HS256));
            if decoded.is_err() {
                return Err(actix_web::error::ErrorUnauthorized("Unauthorized"));
            }
            let decoded = decoded.unwrap().claims;
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
            req.extensions_mut().insert::<Claims>(decoded);
            let res = srv.call(req).await?;
                        
            return Ok(res);
        })
        
    
    }
}

// #[derive(Deserialize, Debug)]
// struct FileData {
//     file_buffer: Vec<u8>,
//     file_name: String,
//     file_type: String,
// }

struct MyAwsCredentialsProviderChicago;
// ignore serialization for now
struct MyAwsCredentialsProviderLA;
struct MyAwsCredentialsProviderIreland;
struct MyAwsCredentialsProviderLondon;
struct MyAwsCredentialsProviderParis;

#[derive(Clone,Copy)]
enum Creds {
    MyAwsCredentialsProviderChicago,
    MyAwsCredentialsProviderLA,
    MyAwsCredentialsProviderIreland,
    MyAwsCredentialsProviderLondon,
    MyAwsCredentialsProviderParis,
}

// impl rusoto_core::credential::ProfileProvider for Creds {
//     fn credential
// }

impl rusoto_core::credential::ProvideAwsCredentials for Creds {
    fn credentials<'life0, 'async_trait>(&'life0 self) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<AwsCredentials, rusoto_core::credential::CredentialsError>> + core::marker::Send + 'async_trait>> where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        match self {
            Creds::MyAwsCredentialsProviderChicago => Box::pin(MyAwsCredentialsProviderChicago.credentials()),
            Creds::MyAwsCredentialsProviderLA => Box::pin(MyAwsCredentialsProviderLA.credentials()),
            Creds::MyAwsCredentialsProviderIreland => Box::pin(MyAwsCredentialsProviderIreland.credentials()),
            Creds::MyAwsCredentialsProviderLondon => Box::pin(MyAwsCredentialsProviderLondon.credentials()),
            Creds::MyAwsCredentialsProviderParis => Box::pin(MyAwsCredentialsProviderParis.credentials()),
        }
    }
}

impl rusoto_core::credential::ProvideAwsCredentials for MyAwsCredentialsProviderChicago {
    fn credentials<'life0,'async_trait>(&'life0 self) ->  core::pin::Pin<Box<dyn core::future::Future<Output = Result<AwsCredentials,rusoto_core::credential::CredentialsError> > + core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        
        Box::pin(async move {
            let access_key = std::env::var("CHICAGO_ACCESS_KEY").unwrap();
            let secret_key = std::env::var("CHICAGO_SECRET_KEY").unwrap();
            let creds = AwsCredentials::new(access_key, secret_key, None, None);
            return Ok(creds);
        })
        
    }
}


impl rusoto_core::credential::ProvideAwsCredentials for MyAwsCredentialsProviderLA {
    fn credentials<'life0,'async_trait>(&'life0 self) ->  core::pin::Pin<Box<dyn core::future::Future<Output = Result<AwsCredentials,rusoto_core::credential::CredentialsError> > + core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        
        Box::pin(async move {
            let access_key = std::env::var("LA_ACCESS_KEY").unwrap();
            let secret_key = std::env::var("LA_SECRET_KEY").unwrap();
            let creds = AwsCredentials::new(access_key, secret_key, None, None);
            return Ok(creds);
        })
        
    }
}

impl rusoto_core::credential::ProvideAwsCredentials for MyAwsCredentialsProviderIreland {
    fn credentials<'life0,'async_trait>(&'life0 self) ->  core::pin::Pin<Box<dyn core::future::Future<Output = Result<AwsCredentials,rusoto_core::credential::CredentialsError> > + core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        
        Box::pin(async move {
            let access_key = std::env::var("IRELAND_ACCESS_KEY").unwrap();
            let secret_key = std::env::var("IRELAND_SECRET_KEY").unwrap();
            let creds = AwsCredentials::new(access_key, secret_key, None, None);
            return Ok(creds);
        })
        
    }
}

impl rusoto_core::credential::ProvideAwsCredentials for MyAwsCredentialsProviderLondon {
    fn credentials<'life0,'async_trait>(&'life0 self) ->  core::pin::Pin<Box<dyn core::future::Future<Output = Result<AwsCredentials,rusoto_core::credential::CredentialsError> > + core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        
        Box::pin(async move {
            let access_key = std::env::var("LONDON_ACCESS_KEY").unwrap();
            let secret_key = std::env::var("LONDON_SECRET_KEY").unwrap();
            let creds = AwsCredentials::new(access_key, secret_key, None, None);
            return Ok(creds);
        })
        
    }
}
impl rusoto_core::credential::ProvideAwsCredentials for MyAwsCredentialsProviderParis {
    fn credentials<'life0,'async_trait>(&'life0 self) ->  core::pin::Pin<Box<dyn core::future::Future<Output = Result<AwsCredentials,rusoto_core::credential::CredentialsError> > + core::marker::Send+'async_trait> >where 'life0:'async_trait,Self:'async_trait {
        
        Box::pin(async move {
            let access_key = std::env::var("PARIS_ACCESS_KEY").unwrap();
            let secret_key = std::env::var("PARIS_SECRET_KEY").unwrap();
            let creds = AwsCredentials::new(access_key, secret_key, None, None);
            return Ok(creds);
        })
        
    }
}




// pub async fn save_file(mut 


#[derive(Clone)]
struct FileData {
    file_buffer: Vec<u8>,
    file_name: String,
    
}

// impl copy for FileData 

// impl Clone for FileData {
//     fn clone(&self) -> FileData {
//         FileData {
//             file_buffer: self.file_buffer.clone(),
//             file_name: self.file_name.clone(),
//             file_type: self.file_type.clone(),
//         }
//     }
// }


#[derive(Clone)]
struct UploadBucket {
    endpoint: String,
    name: String,
    cred: Creds,
}

async fn push_files(req: actix_web::HttpRequest, mut payload:actix_multipart::Multipart,db:web::Data<MongoDB>  ) -> impl Responder {
    // manage the files first
    // inititalize the vec for upload data 
    let mut fileData:Vec<FileData> = Vec::new();
    let claim = req.extensions_mut();
    let claim =  claim.get::<Claims>();
    let mut file_init = datastructures::File::new();
    let  buckets:Vec<UploadBucket> = vec![UploadBucket{
        name:  std::env::var("CHICAGO_NAME").unwrap(),
        endpoint: std::env::var("CHICAGO_ENDPOINT").unwrap(),
        cred: Creds::MyAwsCredentialsProviderChicago,
    }, UploadBucket{
        name:  std::env::var("LA_NAME").unwrap(),
        endpoint: std::env::var("LA_ENDPOINT").unwrap(),
        cred: Creds::MyAwsCredentialsProviderLA,
        }, UploadBucket{
        name:  std::env::var("IRELAND_NAME").unwrap(),
        endpoint: std::env::var("IRELAND_ENDPOINT").unwrap(),
        cred: Creds::MyAwsCredentialsProviderIreland,

        }, UploadBucket{
        name:  std::env::var("LONDON_NAME").unwrap(),
        endpoint: std::env::var("LONDON_ENDPOINT").unwrap(),
        cred: Creds::MyAwsCredentialsProviderLondon,
        },UploadBucket{
        name:  std::env::var("PARIS_NAME").unwrap(),
        endpoint: std::env::var("PARIS_ENDPOINT").unwrap(),
        cred: Creds::MyAwsCredentialsProviderParis,
        }];

    while let Ok(Some(mut field)) = payload.try_next().await {
        let content_type = field.content_disposition();
        let name = content_type.get_filename().unwrap();
        let file_type = content_type.get_name().unwrap().split(".");
        let file_type = file_type.last().unwrap();
        file_init.file_type = Some(file_type.to_string());
        file_init.file_name = name.to_string();
        file_init.account_id = claim.unwrap().account_id.to_string();
        
        let mut init = FileData {
            file_buffer: Vec::new(),
            file_name: name.to_string(),
            
        };
        let mut ini = vec![];
        while let Some(chunk) = field.next().await {
            let data = chunk.unwrap();
            ini.push(data);
        }
        init.file_buffer = ini.into_iter().flatten().collect::<Vec<u8>>();
        fileData.push(init);
    }   
    for file in fileData {
        // create new file data for database 
        for bucket in 0..buckets.len() {
            let _a = file_process(file.clone(), buckets[bucket].clone()).await;
        }
    }
    return HttpResponse::Created().json(json!({
        "file_name": "ok",
        // "account_id": file.account_id,
    }));
}




async fn file_process(file: FileData, bucket:  UploadBucket) -> rusoto_s3::PutObjectOutput {
    let task = tokio::spawn(async move {
        let stream = ByteStream::from(file.file_buffer.clone());
        let client = S3Client::new_with(rusoto_core::HttpClient::new().unwrap(),  bucket.cred  ,Region::Custom {
            name: bucket.endpoint.clone(),
            endpoint: bucket.endpoint.clone(),
        });
        let _res = client.put_object(PutObjectRequest {
            bucket:  bucket.name.clone(),
            key: file.file_name.clone(),
            body: Some(stream),            
            ..Default::default()
        }).await;
        match _res {
            Ok(_) => {
                return Ok(_res)
            }
            Err(e) => return Err(e),
        }
    });
    let init =  task.await.unwrap().expect("failed to upload file").expect("failed to upload file");
    init
}


// uploading files to s3 bucket 

async fn fetchallfiles(req: actix_web::HttpRequest,db:web::Data<MongoDB> ) -> HttpResponse {
    // let claim = req.extensions_mut();
    // let claim = claim.get::<Claims>();
    // if claim.is_none() {
    //     return HttpResponse::BadRequest().json(json!({"error":"unauthorized"}));
    // }
    // let claim = claim.unwrap().clone();
    // let mut files = db.files.find(doc! {"accocunt_id": claim.account_id}, None).await.expect("failed to fetch files");    
    // let mut files_vec = Vec::new();

    // while let Some(file) = files.next().await {
    //     let file = file.expect("failed to fetch file");
    //     files_vec.push(file);
    // }
    // // converting Cursor to Vec and then return the response

    // return HttpResponse::Ok().json(json!({
    //     "files": files_vec,
    // }))
    
    if let Some(claim) = req.extensions().get::<Claims>() {
        let mut files_vec = Vec::new();
        let mut files = db.files
            .find(doc! {"account_id": claim.account_id}, None)
            .await
            .expect("failed to fetch files");
        while let Some(file) = files.next().await {
            let file = file.expect("failed to fetch file");
            files_vec.push(file);
        }
        return HttpResponse::Ok().json(json!({
            "files": files_vec,
        }));
    }

    HttpResponse::BadRequest().json(json!({"error":"unauthorized"}))
}


#[actix_web::main]
async fn main()  -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();
    
    let db = MongoDB::new(&std::env::var("MONGO_URI").unwrap()).await.expect("failed to connect to database");
    let db_data = web::Data::new(db);
    HttpServer::new( move || {
        App::new().app_data(db_data.clone())
            .service(create_account).service(login_account).route("/api/files", web::post().to(push_files).wrap(SayHi)).route("/api/files", web::get().to(fetchallfiles).wrap(SayHi))
    })
    .bind(("127.0.0.1", 1337))?
    .run()
    .await 
}