mod datastructures;
mod macromine;

#[macro_use]
extern crate serde_json;

use mongodb::bson::oid::ObjectId;

use datastructures::{Account,Session};
use actix_web::{web, HttpResponse, Responder,HttpServer, App};
use argon2::{self, Config};
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, Header, EncodingKey};
use serde::Deserialize;


#[derive(Deserialize)]
struct Info {
    username: String,
    password: String,
//     first_name:String,
//     last_name:String
}





async fn create_account(web::Form(data): web::Form<Info>) -> impl Responder {
    let now =  Utc::now();
    let account:Account = Account {
        _id: ObjectId::new(),
        user_name: data.username,
        password: argon2::hash_encoded(data.password.as_bytes(),b"somerandomsalt",&Config::default()).unwrap(),
        role:"User".to_string(),
        created: now,
        updated:now,
        active:None,
        email:None,
        files:None,
        first_name:None,
        last_name:None,
        max_usage:1024,
        session: None,
        usage:None,
    };
    let my_secret = "secret";
    let key = EncodingKey::from_secret(my_secret.as_ref());
    let session_id = ObjectId::new();
    let claims =  json!({
            "account_id":account._id,
            "session_id": session_id
    });
    let token = encode(&Header::default(),&claims, &key).unwrap();
    print!("{}",token);
    let ssn:Session = Session {
        _id: session_id,
        token: token,
        account_id:account._id,
        created_at: Utc::now(),
        active: true,
        expire_at: Utc::now() + Duration::days(7),
    };

    HttpResponse::Created().json(ssn)
   
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new().route("/create_account", web::post().to(create_account))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}