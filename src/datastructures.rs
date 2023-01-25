use serde::{Serialize, Deserialize};
use chrono::DateTime;
use chrono::serde::ts_seconds;
use chrono::offset::{Utc};
use bson::oid::ObjectId;

#[derive(Serialize, Deserialize, Debug)]
pub struct Account {
    pub _id:ObjectId,
    pub user_name: String,
    pub password: String,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub role: String,
    #[serde(with = "ts_seconds")]
    pub created: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub updated: DateTime<Utc>,
    pub active: Option<bool>,
    pub usage: Option<i64>,
    pub max_usage: i64,
    pub files: Option<Vec<File>>,
    pub session: Option<Session>,
}


#[derive(Serialize, Deserialize, Debug)]
pub struct File {
    // fields for the file schema
    pub file_name: String,
    pub file_size: i64,
    pub file_type: Option<String>,
    pub account_id: String,
    pub file_id: String,
    #[serde(with = "ts_seconds")]
    pub uploaded_at: DateTime<Utc>,
    pub file_link: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Session {
    // fields for the session schema
    pub _id: ObjectId,
    pub account_id: ObjectId,
    #[serde(with = "ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub expire_at: DateTime<Utc>,
    pub active: bool,
    pub token: String,
}

