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

impl PartialEq for Session {
    fn eq(&self, other: &Self) -> bool {
        return self._id == other._id && self.account_id == other.account_id && self.token == other.token;
    }
}


impl Clone for Session {
    fn clone(&self) -> Self {
        Session {
            _id: self._id.clone(),
            account_id: self.account_id.clone(),
            created_at: self.created_at.clone(),
            expire_at: self.expire_at.clone(),
            active: self.active.clone(),
            token: self.token.clone(),
        }
    }
}

impl Clone for Account {
    fn clone(&self) -> Self {
        Account {
            _id: self._id.clone(),
            user_name: self.user_name.clone(),
            password: self.password.clone(),
            email: self.email.clone(),
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            role: self.role.clone(),
            created: self.created.clone(),
            updated: self.updated.clone(),
            active: self.active.clone(),
            usage: self.usage.clone(),
            max_usage: self.max_usage.clone(),
            files: self.files.clone(),
            session: self.session.clone(),
        }
    }
}
impl Clone for File {
    fn clone(&self) -> Self {
        File {
            file_name: self.file_name.clone(),
            file_size: self.file_size.clone(),
            file_type: self.file_type.clone(),
            account_id: self.account_id.clone(),
            file_id: self.file_id.clone(),
            uploaded_at: self.uploaded_at.clone(),
            file_link: self.file_link.clone(),
        }
    }
}