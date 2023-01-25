use mongodb::{Client, Collection,options::ClientOptions};

struct MongoDB {
    client: Client,
    pub accounts: Collection,
    pub sessions: Collection,
    pub files: Collection,
}

impl MongoDB {
    fn new(uri: &str) -> Result<Self, mongodb::error::Error> {
        let client_options = ClientOptions::parse("mongodb://localhost:27017").unwrap();
        let client = Client::with_options(client_options).unwrap();
        let accounts = client.database("mydb").collection("accounts");
        let sessions = client.database("mydb").collection("sessions");
        let files = client.database("mydb").collection("files");
        Ok(MongoDB {
            client,
            accounts,
            sessions,
            files,
        })
    }
}
