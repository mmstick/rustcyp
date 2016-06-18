use std::io::Read;
use hyper::Client;
use hyper::header::{Connection, UserAgent};
use hyper::status::StatusCode;
use serde_json::de as JsonDecoder;

const URL: &'static str = "https://haveibeenpwned.com/api";

pub enum Status { Ok, Pwned(Breaches) }

pub enum Error { Request(String), Decode(String, String) }

pub type Breaches = Vec<Breach>;

#[derive(Deserialize)]
pub struct Breach {
    #[serde(rename="Name")]
    pub name: String,
    #[serde(rename="Title")]
    pub title: String,
    #[serde(rename="Domain")]
    pub domain: String,
    #[serde(rename="BreachDate")]
    pub breach_date: String,
    #[serde(rename="AddedDate")]
    pub added_date: String,
    #[serde(rename="PwnCount")]
    pub pwn_count: i32,
    #[serde(rename="Description")]
    pub description: String,
    #[serde(rename="DataClasses")]
    pub data_classes: Vec<String>,
    #[serde(rename="IsSensitive")]
    pub sensitive: bool,
    #[serde(rename="IsRetired")]
    pub retired: bool,
}

pub fn check_account(account: &str) -> Result<Status, Error> {
    let url = format!("{}/{}/{}/{}", URL, "v2", "breachedaccount", account);
    let client = Client::new();
    let request = client.get(&url).header(Connection::close()).header(UserAgent(String::from("hyper")));
    let mut response = match request.send() {
        Ok(response) => response,
        Err(error)   => return Err(Error::Request(error.to_string()))
    };

    if response.status == StatusCode::Ok {
        let mut body = String::new();
        response.read_to_string(&mut body).unwrap();
        match JsonDecoder::from_str::<Breaches>(&body) {
            Ok(results) => Ok(Status::Pwned(results)),
            Err(error)  => Err(Error::Decode(error.to_string(), body)),
        }
    } else {
        Ok(Status::Ok)
    }
}
