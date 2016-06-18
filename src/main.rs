#![feature(plugin)]
#![plugin(serde_macros)]
#![feature(custom_derive)]
#![feature(custom_attribute)]
extern crate colored;
extern crate hyper;
extern crate serde;
extern crate serde_json;
use std::env;
use std::process;
mod api;
use api::{Error, Status};
use colored::Colorize;

fn main() {
    if env::args().count() < 1 {
        println!("Usage: \n\tgocyp <email or user name>");
        process::exit(1);
    }
    for account in env::args().skip(1) {
        println!("Checking {}", account);
        match api::check_account(&account) {
            Err(Error::Request(error)) => {
                println!("rustcyp: unable to get response: {}", error);
                process::exit(1);
            },
            Err(Error::Decode(error, body)) => {
                println!("rustcyp: unable to decode response: {}\n{}", error, body);
                process::exit(1);
            },
            Ok(Status::Pwned(breaches)) => {
                println!("{}: {}", account, "pwned".red().bold());
                for (idx, breach) in breaches.iter().enumerate() {
                    println!("Breach #{} - {} {:?}", idx+1, breach.title, breach.data_classes);
                }
            },
            Ok(Status::Ok) => println!("rustcyp: {}", format!("{} has not been breached", account).green().bold())
        }
    }
}
