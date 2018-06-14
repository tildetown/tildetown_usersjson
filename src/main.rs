extern crate csv;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate regex;
extern crate sha2;

use csv::ReaderBuilder;
use std::collections::HashMap;
use regex::Regex;
use std::fs::{self, File};
use std::io::Write;
use sha2::{Sha256, Digest};
use std::time::UNIX_EPOCH;

#[derive(Serialize, Debug)]
pub struct UsersEntry {
    homepage: String,
    modtime: u64,
    edited: usize,
    ringmember: usize
}

#[derive(Deserialize, Debug)]
pub struct PasswdLine {
    username: String,
    passwd: String,
    uid: u32,
    gid: u32,
    gecos: String,
    home: String,
    interp: String
}

pub static TILDE_URL: &str = "https://tilde.town/~";

fn main() {
    println!("[+] eta's users.json generator");
    let output = ::std::env::args().nth(1)
        .expect("please provide an output filename as the 1st argument");
    println!("[+] outputting to {}", output);
    println!("[+] reading /etc/login.defs");
    let defs = fs::read_to_string("/etc/login.defs")
        .expect("reading /etc/login.defs");
    let re_uid_min = Regex::new(r"UID_MIN\s+(\d*)").unwrap();
    let re_uid_max = Regex::new(r"UID_MAX\s+(\d*)").unwrap();
    let uid_min: u32 = re_uid_min.captures(&defs).unwrap()[1].parse().unwrap();
    let uid_max: u32 = re_uid_max.captures(&defs).unwrap()[1].parse().unwrap();
    println!("[+] UID range: {}-{}", uid_min, uid_max);
    println!("[+] reading /etc/skel/public_html/index.html");
    let mut hasher = Sha256::default();
    let def_html = fs::read_to_string("/etc/skel/public_html/index.html")
        .expect("reading default html");
    hasher.input(def_html.as_bytes());
    let hash = hasher.result();
    println!("[+] reading /etc/passwd");
    let mut rdr = ReaderBuilder::new()
        .delimiter(b':')
        .has_headers(false)
        .from_path("/etc/passwd")
        .expect("reading /etc/passwd");
    let mut ret: HashMap<String, UsersEntry> = HashMap::new();
    for rec in rdr.deserialize() {
        let rec: PasswdLine = rec.expect("parsing passwd line");
        println!("[+] processing user {}", rec.username);
        if rec.uid > uid_max || rec.uid < uid_min {
            println!("[*] system user, skipping");
            continue;
        }
        if rec.passwd == "" {
            println!("[*] user disabled, skipping");
            continue;
        }
        let path = format!("/home/{}/public_html/index.html", rec.username);
        match fs::metadata(&path) {
            Ok(m) => {
                match fs::read_to_string(&path) {
                    Ok(h) => {
                        let mut hasher = Sha256::default();
                        hasher.input(h.as_bytes());
                        let edited = if hasher.result() == hash {
                            0
                        }
                        else {
                            1
                        };
                        let ringmember = if h.find("id=\"tilde_town_ring\"").is_some() {
                            1
                        }
                        else {
                            0
                        };
                        let modified = m.modified().unwrap();
                        let modtime = match modified.duration_since(UNIX_EPOCH) {
                            Ok(t) => t.as_secs(),
                            Err(_) => 0
                        };
                        ret.insert(rec.username.clone(), UsersEntry {
                            homepage: format!("{}{}", TILDE_URL, rec.username),
                            edited,
                            ringmember,
                            modtime
                        });
                    },
                    Err(e) => {
                        println!("[*] couldn't read {}, skipping: {}", path, e);
                        continue;
                    }
                }
            },
            Err(e) => {
                println!("[*] couldn't get metadata for {}, skipping: {}", path, e);
                continue;
            }
        }
    }
    println!("[+] writing json");
    let json = serde_json::to_string_pretty(&ret).expect("serializing");
    let mut file = File::create(output)
        .expect("creating output file");
    file.write_all(json.as_bytes())
        .expect("writing to output file");
    println!("[+] done!");
}
