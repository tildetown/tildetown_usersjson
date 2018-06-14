// to anyone reading this: I'm sorry, it's not exactly perfect.

extern crate csv;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
extern crate regex;
extern crate sha2;
extern crate chrono;

use csv::ReaderBuilder;
use std::collections::BTreeMap;
use regex::Regex;
use std::fs::{self, File};
use std::io::Write;
use sha2::{Sha256, Digest};
use std::time::UNIX_EPOCH;
use chrono::{NaiveDateTime, Utc};

#[derive(Serialize, Debug)]
pub struct UsersEntry {
    homepage: String,
    modtime_unix: u64,
    modtime: String,
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
    let html_output = ::std::env::args().nth(2)
        .expect("please provide a HTML output filename as the 2st argument");
    println!("[+] outputting to {} (JSON)", output);
    println!("[+] outputting to {} (HTML)", html_output);
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
    let mut ret: BTreeMap<String, UsersEntry> = BTreeMap::new();
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
                        let modtime_unix = match modified.duration_since(UNIX_EPOCH) {
                            Ok(t) => t.as_secs(),
                            Err(_) => 0
                        };
                        let modtime = NaiveDateTime::from_timestamp(modtime_unix as _, 0)
                            .format("%a %b %e %H:%M:%S %Y")
                            .to_string();
                        ret.insert(rec.username.clone(), UsersEntry {
                            homepage: format!("{}{}", TILDE_URL, rec.username),
                            edited,
                            ringmember,
                            modtime,
                            modtime_unix
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
    println!("[+] writing json & HTML");
    let json = serde_json::to_string_pretty(&ret).expect("serializing");
    let mut file = File::create(output)
        .expect("creating output file");
    let mut html_file = File::create(html_output)
        .expect("creating HTML output file");
    file.write_all(json.as_bytes())
        .expect("writing to output file");

    // this...isn't great.

    write!(html_file, r#"
<!DOCTYPE html>
<html>
<head>
<title>eta's townies list</title>
</head>
<body>
<pre>
<h2>list of townies</h2>
===============

lists townies with a reachable homepage 
last updated {}; updates every hour, on the hour
maintained by <a href="//tilde.town/~eeeeeta">~eeeeeta</a>
source code <a href="https://github.com/eeeeeta/tildetown_usersjson/">here</a>
view log <a href="//tilde.town/~eeeeeta/users.log">here</a> (if you aren't showing up)

<h3><a href="//tilde.town/~eeeeeta/ring/join.html">~ring</a> members</h3>
===============
"#, Utc::now()).unwrap();
    write_townies(&mut html_file, &ret, TownieFilter::RingMember).unwrap();
    write!(html_file, r#"

<h3>townies with non-default homepages</h3>
===============
"#).unwrap();
    write_townies(&mut html_file, &ret, TownieFilter::NonDefault).unwrap();
    write!(html_file, r#"

<h3>all townies with homepages</h3>
===============
"#).unwrap();
    write_townies(&mut html_file, &ret, TownieFilter::Other).unwrap();
    write!(html_file, r#"
</pre>
</body>
</html>"#).unwrap();
    println!("[+] done!");
}
#[derive(Copy, Clone, Debug)]
pub enum TownieFilter {
    RingMember,
    NonDefault,
    Other
}
fn write_townies<R: Write>(out: &mut R, ret: &BTreeMap<String, UsersEntry>, mode: TownieFilter) -> ::std::io::Result<()> {
    let mut members = 0;
    for (uname, ent) in ret.iter() {
        match mode {
            TownieFilter::RingMember => {
                if ent.ringmember != 1 {
                    continue;
                }
            },
            TownieFilter::NonDefault => {
                if ent.edited == 0 {
                    continue;
                }
            },
            _ => {}
        }
        write!(out, "- <a href=\"{}\">~{}</a> (updated {})\n",
        ent.homepage, uname,
        NaiveDateTime::from_timestamp(ent.modtime_unix as _, 0)
        .format("%Y-%m-%d")
        .to_string())?;
        members += 1;
    }
    write!(out, "\n({} in total)", members)?;
    Ok(())
}
