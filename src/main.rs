use std::net::UdpSocket;
use std::env;
use std::io::Write;
use std::net::{SocketAddr, IpAddr};
use std::io::prelude::*;
use std::fs::{self, File, OpenOptions};
use std::time::{SystemTime, Instant};

use std::collections::HashMap;
use sha1::{Sha1, Digest};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};

use humantime::{format_rfc3339, Rfc3339Timestamp, format_duration};

fn now_timestamp() -> String {
    let rfc = format_rfc3339(SystemTime::now());
    let rfc = format!("{rfc}");
    if let Some((car, cdr)) = rfc.split_once(".") {
        let car = car.replace("T", " ");
        format!("{car} UTC")
    } else { unreachable!() }
}

#[derive(Clone)]
struct AesCipher {
    key: Key<Aes256Gcm>,
    cipher: Aes256Gcm,
}

impl AesCipher {
    pub fn load_from_file() -> Self {
        let mut buf: Vec<u8> = vec![];
        {
            let mut file = File::open("key").expect("can't open keyfile, did you run 'areia key'?");
            file.read_to_end(&mut buf).expect("can't read keyfile correctly, is shit fucked? remove 'key' in the current directory and rerun 'areia key'");
        }
        let key = Key::<Aes256Gcm>::from_slice(&buf[..32]);

        let cipher = Aes256Gcm::new(&key);

        println!("Cipher initialized successfully.");

        Self { key: *key, cipher }
    }
    pub fn encrypt_packet(&self, payload: &[u8]) -> Option<Vec<u8>> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let mut packet = nonce.as_slice().to_vec();

        if let Ok(mut ciphertext) = self.cipher.encrypt(&nonce, payload) {
            packet.append(&mut ciphertext);
            Some(packet)
        } else {
            None
        }
    }
    pub fn decrypt_packet(&self, payload: &[u8]) -> Option<Vec<u8>> {
        let nonce = payload[..12].to_vec();
        let nonce = Nonce::from_slice(&nonce);
        let payload = payload[12..].to_vec();

        if let Ok(plaintext) = self.cipher.decrypt(&nonce, payload.as_slice()) {
            Some(plaintext)
        } else {
            None
        }
    }
}

fn ask(prompt: &str) -> String {
    print!("{}", prompt);
    std::io::stdout().flush().unwrap();

    let mut ans = String::new();
    std::io::stdin()
        .read_line(&mut ans)
        .expect("failed to readline");
    ans.trim().into()
}

#[derive(Debug, Clone, Copy)]
enum Subcommand {
    Server,
    Listener,
    Sender,
    // malformed args
    ShowUsage,
    SaveKey,
    Debug,
}

fn parse_args(mut args: env::Args) -> Subcommand {
    args.next().unwrap();
    if let Some(first_arg) = args.next() {
        if first_arg == "server" {
            Subcommand::Server
        } else if first_arg == "listener" {
            Subcommand::Listener
        } else if first_arg == "sender" {
            Subcommand::Sender
        } else if first_arg == "key" {
            Subcommand::SaveKey
        } else if first_arg == "debug" {
            Subcommand::Debug
        } else {
            Subcommand::ShowUsage
        }
    } else {
        Subcommand::ShowUsage
    }
}

fn server() -> std::io::Result<()> {
    let mut listeners: Vec<SocketAddr> = vec![];
    let mut nicks: HashMap<IpAddr, String> = HashMap::new();
    let mut memos: Vec<String> = vec![];
    let mut userstates: HashMap<String, (Instant, String)> = HashMap::new();

    let port_bind = ask("Bind server to which port? ");
    let bound_addr = format!("0.0.0.0:{}", port_bind);

    let socket = UdpSocket::bind(bound_addr)?;

    let crypto = AesCipher::load_from_file();

    loop {
        // cuts off datagrams bigger than 512 bytes.
        let mut buf = [0; 1024];
        let (amt, src) = socket.recv_from(&mut buf)?;

        if amt < 1 {
            continue;
        }

        let packet = &buf[..amt];
        let packet = match crypto.decrypt_packet(packet) {
            Some(v) => v,
            None => continue,
        };

        let parsed_str = String::from_utf8(packet.to_vec()).expect("couldn't parse");

        if parsed_str.len() < 1 {
            continue;
        }

        if nicks.contains_key(&src.ip()) {
            userstates.entry(nicks.get(&src.ip()).unwrap().clone()).and_modify(|state| (*state).0 = Instant::now()).or_insert_with(|| (Instant::now(), String::new()));
        }

        if parsed_str == "thisisaveryrandomstring" {
            // deduplicate old listeners from same ip
            // NOTE: causes issues when there are multiple clients behind an ip, FIXME, not
            // important in the current circumstances
            listeners = listeners.iter().filter(|x| x.ip() != src.ip()).copied().collect::<Vec<SocketAddr>>();

            listeners.push(src);
            println!("[{}] Registered {} as a listener!", now_timestamp(), src);
            dbg!(&listeners);

            for memo in &memos {
                let response = format!("Memo > {memo}");
                if let Some(response) = crypto.encrypt_packet(response.as_str().as_bytes()) {
                    socket.send_to(&response, &src)?;
                } else {
                    println!("Malformed fucking packet encountered trying to encrypt. How the fuck did this happen?");
                }
            }
        } else if parsed_str.starts_with("/setnick") {
            println!("[{}] {parsed_str}", now_timestamp());
            let mut whitespace_iter = parsed_str.split_ascii_whitespace();
            whitespace_iter.next().unwrap(); // shouldnt fail
            if let Some(nick) = whitespace_iter.next() {
                nicks.insert(src.ip(), nick.into());
            }
        } else if parsed_str.starts_with("/status") {
            if !nicks.contains_key(&src.ip()) { continue; }

            if let Some((_, status)) = parsed_str.split_once(" ") {
                userstates.entry(nicks.get(&src.ip()).unwrap().to_string()).and_modify(|val| val.1 = status.to_string());

                if let Some(socketaddr) = listeners.iter().find(|&x| x.ip() == src.ip()) {
                    println!("[{}] User {} (socket {:?}) changed status to {}.", now_timestamp(), nicks.get(&src.ip()).unwrap(), src, status);
                        let response = format!("Status > Updated your status to {}.", status);

                        if let Some(response) = crypto.encrypt_packet(response.trim().as_bytes()) {
                            socket.send_to(&response, &socketaddr)?;
                        } else {
                            println!("Malformed fucking packet encountered trying to encrypt. How the fuck did this happen?");
                        }
                    }
            }
        } else if parsed_str.starts_with("/list") {
            if !nicks.contains_key(&src.ip()) { continue; }

            if let Some(socketaddr) = listeners.iter().find(|&x| x.ip() == src.ip()) {
                println!("[{}] User {} (socket {:?}) sent list request.", now_timestamp(), nicks.get(&src.ip()).unwrap(), src);
                for (key, val) in userstates.iter() {
                    let state = if !val.1.is_empty() {
                        format!("They are {}.", val.1)
                    } else {
                        format!("")
                    };
                    let response = format!("List > {}'s last message was {} ago. {}", key, format_duration(val.0.elapsed()), state);

                    if let Some(response) = crypto.encrypt_packet(response.trim().as_bytes()) {
                        socket.send_to(&response, &socketaddr)?;
                    } else {
                        println!("Malformed fucking packet encountered trying to encrypt. How the fuck did this happen?");
                    }
                }
            }
        } else if parsed_str.starts_with("/viewmemo") {
            if !nicks.contains_key(&src.ip()) { continue; }

            if let Some(socketaddr) = listeners.iter().find(|&x| x.ip() == src.ip()) {
                println!("[{}] User {} (socket {:?}) viewed memos.", now_timestamp(), nicks.get(&src.ip()).unwrap(), src.ip());

                for memo in &memos {
                    let response = format!("Memo > {memo}");
                    if let Some(response) = crypto.encrypt_packet(response.as_str().as_bytes()) {
                        socket.send_to(&response, &socketaddr)?;
                    } else {
                        println!("Malformed fucking packet encountered trying to encrypt. How the fuck did this happen?");
                    }
                }
            }
        } else if parsed_str.starts_with("/clearmemo") {
            if !nicks.contains_key(&src.ip()) { continue; }

            memos = vec![];
            let response = format!("Memo > Cleared all memos at the orders of {}!", nicks.get(&src.ip()).unwrap());
            println!("[{}] User {} (socket {:?}) cleared memos.", now_timestamp(), nicks.get(&src.ip()).unwrap(), src);

            if let Some(response) = crypto.encrypt_packet(response.as_str().as_bytes()) {
                for addr in &listeners {
                    socket.send_to(&response, &addr)?;
                }
            } else {
                println!("Malformed fucking packet encountered trying to encrypt. How the fuck did this happen?");
            }
        } else if parsed_str.starts_with("/attrition") {
            if !nicks.contains_key(&src.ip()) { continue; }

            let response = format!("List > Cleared all listeners at the orders of {}!", nicks.get(&src.ip()).unwrap());
            println!("[{}] User {} (socket {:?}) cleared listeners.", now_timestamp(), nicks.get(&src.ip()).unwrap(), src);

            if let Some(response) = crypto.encrypt_packet(response.as_str().as_bytes()) {
                for addr in &listeners {
                    socket.send_to(&response, &addr)?;
                }
            } else {
                println!("Malformed fucking packet encountered trying to encrypt. How the fuck did this happen?");
            }
            listeners = vec![];
        } else if parsed_str.starts_with("/memo") {
            if !nicks.contains_key(&src.ip()) { continue; }

            if let Some((_, memo)) = parsed_str.split_once(" ") {
                println!("[{}] memo added by {} ({}): {}", now_timestamp(), nicks.get(&src.ip()).unwrap(), &src, &memo);

                let added_memo = format!("{} @ {}: {}", nicks.get(&src.ip()).unwrap(), now_timestamp(), memo.trim());
                memos.push(added_memo.to_string());

                let response = String::from(format!("Memo > New memo added by {}!", nicks.get(&src.ip()).unwrap()));

                memos = memos.iter().rev().take(10).rev().map(|s| s.clone()).collect::<Vec<String>>();

                if let Some(response) = crypto.encrypt_packet(response.as_str().as_bytes()) {
                    for addr in &listeners {
                        socket.send_to(&response, &addr)?;
                    }
                } else {
                    println!("Malformed fucking packet encountered trying to encrypt. How the fuck did this happen?");
                }
            }
        } else if parsed_str.starts_with("/me") {
            if let Some((_, sentence)) = parsed_str.split_once(" ") {
                println!("[{}] /me '{sentence}' from {:?}", now_timestamp(), src);

                let broadcast = if nicks.contains_key(&src.ip()) {
                    // shouldn't fail, it contains it
                    format!("* {} {sentence}", nicks.get(&src.ip()).unwrap())
                } else {
                    format!("* {src} {sentence}")
                };

                if let Some(broadcast) = crypto.encrypt_packet(broadcast.as_str().as_bytes()) {
                    for addr in &listeners {
                        socket.send_to(&broadcast, &addr)?;
                    }
                } else {
                    println!("Malformed fucking packet encountered trying to encrypt. How the fuck did this happen? (/me)");
                }
            }
        } else {
            println!("[{}] '{parsed_str}' from {:?}", now_timestamp(), src);

            let broadcast = if nicks.contains_key(&src.ip()) {
                // shouldn't fail, it contains it
                format!("{} -> {parsed_str}", nicks.get(&src.ip()).unwrap())
            } else {
                format!("{src} > {parsed_str}")
            };

            if let Some(broadcast) = crypto.encrypt_packet(broadcast.as_str().as_bytes()) {
                for addr in &listeners {
                    socket.send_to(&broadcast, &addr)?;
                }
            } else {
                println!("Malformed fucking packet encountered trying to encrypt. How the fuck did this happen?");
            }
        }
    }
    Ok(())
}

fn listener() -> std::io::Result<()> {
    let outbound = ask("Server address with port? ");
    let bound_addr = format!("0.0.0.0:0");

    let socket = UdpSocket::bind(bound_addr)?;
    socket.connect(outbound.as_str())?;

    let crypto = AesCipher::load_from_file();

    let register_str = String::from("thisisaveryrandomstring").into_bytes();
    // this shit genuinely should not fail
    let register_str = crypto.encrypt_packet(register_str.as_slice()).unwrap();
    socket.send(&register_str)?;

    loop {
        let mut buf = [0; 512];
        let (amt, src) = socket.recv_from(&mut buf)?;
        
        if amt < 1 {
            continue;
        }

        let packet = &buf[..amt];
        // this should also be safe to unwrap because of
        // the fact that the server doesn't send malformed
        // packets. i think.
        let packet = crypto.decrypt_packet(packet).unwrap();

        if let Ok(parsed_str) = String::from_utf8(packet.to_vec()) {
            println!("{parsed_str}");
        } else {
            println!("[ERR] Invalid packet received!");
        }
    }

    Ok(())
}

fn sender() -> std::io::Result<()> {
    let outbound = ask("Server address with port? ");
    //let port_bind = ask("Bind to which port (8000 to 64000)? ");
    //let bound_addr = format!("0.0.0.0:{}", port_bind);
    let bound_addr = format!("0.0.0.0:0");

    let socket = UdpSocket::bind(bound_addr)?;
    socket.connect(outbound.as_str())?;

    let crypto = AesCipher::load_from_file();

    loop {
        let packet = ask("message: ");
        // also should be safe to unwrap unless keyfile is fucked
        let packet = crypto.encrypt_packet(packet.as_bytes()).unwrap();

        socket.send(&packet)?;
    }

    Ok(())
}

fn main() -> std::io::Result<()> {
    let subcmd = parse_args(env::args());

    match subcmd {
        Subcommand::ShowUsage => {
            println!("Usage:");
            println!("(run server) ./areia server");
            println!("(run listener) ./areia listener");
            println!("(run sender) ./areia sender");
            println!("(make and write aes key) ./areia key");
        }
        Subcommand::Server => {
            server()?;
        }
        Subcommand::Listener => {
            listener()?;
        }
        Subcommand::Sender => {
            sender()?;
        }
        Subcommand::SaveKey => {
            let passphrase = ask("Passphrase? ");
            // sha1 isnt cryptographically safe, but it's the
            // only hashing algorithm i had the library for.
            // so we'll have to try and make it work.
            let mut hasher = Sha1::new();
            hasher.update(passphrase.as_bytes());
            let step_one = hasher.finalize();

            let mut hasher = Sha1::new();
            let slice = step_one.as_slice()[..].to_vec();
            hasher.update(&slice);
            let step_two = hasher.finalize();

            let mut digest = step_one.as_slice()[..].to_vec();
            digest.append(&mut step_two.as_slice()[6..18].to_vec());

            print!("Derived key: ");
            for byte in &digest {
                print!("{:x}", byte);
            }
            println!("");

            let mut file = File::create("key")?;
            file.write_all(&digest)?;
            println!("Key written.");
        }
        Subcommand::Debug => {
            //retrofit ip keepalive until reload makes a proper one
            let outbound = ask("Server address with port? ");
            let bound_addr = format!("0.0.0.0:0");

            let socket = UdpSocket::bind(bound_addr)?;
            socket.connect(outbound.as_str())?;

            let crypto = {
                let mut buf: Vec<u8> = vec![];
                {
                    let mut file = File::open("asskey").expect("can't open keyfile, did you run 'areia key'?");
                    file.read_to_end(&mut buf).expect("can't read keyfile correctly, is shit fucked? remove 'key' in the current directory and rerun 'areia key'");
                }
                let key = Key::<Aes256Gcm>::from_slice(&buf[..32]);

                let cipher = Aes256Gcm::new(&key);

                println!("Cipher initialized successfully.");

                AesCipher { key: *key, cipher }
            };

            loop {
                /*
                let ip_keep = String::from("/setnick Retrofit_keepalive").into_bytes();
                let ip_keep = crypto.encrypt_packet(ip_keep.as_slice()).unwrap();
                socket.send(&ip_keep)?;
                */

                let ip_keep = String::from("just spout some random bullshit honestly").into_bytes();
                let ip_keep = crypto.encrypt_packet(ip_keep.as_slice()).unwrap();
                socket.send(&ip_keep)?;

                /*
                let mut buf = [0; 512];
                let (amt, src) = socket.recv_from(&mut buf)?;
                
                if amt < 1 {
                    continue;
                }

                let packet = &buf[..amt];
                // this should also be safe to unwrap because of
                // the fact that the server doesn't send malformed
                // packets. i think.
                let packet = crypto.decrypt_packet(packet).unwrap();

                if let Ok(parsed_str) = String::from_utf8(packet.to_vec()) {
                    println!("{parsed_str}");
                } else {
                    println!("[ERR] Invalid packet received!");
                }
                */

                std::thread::sleep(std::time::Duration::from_millis(120));
            }
        }
    }

    Ok(())
}
