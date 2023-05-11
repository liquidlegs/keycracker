use clap::Parser;
use osshkeys::{KeyPair, cipher::Cipher, KeyType};
use serde::Serialize;
use std::{sync::mpsc, error::Error};

#[derive(Debug, Clone, Parser)]
#[clap(author, version, about)]
pub struct Arguments {
  #[clap(value_parser)]
  /// The input word list.
  pub wordlist: String,

  /// File to write the private keys
  #[clap(short, long)]
  pub output: Option<String>,

  #[clap(short, long, value_enum)]
  /// The type of private key o create.
  pub key_type: Option<ArgKeyType>,

  #[clap(short, long)]
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

pub const LR: &str = "\n";
pub const CRLF: &str = "\r\n";  

#[derive(Debug, Clone)]
pub enum LineEndings {
  LR,
  CRLR,
}

impl Arguments {

  // Works out whether each line uses \r\n or \n.
  pub fn get_line_ending(&self, file_contents: String) -> LineEndings {
    let mut out = LineEndings::CRLR;
    
    let mut content: Vec<&str> = file_contents.split(LR).collect();
    if content.len() > 1 {
      out = LineEndings::LR;
    }

    content = file_contents.split(CRLF).collect();
    if content.len() > 1 {
      out = LineEndings::CRLR;
    }

    out
  }

  // Reads a file into a string.
  pub fn read_wordlist(&self) -> std::io::Result<String> {
    let path = self.wordlist.clone();
    let file =  std::fs::read_to_string(path)?;

    Ok(file)
  }

  // Creates the structure to store passwords and private keys.
  pub fn populate_output_buffer(&self, ln: LineEndings, file_content: String) -> FileInputOutput {
    let mut bits = 0;
    
    match self.bits {
      Some(s) => {}
      None => { bits = 2048; }
    }
    
    let mut input_strings: Vec<String> = Default::default();
    let mut file_output = FileInputOutput::default();
    let mut line_end = "\r\n";

    match ln {
      LineEndings::LR =>    { line_end = "\n"; }
      _ => {}
    }

    let lines: Vec<&str> = file_content.split(line_end).collect();
    for i in lines {
      input_strings.push(String::from(i));
    }

    for i in input_strings {
      if let Ok(s) = Self::encrypt_pass_to_key(i.as_str(), bits, KeyType::RSA) {
        file_output.data.push(OutputKey {
          password: i,
          private_key: s,
        });
      }
    }

    file_output
  }

  // Write the FileInputOutput buffer content to a json file.
  pub fn write_output(&self, content: FileInputOutput) -> () {
    match serde_json::to_string_pretty(&content) {
      Ok(s) => {
        println!("{s}");
      },
      Err(e) => {}
    }
  }

  /**Function creates a d private key in the openssh format
   * Params:
   *  text: &str        {Passphrase to encrypt}
   *  bits: u32         {The bits / passes to encrypt the key}
   *  key:  KeyType     {The type of algorithim to use}
   * Returns String
   */
  pub fn encrypt_pass_to_key(text: &str, bits: usize, key: osshkeys::KeyType) -> std::result::Result<String, osshkeys::error::Error> {
    let pair = KeyPair::generate(key, bits)?;
    let key = pair.serialize_openssh(Some(text), Cipher::Aes256_Ctr)?;

    Ok(key)
  }

  /**function parses the input specified by the user and assigns it to the corresponding key algorithim type
   * Params:
   *  key_type: ArgKeyType {The key algorithim}
   * Returns KeyType
   */
  pub fn get_key_type(key_type: ArgKeyType) -> osshkeys::KeyType {
    let mut out = osshkeys::KeyType::RSA;

    match key_type {
      ArgKeyType::Dsa =>     { out = KeyType::DSA }
      ArgKeyType::Ecdsa =>   { out = KeyType::ECDSA }
      ArgKeyType::Ed25519 => { out = KeyType::ED25519 }
      ArgKeyType::Rsa =>     { out = KeyType::RSA }
      _ => {}
    }

    out
  }

  /**Function parses the users input and assigns it to the corresponding cipher.
   * Params:
   *  cipher: ArgCipher {The cipher to use}
   * Returns Cipher
   */
  pub fn get_cipher(cipher: ArgCipher) -> Cipher {
    let mut out = Cipher::Aes128_Cbc;

    match cipher {
      ArgCipher::Aes128Cbc => { out = Cipher::Aes128_Cbc }
      ArgCipher::Aes128Ctr => { out = Cipher::Aes128_Ctr }
      ArgCipher::Aes192Cbc => { out = Cipher::Aes192_Cbc }
      ArgCipher::Aes192Ctr => { out = Cipher::Aes192_Ctr }
      ArgCipher::Aes256Cbc => { out = Cipher::Aes256_Cbc }
      ArgCipher::Aes256Ctr => { out = Cipher::Aes256_Ctr }
      _ => {}    
    }

    out
  }

}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ArgKeyType {
  Rsa,
  Dsa,
  Ecdsa,
  Ed25519,
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
pub struct FileInputOutput {
  data: Vec<OutputKey>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct OutputKey {
  password: String,
  private_key: String,
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