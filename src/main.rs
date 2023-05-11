mod arguments;
use arguments::*;
use clap::Parser;
use osshkeys::{Key, KeyPair, PrivateParts, error::Error, sshbuf::SshWriteExt, cipher::Cipher};

fn main() -> std::result::Result<(), Error> {
  let args = Arguments::parse();
  let file_contents = args.read_wordlist()?;

  let line_ending = args.get_line_ending(file_contents.clone());
  let file_output = args.populate_output_buffer(line_ending, file_contents);
  args.write_output(file_output);

  Ok(())
}
