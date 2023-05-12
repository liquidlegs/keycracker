mod arguments;
use arguments::*;
use clap::Parser;
use osshkeys::error::Error;

fn main() -> std::result::Result<(), Error> {
  let args = Arguments::parse();

  let user_content = Arguments::read_wordlist(args.usr_wordlist.as_str())?;  
  let pass_content = Arguments::read_wordlist(&args.pwr_wordlist.as_str())?;
  let usr_ln = Arguments::get_line_ending(user_content.clone());
  let pwr_ln = Arguments::get_line_ending(pass_content.clone());

  let file_output = args.populate_output_buffer(usr_ln, pwr_ln, user_content, pass_content);
  args.write_output(file_output);

  Ok(())
}
