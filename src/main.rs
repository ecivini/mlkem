use mlkem::mlkem::*;
use clap::{arg, Command};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use base64::{engine::general_purpose, Engine as _};
use std::fs::File;
use std::io::prelude::*;

fn cli() -> Command {
  Command::new("mlkem")
    .about("Module Lattice-based Key Encapsulation Mechanism")
    .subcommand_required(true)
    .arg_required_else_help(true)
    .allow_external_subcommands(true)
    .subcommand(
        Command::new("keygen")
            .about("Generates a new key pair")
            .arg( 
              arg!(<KEY_LENGTH> "Key length. Must be 512, 768 or 1024.")
                .value_parser(clap::value_parser!(u16))
                .required(true)
            ).arg_required_else_help(true),
    )
}

fn keygen_and_store(key_length: u16) {
  let rng = ChaCha20Rng::from_entropy();
  let (ek, dk) = match keygen(key_length, rng) {
    Some((ek, dk)) => (ek ,dk),
    None => panic!("Invalid key length.")
  };

  let enc_file_data = "-----BEGIN ENCAPSULATION KEY-----".to_owned() + "\n\r" + 
    &general_purpose::STANDARD.encode(&ek).to_string() + "\n\r" + 
    "-----END ENCAPSULATION KEY-----";

  let dec_file_data = "-----BEGIN DECAPSULATION KEY-----".to_owned() + "\n\r" + 
    &general_purpose::STANDARD.encode(&dk).to_string() + "\n\r" + 
    "-----END DECAPSULATION KEY-----";

  let mut file = File::create("encapsulation.key").unwrap();
  if file.write_all(enc_file_data.as_bytes()).is_err() {
    println!("Unable to save encapsulation key.");
  }
 
  file = File::create("decapsulation.key").unwrap();
  if file.write_all(dec_file_data.as_bytes()).is_err() {
    println!("Unable to save decapsulation key.");
  }
}

fn main() {
  let matches = cli().get_matches();

  match matches.subcommand() {
    Some(("keygen", sub_matches)) => {
      let key_length = sub_matches.get_one::<u16>("KEY_LENGTH").unwrap();
      keygen_and_store(*key_length);
    },
    _ => unreachable!()
  }
}
