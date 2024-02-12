use mlkem::mlkem::*;
use clap::{arg, Command};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use base64::{engine::general_purpose, Engine as _};
use std::fs::{self, File};
use std::io::prelude::*;
use std::ops::Deref;
use std::os::macos::raw;

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
    .subcommand(
      Command::new("encapsulate")
        .about("Generates a shared key and the associated ciphertext")
        .arg( 
          arg!(<EK_KEY_PATH> "Encapsulation key file path.")
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

  let enc_file_data = "-----BEGIN ENCAPSULATION KEY-----".to_owned() + "\n" + 
    &general_purpose::STANDARD.encode(&ek).to_string() + "\n" + 
    "-----END ENCAPSULATION KEY-----";

  let dec_file_data = "-----BEGIN DECAPSULATION KEY-----".to_owned() + "\n" + 
    &general_purpose::STANDARD.encode(&dk).to_string() + "\n" + 
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

fn read_key_and_encapsulate(path: String) {
  let raw_ek = fs::read_to_string(path).expect("Invalid key path.");

  let mut encoded_ek = raw_ek.split("-----").nth(2).expect("Invalid key file.").chars();
  encoded_ek.next();
  encoded_ek.next_back();

  let ek = &general_purpose::STANDARD.decode(encoded_ek.as_str()).unwrap();

  let rng = ChaCha20Rng::from_entropy();
  let (shared_key, c) = match encapsulate(ek.clone(), rng) {
    Some((key, c)) => (key, c),
    None => {
      println!("Invalid key length.");
      return;
    }
  };

  let b64_shared_key = general_purpose::STANDARD.encode(&shared_key).to_string();
  let b64_ciphertext = general_purpose::STANDARD.encode(&c).to_string();

  println!("Shared key: {:?}\n\nAssociated ciphertext: {:?}", b64_shared_key, b64_ciphertext);
}

fn main() {
  let matches = cli().get_matches();

  match matches.subcommand() {
    // Key generation
    Some(("keygen", sub_matches)) => {
      let key_length = sub_matches.get_one::<u16>("KEY_LENGTH").unwrap();
      keygen_and_store(*key_length);
    },
    // Encapsulation
    Some(("encapsulate", sub_matches)) => {
      let path = sub_matches.get_one::<String>("EK_KEY_PATH").unwrap();
      read_key_and_encapsulate(path.to_string());
    },
    _ => unreachable!()
  }
}
