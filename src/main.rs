use mlkem::*;
use clap::{arg, Command};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use base64::{engine::general_purpose, Engine as _};
use std::fs::{self, File};
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
    .subcommand(
      Command::new("encapsulate")
        .about("Generates a shared key and the associated ciphertext")
        .arg( 
          arg!(<EK_KEY_PATH> "Encapsulation key file path.")
            .required(true)
        ).arg_required_else_help(true)
    )
    .subcommand(
      Command::new("decapsulate")
        .about("Generates a shared key given the decapsulation key and a ciphertext")
        .arg( 
          arg!(<DK_KEY_PATH> "Decapsulation key file path.")
            .required(true)
        )
        .arg( 
          arg!(<C_PATH> "Ciphertext file path.")
            .required(true)
        )
        .arg_required_else_help(true)
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

    
  let mut no_errors = true;
  let mut file = File::create("encapsulation.key").unwrap();
  if file.write_all(enc_file_data.as_bytes()).is_err() {
    println!("Unable to save encapsulation key.");
    no_errors = false;
  }
 
  file = File::create("decapsulation.key").unwrap();
  if file.write_all(dec_file_data.as_bytes()).is_err() {
    println!("Unable to save decapsulation key.");
    no_errors = false;
  }
  
  if no_errors {
    println!("Encapsulation and decapsulation keys generated correctly.\nYou can find them in encapsulation.key and decapsulation.key.");
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

  let mut no_errors = true;
  let mut file = File::create("shared_enc.key").unwrap();
  if file.write_all(b64_shared_key.as_bytes()).is_err() {
    println!("Unable to save shared key.");
    no_errors = false;
  }

  file = File::create("ciphertext.txt").unwrap();
  if file.write_all(b64_ciphertext.as_bytes()).is_err() {
    println!("Unable to save associated ciphertext.");
    no_errors = false;
  }

  if no_errors {
    println!("Shared key generated correctly.\nYou can find it in shared_enc.key");
  }
}

fn read_key_and_decapsulate(dk_path: String, c_path: String) {
  let raw_dk = fs::read_to_string(dk_path).expect("Invalid key path.");
  let encoded_c = fs::read_to_string(c_path).expect("Invalid ciphertext path.");

  let mut encoded_dk = raw_dk.split("-----").nth(2).expect("Invalid key file.").chars();
  encoded_dk.next();
  encoded_dk.next_back();

  let dk = general_purpose::STANDARD.decode(encoded_dk.as_str()).unwrap();
  let c = general_purpose::STANDARD.decode(encoded_c.as_str()).unwrap();

  let shared_key = match decapsulate(dk, c) {
    Some(shared_key) => shared_key,
    None => {
      println!("Invalid key length.");
      return;
    }
  };

  let b64_shared_key = general_purpose::STANDARD.encode(&shared_key).to_string();

  let mut file = File::create("shared_dec.key").unwrap();
  if file.write_all(b64_shared_key.as_bytes()).is_err() {
    println!("Unable to save shared key.");
  } else {
    println!("Shared key generated correctly.\nYou can find it in shared_dec.key");
  }
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
    // Decapsulation
    Some(("decapsulate", sub_matches)) => {
      let dk_path = sub_matches.get_one::<String>("DK_KEY_PATH").unwrap();
      let c_path = sub_matches.get_one::<String>("C_PATH").unwrap();
      read_key_and_decapsulate(dk_path.to_string(), c_path.to_string());
    },
    _ => unreachable!()
  }
}
