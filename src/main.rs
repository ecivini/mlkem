use mlkem::mlkem::*;
use clap::{arg, Command};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

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

  println!("Encapsulation key: {:?}\n\n", ek);
  println!("Decapsulation key: {:?}\n\n", dk);
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
