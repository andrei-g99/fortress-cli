mod fortress_lib;
use pbkdf2::{pbkdf2, hmac};
use hmac::Hmac;
use sha2::Sha256;
use std::env;

fn main() {
    // Get command-line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        println!("Please provide the required input.");
        return;
    }

    if args[1] == "encrypt"
    {
        let mut buf = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(args[4].as_bytes(), b"salt", 600_000, &mut buf)
        .expect("HMAC can be initialized with any key length");

        fortress_lib::encrypt(args[2].as_str(), args[3].as_str(), buf);


    }
    else if args[1] == "decrypt"
    {

        let mut buf = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(args[4].as_bytes(), b"salt", 600_000, &mut buf)
        .expect("HMAC can be initialized with any key length");

        let padding_byte : u8 = fortress_lib::decrypt(args[2].as_str(), args[3].as_str(), buf);
        fortress_lib::depad(args[2].as_str(), padding_byte);

    }
    else
    {
        panic!("First argument must be either 'encrypt' or 'decrypt' e.g.\n cargo run encrypt plaintext.txt ciphertext.bin passphrase123");
    }

}
