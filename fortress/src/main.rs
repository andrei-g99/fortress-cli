mod fortress_lib;
use pbkdf2::{pbkdf2, hmac};
use hmac::Hmac;
use sha2::Sha256;
use std::env;

fn is_valid_string(input: &str) -> bool {
    if input.len() > 32 {
        return false;
    }

    for ch in input.chars() {
        if !ch.is_ascii() || ch.is_whitespace() {
            return false;
        }
    }

    true
}

fn main() {
    // Get command-line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() != 5 {
        println!("Please provide the required input. (4 parameters) e.g. <encrypt/decrypt> <plaintext_filename.format> <cipher_filename.format> <passphrase>");
        return;
    }
    if is_valid_string(&args[2]) && is_valid_string(&args[3]) && is_valid_string(&args[4])
    {
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
            panic!("First argument must be either 'encrypt' or 'decrypt' e.g.\n encrypt plaintext.txt ciphertext.bin passphrase123");
        }
    }


}
