mod fortress_lib;

fn main() {

    let key : [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 30, 31, 32];

    //fortress_lib::encrypt("plaintext.txt", "ciphertext.bin", key);
    let padding_byte : u8 = fortress_lib::decrypt("plaintext_decrypted.txt", "ciphertext.bin", key);
    fortress_lib::depad("plaintext_decrypted.txt", padding_byte);

}
