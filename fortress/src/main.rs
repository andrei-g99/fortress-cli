mod fortress_lib;
use aes::Aes256;
use rand::{Rng, thread_rng};
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};


fn main() {

    let mut file = File::open("plaintext.txt").unwrap();
    let mut o_file = OpenOptions::new()
    .create(true)
    .append(true)
    .open("ciphertext.bin").unwrap();

    let key : [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8,
                          9, 10, 11, 12, 13, 14, 15, 16,
                          17, 18, 19, 20, 21, 22, 23, 24,
                          25, 26, 27, 28, 29, 30, 31, 32];
    let mut rng = thread_rng();

    let mut buffer: [u8; 16] = [0; 16];
    let mut rand_iv: [u8; 16] = [0; 16];
    rng.fill(&mut rand_iv);

    let IV: [u8; 16] = rand_iv;
    println!("IV: {:?}", &IV);////////////////////////////
    let mut prev_block: [u8; 16] = [0; 16];

    let mut init = false;
    let mut last_block_encountered = false;

    loop {
        let bytes_read = file.read(&mut buffer).unwrap();

        if bytes_read == 0
        {//EOF reached

            if last_block_encountered == false
            {
                //file divides perfectly into blocks, set padding byte to 0
                let padding_byte: u8 = 0;
                let slice: &[u8] = std::slice::from_ref(&padding_byte);
                o_file.write_all(slice).unwrap();
            }
            //append IV to binary (16 bytes)     [total of 17 metadata bytes at the end of the binary: padding + IV]
            o_file.write_all(&IV[..]).unwrap();
            break;
        }
        else if bytes_read < 16
        {//last block

            let slice : &[u8] = &buffer[0..bytes_read];
            for index in bytes_read..16 {
                //pad with 0u bytes
                buffer[index] = 0;
            }

            last_block_encountered = true;
            let mut xor_result: [u8; 16] = [0; 16];
            
            for (i, (&a, &b)) in buffer.iter().zip(prev_block.iter()).enumerate() {
                xor_result[i] = a ^ b;
            }
                //Encrypt xor_result
                let mut block = GenericArray::from(xor_result.clone());
                let cipher = Aes256::new(&GenericArray::from(key.clone()));
                cipher.encrypt_block(&mut block);
                let u8_array: &[u8] = block.as_slice();
                //append to file
                o_file.write_all(u8_array).unwrap();
            //append one byte specifying how many padded bytes are present in the last block (from 0 to 15)
            let u8_bytes_read : u8 = bytes_read.try_into().unwrap();
            let padding_byte: u8 = 16 - u8_bytes_read;
            let slice: &[u8] = std::slice::from_ref(&padding_byte);
            o_file.write_all(slice).unwrap();
            //println!("{:?}", &slice);
        }
        else
        {//normal block
            
            if init == false
            {
                //initial block
                // IV xor BLOCK_1
                let mut xor_result: [u8; 16] = [0; 16];
            
                for (i, (&a, &b)) in buffer.iter().zip(IV.iter()).enumerate() {
                    xor_result[i] = a ^ b;
                }
                //Encrypt xor_result
                let mut block = GenericArray::from(xor_result.clone());
                let cipher = Aes256::new(&GenericArray::from(key.clone()));
                cipher.encrypt_block(&mut block);
                //set prev_block for next rounds
                let u8_array: &[u8] = block.as_slice();
                prev_block.copy_from_slice(u8_array);
                //append to file
                o_file.write_all(u8_array).unwrap();
                
                init = true;
            }
            else 
            {
                // PREV CIPHER BLOCK xor CURRENT PLAIN BLOCK
                let mut xor_result: [u8; 16] = [0; 16];
            
                for (i, (&a, &b)) in buffer.iter().zip(prev_block.iter()).enumerate() {
                    xor_result[i] = a ^ b;
                }
                //Encrypt xor_result
                let mut block = GenericArray::from(xor_result.clone());
                let cipher = Aes256::new(&GenericArray::from(key.clone()));
                cipher.encrypt_block(&mut block);
                //set prev_block for next rounds
                let u8_array: &[u8] = block.as_slice();
                prev_block.copy_from_slice(u8_array);
                //append to file
                o_file.write_all(u8_array).unwrap();

                
            }
        }

    }


    // let mut binary = read_file_as_vec("plaintext.txt").unwrap();
    // let nr_blocks : usize = calc_block_nr(&binary.len());
    // let file_blocks : Vec<[u8; 16]> = Vec::new();

    // println!("file byte size: {}, file blocks needed: {}", &binary.len(),&nr_blocks);
    //println!("{:?}", &binary);
    // let mut rng = thread_rng();
    // let mut data: [u8; 16] = [87, 237, 149, 99, 133, 145, 233, 157, 181, 115, 244, 162, 48, 2, 228, 91];
    // let key : [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8,
    //                       9, 10, 11, 12, 13, 14, 15, 16,
    //                       17, 18, 19, 20, 21, 22, 23, 24,
    //                       25, 26, 27, 28, 29, 30, 31, 32];
    // //rng.fill(&mut data);
    // //println!("{:?}", &data);
    // let mut block = GenericArray::from(data.clone());
    // let cipher = Aes256::new(&GenericArray::from(key.clone()));
    // let data_copy = data.clone();
    // println!("{:?}", &block);
    // cipher.encrypt_block(&mut block);
    // println!("{:?}", &block);

}
