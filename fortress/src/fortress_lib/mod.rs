use aes::Aes256;
use rand::{Rng, thread_rng};
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, SeekFrom, Seek};

pub fn encrypt(plaintext_path: &str, ciphertext_path: &str, key: [u8; 32])
{
    let mut file = File::open(plaintext_path).unwrap();
    let mut o_file = OpenOptions::new()
    .create(true)
    .append(true)
    .open(ciphertext_path).unwrap();

    let mut rng = thread_rng();

    let mut buffer: [u8; 16] = [0; 16];
    let mut rand_iv: [u8; 16] = [0; 16];
    rng.fill(&mut rand_iv);

    let iv: [u8; 16] = rand_iv;
 
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
            o_file.write_all(&iv[..]).unwrap();
            break;
        }
        else if bytes_read < 16
        {//last block

            //let slice : &[u8] = &buffer[0..bytes_read];
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
            
                for (i, (&a, &b)) in buffer.iter().zip(iv.iter()).enumerate() {
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
}

pub fn decrypt(plaintext_path: &str, ciphertext_path: &str, key: [u8; 32]) -> u8
{
    let mut file = File::open(ciphertext_path).unwrap();
    let mut o_file = OpenOptions::new()
    .create(true)
    .append(true)
    .open(plaintext_path).unwrap();

    let mut metadata: [u8; 17] = [0; 17];

    //get metadata from ciphertext
      let file_size = file.seek(SeekFrom::End(0)).unwrap();
    
      // Determine the starting position to read from
    if file_size > 17
    {
        file.seek(SeekFrom::End(-17)).unwrap();
    }
      
    file.read(&mut metadata[..]).unwrap();

    let padding_byte : u8 = metadata[0];
    let iv_slice : &[u8] = &metadata[1..];
    let mut iv : [u8; 16] = [0; 16];
    iv.copy_from_slice(iv_slice);

    let mut buffer: [u8; 16] = [0; 16];
 
    let mut prev_block: [u8; 16] = [0; 16];

    let mut init = false;
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut total_bytes_read = 0;
    loop {
        let bytes_read = file.read(&mut buffer).unwrap();
        total_bytes_read = total_bytes_read + (bytes_read as i32);
        if bytes_read == 0
        {//EOF reached
            break;
        }
        else
        {//normal block
            
            if init == false
            {
                //initial block
                let mut xor_result: [u8; 16] = [0; 16];
                //Decrypt ciphertext block 1
                let mut block = GenericArray::from(buffer.clone());
                let cipher = Aes256::new(&GenericArray::from(key.clone()));
                cipher.decrypt_block(&mut block);
                let mut decrypted_block : [u8; 16] = [0; 16];
                decrypted_block.copy_from_slice(block.as_slice());
                
                for (i, (&a, &b)) in decrypted_block.iter().zip(iv.iter()).enumerate() {
                    xor_result[i] = a ^ b;
                }
                //set prev_block for next rounds
                let u8_array: &[u8] = buffer.as_slice();
                prev_block.copy_from_slice(u8_array);
                //append to file
                o_file.write_all(&xor_result[..]).unwrap();
                
                init = true;
            }
            else 
            {
                if (file_size as i32) - total_bytes_read > 1
                {
                //normal block
                let mut xor_result: [u8; 16] = [0; 16];
                //Decrypt ciphertext block 1
                let mut block = GenericArray::from(buffer.clone());
                let cipher = Aes256::new(&GenericArray::from(key.clone()));
                cipher.decrypt_block(&mut block);
                let mut decrypted_block : [u8; 16] = [0; 16];
                decrypted_block.copy_from_slice(block.as_slice());
                
                for (i, (&a, &b)) in decrypted_block.iter().zip(prev_block.iter()).enumerate() {
                    xor_result[i] = a ^ b;
                }
                //set prev_block for next rounds
                let u8_array: &[u8] = buffer.as_slice();
                prev_block.copy_from_slice(u8_array);
                //append to file
                o_file.write_all(&xor_result[..]).unwrap();

                }
                
            }
        }

    }

    padding_byte

}

pub fn depad(plaintext_path: &str, padding_byte: u8)
{
    let mut o_file = OpenOptions::new()
    .create(false)
    .write(true)
    .open(plaintext_path).unwrap();
        // Get the size of the output file
    let o_file_size = o_file.seek(SeekFrom::End(0)).unwrap();
    
    // Calculate the new file size after deleting N bytes
    let new_size = if o_file_size > (padding_byte as u64) {
        o_file_size - (padding_byte as u64)
    } else {
        0
    };
    o_file.set_len(new_size).unwrap();
}
