use anyhow::anyhow;
use anyhow::{Context, Result};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305};
use des::cipher::*;
use des::Des;
use generic_array::{typenum::U8, GenericArray};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

pub struct Crypto;

impl Crypto {
    pub fn read_ciphertext_from_file(path: &str) -> io::Result<Vec<u8>> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        let limit_size: usize = 512; // Limit the buffer to the first 512 characters

        if buffer.len() > limit_size {
            buffer.truncate(limit_size);
        }

        Ok(buffer)
    }

    pub fn chaca20poly1305(
        path: &String,
        key: &[u8; 32],
        nonce: &[u8; 24],
        is_encrypt: bool,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let file_data = fs::read(path)?;
        let file = if is_encrypt {
            cipher
                .encrypt(nonce.into(), file_data.as_ref())
                .map_err(|err| anyhow!("Error encrypting file: {}", err))?
        } else {
            cipher
                .decrypt(nonce.into(), file_data.as_ref())
                .map_err(|err| anyhow!("Error decrypting file: {}", err))?
        };
        // let extension = if is_encrypt { ".encrypted" } else { "" };
        fs::write(format!("{}", path), file)?;
        let ciphertext = Self::read_ciphertext_from_file(path)?;
        Ok(ciphertext)
    }

    pub fn des(path: &str, key: &[u8; 32], is_encrypt: bool) -> Result<Vec<u8>, anyhow::Error> {
        let key_array = GenericArray::<u8, U8>::clone_from_slice(&key[..8]); // Convert key to GenericArray
        let des = Des::new(&key_array); // Initialize DES with the key
        let temp_file_path = format!("{}.tmp", path); // Create a temporary file
        let mut temp_file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&temp_file_path)
            .with_context(|| format!("Unable to open temporary file: {}", temp_file_path))?;

        // Open the input file
        let mut input_file =
            File::open(path).with_context(|| format!("Unable to open input file: {}", path))?;
        let mut buffer = Vec::new();
        input_file
            .read_to_end(&mut buffer)
            .with_context(|| "Unable to read input file")?;

        // Process data block by block
        let block_size = 8; // DES block size is 8 bytes
        let mut processed_data = Vec::new();

        if is_encrypt {
            // Add padding if encrypting
            let padding_len = block_size - (buffer.len() % block_size);
            buffer.extend(vec![padding_len as u8; padding_len]); // PKCS7 padding
        }

        for chunk in buffer.chunks(block_size) {
            let mut block = GenericArray::default();
            block.copy_from_slice(chunk);

            if is_encrypt {
                des.encrypt_block(&mut block);
            } else {
                des.decrypt_block(&mut block);
            }
            processed_data.extend_from_slice(&block);
        }

        if !is_encrypt {
            // Remove padding if decrypting
            if let Some(&padding_len) = processed_data.last() {
                let padding_len = padding_len as usize;
                if padding_len <= block_size
                    && processed_data.ends_with(&vec![padding_len as u8; padding_len])
                {
                    processed_data.truncate(processed_data.len() - padding_len);
                }
            }
        }

        temp_file
            .write_all(&processed_data)
            .with_context(|| "Unable to write processed data to temporary file")?;

        // Replace the original file with the temporary file
        std::fs::rename(&temp_file_path, path).with_context(|| {
            format!(
                "Unable to replace original file with temporary file: {}",
                path
            )
        })?;
        let ciphertext = Self::read_ciphertext_from_file(path)?;
        Ok(ciphertext)
    }
}
