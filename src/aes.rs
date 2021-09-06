use crate::padding;
use openssl::error::ErrorStack;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_aes_128_ecb() {
        let decoded_data = base64::decode(
            include_str!("../resources/cryptopals_set1_challenge7.txt").replace("\n", ""),
        )
        .unwrap();
        let decrypted_data = decrypt_aes_128_ecb(&decoded_data, b"YELLOW SUBMARINE");

        assert_eq!(decrypted_data.is_ok(), true);
    }

    #[test]
    fn test_ecb_encrypt_decrypt() {
        let decoded_data = base64::decode(
            include_str!("../resources/cryptopals_set1_challenge7.txt").replace("\n", ""),
        )
        .unwrap();

        let decrypted_data = decrypt_aes_128_ecb(&decoded_data, b"YELLOW SUBMARINE").unwrap();

        let reencrypted_data = encrypt_aes_128_ecb(&decrypted_data, b"YELLOW SUBMARINE");

        assert_eq!(reencrypted_data.unwrap(), decoded_data);
    }

    #[test]
    fn test_ecb_encrypt_decrypt_divide_to_chunks() {
        let decoded_data = base64::decode(
            include_str!("../resources/cryptopals_set1_challenge7.txt").replace("\n", ""),
        )
        .unwrap();

        let blocks: Vec<&[u8]> = decoded_data.chunks(16).collect();
        let (last, elements) = blocks.split_last().unwrap();

        for block in elements {
            assert_eq!(
                decrypt_aes_128_ecb(block, b"YELLOW SUBMARINE").is_ok(),
                true
            );
        }
        assert_eq!(decrypt_aes_128_ecb(last, b"YELLOW SUBMARINE").is_ok(), true);
    }

    #[test]
    fn test_cbc_decrypt() {
        let decoded_data = base64::decode(
            include_str!("../resources/cryptopals_set2_challenge10.txt").replace("\n", ""),
        )
        .unwrap();

        let decrypted_data = String::from_utf8(
            decrypt_cbc_ecb_128_bit(&decoded_data, b"YELLOW SUBMARINE", &vec![0; 16]).unwrap(),
        )
        .unwrap();

        assert_eq!(decrypted_data.ends_with("Play that funky music \n"), true);
    }

    #[test]
    fn test_cbc_encrypt_decrypt() {
        let data_to_encrypt =
            b"YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE_EH";

        let encrypted_data =
            encrypt_cbc_ecb_128_bit(&data_to_encrypt[..], b"YELLOW SUBMARINE", &vec![0; 16]);

        let decrypted_data =
            decrypt_cbc_ecb_128_bit(&encrypted_data, b"YELLOW SUBMARINE", &vec![0; 16]).unwrap();
        assert_eq!(decrypted_data, *data_to_encrypt);
    }
}

pub fn decrypt_aes_128_ecb(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    use openssl::symm::Cipher;
    use openssl::symm::Crypter;
    use openssl::symm::Mode;
    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None)?;
    crypter.pad(false);

    let mut output = vec![0; encrypted_data.len() + 16];

    crypter.update(&encrypted_data[..], &mut output)?;

    crypter.finalize(&mut output)?;

    return Ok(output.drain(..encrypted_data.len()).collect());
}

pub fn encrypt_aes_128_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    use openssl::symm::Cipher;
    use openssl::symm::Crypter;
    use openssl::symm::Mode;
    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None).unwrap();
    crypter.pad(false);
    let mut output = vec![0; data.len() + 16];

    crypter.update(&data[..], &mut output)?;

    crypter.finalize(&mut output)?;

    return Ok(output.drain(..data.len()).collect::<Vec<u8>>());
}

pub fn encrypt_cbc_ecb_128_bit(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let block_length = 16;

    let mut last_encrypted_block: &[u8] = iv;
    let mut encrypted_blocks: Vec<Vec<u8>> = Vec::new();

    let blocks: Vec<&[u8]> = data.chunks(block_length).collect();
    let (last, chunks) = blocks.split_last().unwrap();

    for chunk in chunks {
        let input_to_block_cipher: Vec<u8> = last_encrypted_block
            .iter()
            .zip(*chunk)
            .map(|(&b1, &b2)| b1 ^ b2)
            .collect();

        encrypted_blocks.push(encrypt_aes_128_ecb(&input_to_block_cipher[..], &key).unwrap());

        last_encrypted_block = encrypted_blocks.last().unwrap();
    }
    if last.len() < block_length {
        let input_to_block_cipher: Vec<u8> = last_encrypted_block
            .iter()
            .zip(padding::pkcs7(last, block_length).unwrap())
            .map(|(b1, b2)| b1 ^ b2)
            .collect();

        encrypted_blocks.push(encrypt_aes_128_ecb(&input_to_block_cipher[..], &key).unwrap());
    } else {
        let input_to_block_cipher: Vec<u8> = last_encrypted_block
            .iter()
            .zip(last.to_vec())
            .map(|(b1, b2)| b1 ^ b2)
            .collect();

        encrypted_blocks.push(encrypt_aes_128_ecb(&input_to_block_cipher[..], &key).unwrap());
        let padding_block_input_to_block_cipher: Vec<u8> = encrypted_blocks
            .last()
            .unwrap()
            .iter()
            .zip(vec![16; 16])
            .map(|(b1, b2)| b1 ^ b2)
            .collect();
        encrypted_blocks
            .push(encrypt_aes_128_ecb(&padding_block_input_to_block_cipher[..], &key).unwrap());
    }
    let output_vector: Vec<u8> =
        Vec::with_capacity(encrypted_blocks.iter().fold(0, |acc, b| acc + b.len()));

    let encrypted_data = encrypted_blocks
        .iter_mut()
        .fold(output_vector, |mut acc, v| {
            acc.append(v);
            acc
        });

    return encrypted_data;
}

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    InvalidArgument,
    ParsingError(padding::Pkcs7ParsingError),
}

use std::fmt;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unable to proceed with aes")
    }
}

impl std::error::Error for Error {}

pub fn decrypt_cbc_ecb_128_bit(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
    let block_length = 16;
    let mut last_chunk: &[u8] = iv;
    let mut decrypted_blocks: Vec<Vec<u8>> = Vec::new();

    let blocks: Vec<&[u8]> = data.chunks(block_length).collect();
    let (last, chunks) = blocks.split_last().ok_or(Error::InvalidArgument)?;

    for chunk in chunks {
        let cipher_decrypted = decrypt_aes_128_ecb(chunk, key).unwrap();

        let decrypted_block: Vec<u8> = cipher_decrypted
            .iter()
            .zip(last_chunk)
            .map(|(&b1, &b2)| b1 ^ b2)
            .collect();

        decrypted_blocks.push(decrypted_block);

        last_chunk = chunk;
    }

    let cipher_decrypted = decrypt_aes_128_ecb(last, key).unwrap();

    let decrypted_block: Vec<u8> = cipher_decrypted
        .iter()
        .zip(last_chunk)
        .map(|(&b1, &b2)| b1 ^ b2)
        .collect();

    decrypted_blocks.push(
        padding::remove_pkcs7(&decrypted_block[..]).or_else(|e| Err(Error::ParsingError(e)))?,
    );

    let data = decrypted_blocks
        .iter_mut()
        .fold(Vec::with_capacity(data.len()), |mut acc, v| {
            acc.append(v);
            acc
        });
    return Ok(data);
}
