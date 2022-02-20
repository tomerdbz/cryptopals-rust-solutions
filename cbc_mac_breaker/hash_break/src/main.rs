use std::io::prelude::*;

fn get_last_block<'a>(block: &'a [u8]) -> &'a [u8] {
    &block[block.len() - 16..block.len()]
}

fn main() {
    const MALICIOUS_SCRIPT: &[u8] = b"alert('Ayo, the Wu is back!');///";
    const KEY: &[u8] = b"YELLOW SUBMARINE";
    const ORIGINAL_SCRIPT: &[u8] = b"alert('MZA who was that?');\n";
    const ZERO_BLOCK: [u8; 16] = [0; 16];

    // starting with the malicious command, commenting the remainder
    // an extra / is necessary, without it - the output has a newline that ruins the comment
    let malicious_script_encrypted =
        crypto::aes::encrypt_cbc_ecb_128_bit(MALICIOUS_SCRIPT, KEY, &ZERO_BLOCK);
    let malicious_script_last_block = get_last_block(&malicious_script_encrypted[..]);

    // the idea is to get back to the state where we have an "IV" of zeroes
    // with the original script
    let decrypted_zero_block = crypto::aes::decrypt_aes_128_ecb(&ZERO_BLOCK, KEY).unwrap();

    // what should be appended to the malicious script to get back to the zero IV state
    // before I append the original script?
    let desired_plaintext: Vec<u8> = malicious_script_last_block
        .iter()
        .zip(decrypted_zero_block)
        .map(|(&b1, b2)| b1 ^ b2)
        .collect();

    // the 15's are pkcs7 padding the last block of the malicious script has
    let malicious_msg_same_hash = [
        &MALICIOUS_SCRIPT[..],
        &[15; 15],
        &desired_plaintext[..],
        &ORIGINAL_SCRIPT[..],
    ]
    .concat();

    let mut file = std::fs::File::create("malicious.txt").unwrap();
    file.write_all(&malicious_msg_same_hash).unwrap();

    let cbc_encrypted_malicious_input =
        crypto::aes::encrypt_cbc_ecb_128_bit(&malicious_msg_same_hash[..], KEY, &[0; 16]);
    let malicious_input_cbc_mac = hex::encode(get_last_block(&cbc_encrypted_malicious_input));

    println!("cbc-mac should be 296b8d7cb78a243dda4d0a61d33bbdd1");
    println!("cbc-mac is {}", malicious_input_cbc_mac);
}
