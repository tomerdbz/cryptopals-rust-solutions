use openssl::error::ErrorStack;
pub fn decrypt_aes_128_ecb(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    use openssl::symm::decrypt;
    use openssl::symm::Cipher;

    return decrypt(Cipher::aes_128_ecb(), &key, None, encrypted_data);
}

pub fn detect_128_ecb(encrypted_blobs: &[&[u8]]) -> Vec<usize> {
    let mut ecb_blob_indexes = Vec::new();
    for (i, &blob) in encrypted_blobs.iter().enumerate() {
        let mut is_ecb = false;

        let mut blob_chunks = blob.chunks(16).collect::<Vec<&[u8]>>();
        blob_chunks.sort();

        for pair_chunks in blob_chunks.chunks(2) {
            if pair_chunks[0] == pair_chunks[1] {
                is_ecb = true;
            }
        }

        if is_ecb {
            ecb_blob_indexes.push(i);
        }
    }

    return ecb_blob_indexes;
}
