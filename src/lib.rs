pub mod aes;
pub mod xor;

#[cfg(test)]
mod tests {
    #[test]
    fn test_break_repeating_xor() {
        let decoded_data = base64::decode(
            include_str!("../resources/cryptopals_set1_challenge6.txt").replace("\n", ""),
        )
        .unwrap();
        let keys = super::xor::break_repeating_xor(&decoded_data, Some(4));
        assert_eq!(
            String::from_utf8(keys[0].clone()).unwrap(),
            "Terminator X: Bring the noise"
        );
    }

    #[test]
    fn test_decrypt_aes_128_ecb() {
        let decoded_data = base64::decode(
            include_str!("../resources/cryptopals_set1_challenge7.txt").replace("\n", ""),
        )
        .unwrap();
        let decrypted_data = super::aes::decrypt_aes_128_ecb(&decoded_data, b"YELLOW SUBMARINE");

        assert_eq!(decrypted_data.is_ok(), true);
    }

    #[test]
    fn test_detect_128_ecb() {
        let decoded_data: Vec<Vec<u8>> =
            include_str!("../resources/cryptopals_set1_challenge8.txt")
                .split("\n")
                .collect::<Vec<&str>>()
                .iter()
                .filter_map(|s| {
                    let decoded = hex::decode(s).unwrap();
                    if decoded.len() > 0 {
                        Some(decoded)
                    } else {
                        None
                    }
                })
                .collect();
        let decoded_data_view: Vec<&[u8]> = decoded_data.iter().map(|v| &v[..]).collect();
        let detected_ecb_indexes = super::aes::detect_128_ecb(&decoded_data_view[..]);

        assert_eq!(detected_ecb_indexes.len(), 1);
    }
}
