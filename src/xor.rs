pub fn apply_repeating_xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();

    for (pos, b) in data.iter().enumerate() {
        let xor_byte = key[pos % key.len()];
        let xored_byte = b ^ xor_byte;
        out.push(xored_byte);
    }

    return out;
}
