pub fn apply_repeating_xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();

    for (pos, b) in data.iter().enumerate() {
        let xor_byte = key[pos % key.len()];
        let xored_byte = b ^ xor_byte;
        out.push(xored_byte);
    }

    return out;
}

pub fn apply_xor(data: &[u8], key: &[u8], start: usize) -> Vec<u8> {
    let mut xored = Vec::new();

    for (pos, b) in data[start..start + key.len()].iter().enumerate() {
        let xor_byte = key[pos];
        let xored_byte = b ^ xor_byte;
        xored.push(xored_byte);
    }

    data.to_vec()
        .splice(start..start + key.len(), xored)
        .collect::<Vec<u8>>()
}
