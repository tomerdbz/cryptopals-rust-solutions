use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_break_repeating_xor() {
        let decoded_data = base64::decode(
            include_str!("../../resources/cryptopals_set1_challenge6.txt").replace("\n", ""),
        )
        .unwrap();
        let keys = break_repeating_xor(&decoded_data, Some(4));
        assert_eq!(
            String::from_utf8(keys[0].clone()).unwrap(),
            "Terminator X: Bring the noise"
        );
    }
}

pub fn break_repeating_xor(encrypted_data: &[u8], best: Option<usize>) -> Vec<Vec<u8>> {
    let mut inspected_keysizes = Vec::new();
    match get_keysize(&encrypted_data, 2..40, best) {
        KeysizeResult::Single(single_promising_keysize) => {
            inspected_keysizes.push(single_promising_keysize);
        }
        KeysizeResult::Multiple(most_promising_keysizes) => {
            inspected_keysizes = most_promising_keysizes;
        }
    };

    let mut keys = Vec::new();

    for keysize in inspected_keysizes {
        let mut key = Vec::new();
        let mut possible_key = true;
        for n in 0..keysize {
            let xord_with_nth_key_byte = fetch_nth_from_each_block(&encrypted_data, n, keysize);
            let score_on_lowercase = |output: &[u8]| {
                output
                    .iter()
                    .filter(|&c| (*c >= b'a' && *c <= b'z') || *c == b' ')
                    .count()
            };

            let is_weird_ascii = |output: &[u8]| {
                output
                    .iter()
                    .filter(|&c| *c < b' ' && *c != b'\n' && *c != b'\t')
                    .count()
                    == 0
            };

            let xor_byte_score = brute_force_xor_byte(&xord_with_nth_key_byte[..], |output| {
                score_on_lowercase(&output) * is_weird_ascii(&output) as usize
            });

            possible_key &= xor_byte_score.score > 0;

            if !possible_key {
                break;
            }

            key.push(xor_byte_score.xor_byte);
        }

        if possible_key {
            keys.push(key);
        }
    }

    keys
}

#[derive(PartialEq, Eq)]
struct XorByteScore {
    xor_byte: u8,
    score: usize,
}

impl Ord for XorByteScore {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.score.cmp(&other.score)
    }
}
impl PartialOrd for XorByteScore {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.score.cmp(&other.score))
    }
}

fn brute_force_xor_byte(arr: &[u8], score_output: impl Fn(&[u8]) -> usize) -> XorByteScore {
    let mut max_xor_byte_score = XorByteScore {
        xor_byte: 0,
        score: 0,
    };
    for possible_xor_byte in 1..u8::MAX {
        let output_bytes: Vec<u8> = arr.iter().map(|b| b ^ possible_xor_byte).collect();
        let score = score_output(&output_bytes[..]);

        let new_score = XorByteScore {
            score,
            xor_byte: possible_xor_byte,
        };

        if new_score.cmp(&max_xor_byte_score).is_gt() {
            max_xor_byte_score = new_score;
        }
    }

    max_xor_byte_score
}

fn fetch_nth_from_each_block(arr: &[u8], n: u8, keysize: u8) -> Vec<u8> {
    let iterations = arr.len() / keysize as usize;
    let mut out = Vec::new();

    for i in 0..iterations {
        out.push(arr[i * keysize as usize + n as usize]);
    }

    return out;
}

enum KeysizeResult {
    Single(u8),
    Multiple(Vec<u8>),
}

fn get_keysize(
    encrypted_data: &[u8],
    range: std::ops::Range<u8>,
    best: Option<usize>,
) -> KeysizeResult {
    let mut keysize_to_hamming_distance: HashMap<u8, f64> = HashMap::new();

    for possible_keysize in range {
        let block_pairs_analyzed = [1, 2, 3];
        let mut hamming_distance_sum = 0;
        for block in block_pairs_analyzed {
            let first_slice = &encrypted_data
                [block * (possible_keysize as usize)..(block + 1) * (possible_keysize as usize)];
            let second_slice = &encrypted_data[(block + 1) * (possible_keysize as usize)
                ..(block + 2) * (possible_keysize as usize)];

            hamming_distance_sum += hamming_distance(first_slice, second_slice);
        }
        let average_hamming_distance = hamming_distance_sum / block_pairs_analyzed.len();

        let normalized_hamming_distance = average_hamming_distance as f64 / possible_keysize as f64;

        keysize_to_hamming_distance.insert(possible_keysize, normalized_hamming_distance);
    }

    let result = match best {
        None => KeysizeResult::Single(
            *keysize_to_hamming_distance
                .iter()
                .min_by(|(_, v1), (_, v2)| v1.partial_cmp(v2).unwrap())
                .unwrap()
                .0,
        ),
        Some(top_n) => {
            let mut tuple_vector: Vec<(&u8, &f64)> = keysize_to_hamming_distance.iter().collect();
            KeysizeResult::Multiple({
                tuple_vector.sort_by(|t1, t2| t1.1.partial_cmp(t2.1).unwrap());
                tuple_vector[..top_n]
                    .into_iter()
                    .map(|t| *t.0)
                    .collect::<Vec<u8>>()
                    .to_vec()
            })
        }
    };

    return result;
}

fn hamming_distance(s1: &[u8], s2: &[u8]) -> usize {
    use bitvec::prelude::*;
    let b1 = s1.view_bits::<Msb0>();
    let b2 = s2.view_bits::<Msb0>();
    let mut distance = 0;

    for i in 0..std::cmp::max(b1.len(), b2.len()) {
        if b1[i] != b2[i] {
            distance += 1;
        }
    }

    return distance;
}
