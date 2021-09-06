#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mt19937_same_seed() {
        let random_numbers = generate(1, 10);
        let random_numbers_yet_again = generate(1, 10);

        assert_eq!(random_numbers, random_numbers_yet_again);
    }
    #[test]
    fn test_mt19937_different_seed() {
        let random_numbers = generate(1, 10);
        let different_random_numbers = generate(0, 10);

        assert_ne!(random_numbers, different_random_numbers);
    }

    #[test]
    fn test_mt19937_got_amount_asked() {
        let random_numbers = generate(1, 10);

        assert_eq!(random_numbers.len(), 10);
    }

    #[test]
    fn test_mt19937_struct_wrap_operates_same() {
        const AMOUNT_TO_GENERATE: usize = DEGREE_OF_RECURRENCE as usize + 2;
        let random_numbers = generate(0, AMOUNT_TO_GENERATE);
        let mut generator = Mt19937::new(0);
        let mut equal_random_numbers = Vec::new();
        for _ in 0..AMOUNT_TO_GENERATE {
            equal_random_numbers.push(generator.generate());
        }

        assert_eq!(random_numbers, equal_random_numbers);
    }

    #[test]
    fn test_mt19937_apply_cipher() {
        const PLAINTEXT: &[u8] = b"Hello? is it me you're looking for?";
        const KEY: u16 = 555;
        let ciphertext = apply_cipher(PLAINTEXT, KEY);

        assert_eq!(PLAINTEXT, apply_cipher(&ciphertext[..], KEY));
    }
}

use std::num::Wrapping;

// w
pub const WORD_SIZE: u8 = 32;
// n
pub const DEGREE_OF_RECURRENCE: u16 = 624;
// m
pub const MIDDLE_WORD: u16 = 397;
// r
pub const SEPERATION_POINT: u8 = 31;
// a
pub const TWIST_COEFFICIENTS: u32 = 0x9908B0DF;
// u, d, l
pub const TEMPERING_MASK_1: u8 = 11;
pub const TEMPERING_MASK_2: u32 = 0xFFFFFFFF;
pub const TEMPERING_MASK_3: u8 = 18;
// s, t
pub const TEMPERING_SHIFT_1: u8 = 7;
pub const TEMPERING_SHIFT_2: u8 = 15;
// b, c
pub const TEMPERING_BITMASK_1: u32 = 0x9D2C5680;
pub const TEMPERING_BITMASK_2: u32 = 0xEFC60000;

use std::collections::VecDeque;
pub struct Mt19937 {
    // XX - the pub is for the challenges
    pub state: VecDeque<u32>,
}

impl Mt19937 {
    pub fn new(seed: u32) -> Mt19937 {
        let mut x = VecDeque::new();
        x.push_back(seed);
        for i in 1..DEGREE_OF_RECURRENCE as usize {
            pub const F: u32 = 1812433253;
            x.push_back(
                (Wrapping(F) * Wrapping(x[i - 1] ^ (x[i - 1] >> (WORD_SIZE - 2)))
                    + Wrapping(i as u32))
                .0,
            );
        }

        Mt19937 { state: x }
    }

    pub fn generate(&mut self) -> u32 {
        pub const UPPER_MASK: u32 = 0xFFFFFFFF << SEPERATION_POINT;
        pub const LOWER_MASK: u32 = 0xFFFFFFFF >> (WORD_SIZE - SEPERATION_POINT);
        let concat = (self.state[0] & UPPER_MASK) | (self.state[1] & LOWER_MASK);

        let matrix_multiplication;
        if concat & 1 == 0 {
            matrix_multiplication = concat >> 1;
        } else {
            matrix_multiplication = (concat >> 1) ^ TWIST_COEFFICIENTS;
        }
        let x_k_n = self.state[MIDDLE_WORD as usize] ^ matrix_multiplication;
        self.state.push_back(x_k_n);

        self.state.pop_front();

        temper_transform(x_k_n)
    }
}

pub fn temper_transform(x: u32) -> u32 {
    let mut y = x ^ ((x >> TEMPERING_MASK_1) & TEMPERING_MASK_2);
    y = y ^ ((y << TEMPERING_SHIFT_1) & TEMPERING_BITMASK_1);
    y = y ^ ((y << TEMPERING_SHIFT_2) & TEMPERING_BITMASK_2);
    let z = y ^ (y >> TEMPERING_MASK_3);
    z
}

pub fn generate(seed: u32, amount_to_generate: usize) -> Vec<u32> {
    let temper_transform = |x| {
        let mut y = x ^ ((x >> TEMPERING_MASK_1) & TEMPERING_MASK_2);
        y = y ^ ((y << TEMPERING_SHIFT_1) & TEMPERING_BITMASK_1);
        y = y ^ ((y << TEMPERING_SHIFT_2) & TEMPERING_BITMASK_2);
        let z = y ^ (y >> TEMPERING_MASK_3);
        z
    };

    // initialize x series
    let mut x = Vec::new();
    x.push(seed);
    for i in 1..DEGREE_OF_RECURRENCE as usize {
        pub const F: u32 = 1812433253;
        x.push(
            (Wrapping(F) * Wrapping(x[i - 1] ^ (x[i - 1] >> (WORD_SIZE - 2))) + Wrapping(i as u32))
                .0,
        );
    }

    // generate
    let mut output: Vec<u32> = Vec::new();
    for k in 0..amount_to_generate {
        pub const UPPER_MASK: u32 = 0xFFFFFFFF << SEPERATION_POINT;
        pub const LOWER_MASK: u32 = 0xFFFFFFFF >> (WORD_SIZE - SEPERATION_POINT);
        let concat = (x[k] & UPPER_MASK) | (x[k + 1] & LOWER_MASK);

        let matrix_multiplication;
        if concat & 1 == 0 {
            matrix_multiplication = concat >> 1;
        } else {
            matrix_multiplication = (concat >> 1) ^ TWIST_COEFFICIENTS;
        }
        let x_k_n = x[k + MIDDLE_WORD as usize] ^ matrix_multiplication;
        x.push(x_k_n);

        output.push(temper_transform(x_k_n));
    }

    output
}

use byteorder::{ByteOrder, LittleEndian};
pub fn apply_cipher(data: &[u8], key: u16) -> Vec<u8> {
    let mut generator = Mt19937::new(key as u32);

    let keystream_byte_len = data.len();
    let mut keystream = Vec::new();
    for _ in 0..(keystream_byte_len as f32 / 4 as f32).ceil() as usize {
        let random_u32 = generator.generate();
        let mut random_u32_as_bytearray = [0; 4];
        LittleEndian::write_u32(&mut random_u32_as_bytearray, random_u32);
        keystream.extend_from_slice(&random_u32_as_bytearray[..]);
    }

    data.iter()
        .zip(keystream)
        .map(|(&b1, b2)| b1 ^ b2)
        .collect::<Vec<u8>>()
}

pub fn generate_password_reset_token() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now();
    let since_the_epoch = now.duration_since(UNIX_EPOCH).unwrap();
    let now_epoch = since_the_epoch.as_secs() as u32;
    let mut generator = Mt19937::new(now_epoch);
    generator.generate()
}
