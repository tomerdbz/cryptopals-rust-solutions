use crate::mt19937;
use rand;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
mod tests {
    use super::*;
    use mt19937;

    /*
    the generation takes quite a while... so for now let's keep it commented out
    #[test]
    fn test_crack_mt19937_seed() {
        assert!(crack_mt19937_seed(generate_u32()).is_some());
    }*/

    #[test]
    fn test_reverse_temper_transform() {
        let temper_transform_output = mt19937::temper_transform(2443250962);
        let reversed = reverse_temper_transform(temper_transform_output);

        assert_eq!(reversed, 2443250962);
    }

    #[test]
    fn test_clone_rng() {
        let mut generator = mt19937::Mt19937::new(0);
        for _ in 0..mt19937::DEGREE_OF_RECURRENCE {
            generator.generate();
        }
        let mut cloned_rng = clone_rng(0);
        assert_eq!(cloned_rng.generate(), generator.generate());
    }

    #[test]
    fn test_password_token_seeded_from_unix_timestamp() {
        assert_eq!(
            is_password_reset_token_unix_timestamp_seeded(mt19937::generate_password_reset_token()),
            true
        );
    }

    #[test]
    fn test_password_token_not_seeded_from_unix_timestamp() {
        assert_eq!(is_password_reset_token_unix_timestamp_seeded(1024), false);
    }

    #[test]
    fn test_break_mt19937_cipher() {
        use rand::prelude::*;

        const KNOWN_END: [u8; 14] = [b'A'; 14];
        let key: u16 = random();
        let mut rng = rand::thread_rng();

        let random_prepend_len: u8 = rand::random();
        let mut plaintext: Vec<u8> = (0..random_prepend_len)
            .map(|_| rng.gen_range(0..=u8::MAX))
            .collect();
        plaintext.extend_from_slice(&KNOWN_END);

        let ciphertext = mt19937::apply_cipher(&plaintext[..], key);

        assert_eq!(
            break_mt19937_cipher(&ciphertext[..], &KNOWN_END).unwrap(),
            key
        );
    }
}

pub fn is_password_reset_token_unix_timestamp_seeded(password_reset_token: u32) -> bool {
    use mt19937::Mt19937;
    let now = SystemTime::now();
    let since_the_epoch = now.duration_since(UNIX_EPOCH).unwrap();
    let now_epoch = since_the_epoch.as_secs() as u32;
    let hour_ago_epoch = now_epoch - 60 * 60;
    for i in hour_ago_epoch..=now_epoch {
        let mut generator = Mt19937::new(i);
        if password_reset_token == generator.generate() {
            return true;
        }
    }

    false
}

pub fn break_mt19937_cipher(ciphertext: &[u8], known_ending_plaintext: &[u8]) -> Option<u16> {
    use byteorder::{ByteOrder, LittleEndian};
    use mt19937::Mt19937;

    let ending_offset = ciphertext.len() - known_ending_plaintext.len();
    let last_key_bytes = ciphertext[ending_offset..]
        .iter()
        .zip(known_ending_plaintext)
        .map(|(&b1, b2)| b1 ^ b2)
        .collect::<Vec<u8>>();

    let iterations_of_dont_cares;
    iterations_of_dont_cares = ending_offset / 4;

    let iterations_of_discoverable_keystream;
    if known_ending_plaintext.len() % 4 == 0 {
        iterations_of_discoverable_keystream = (known_ending_plaintext.len() / 4) + 1;
    } else {
        iterations_of_discoverable_keystream = (known_ending_plaintext.len() / 4) + 2;
    }

    for possible_key in 0..u16::MAX {
        let mut generator = Mt19937::new(possible_key as u32);

        for _ in 0..iterations_of_dont_cares {
            generator.generate();
        }

        let mut possible_key_last_key_bytes = Vec::new();
        for _ in 0..iterations_of_discoverable_keystream {
            let u32_keystream = generator.generate();
            let mut u32_keystream_as_bytearray = [0; 4];
            LittleEndian::write_u32(&mut u32_keystream_as_bytearray, u32_keystream);
            possible_key_last_key_bytes.extend_from_slice(&u32_keystream_as_bytearray[..]);
        }

        if possible_key_last_key_bytes
            .windows(last_key_bytes.len())
            .any(|w| w == last_key_bytes)
        {
            return Some(possible_key);
        }
    }
    None
}

fn reverse_temper_transform(z: u32) -> u32 {
    use mt19937::*;

    /*let mut y = x ^ ((x >> TEMPERING_MASK_1) & TEMPERING_MASK_2);
    y = y ^ ((y << TEMPERING_SHIFT_1) & TEMPERING_BITMASK_1);
    y = y ^ ((y << TEMPERING_SHIFT_2) & TEMPERING_BITMASK_2);
    let z = y ^ (y >> TEMPERING_MASK_3);
    z*/

    // reverse
    // let z = y ^ (y >> TEMPERING_MASK_3);
    let y_18_upper_bits = z & !(0xFFFFFFFF >> 18);
    let y_14_lower_bits = (y_18_upper_bits >> 18) ^ (z & (0xFFFFFFFF >> 18));
    let y = y_18_upper_bits + y_14_lower_bits;

    // reverse
    // y = y ^ ((y << TEMPERING_SHIFT_2) & TEMPERING_BITMASK_2);
    let y2_lower_17_bits = y & !(0xFFFFFFFF << 17);
    let y2_lower_15_bits = y & !(0xFFFFFFFF << 15);
    let y2_upper_17_bits =
        ((y2_lower_17_bits << 15) & TEMPERING_BITMASK_2) ^ (y & (!(0xFFFFFFFF >> 17)));
    let y2 = y2_lower_15_bits + y2_upper_17_bits;

    // reverse
    // y = y ^ ((y << TEMPERING_SHIFT_1) & TEMPERING_BITMASK_1);
    let y3_lower_7_bits = y2 & !(0xFFFFFFFF << 7);
    let y3_7_to_13_bits =
        ((y3_lower_7_bits << 7) & TEMPERING_BITMASK_1) ^ ((((y2 >> 7) << 7) << 18) >> 18);
    let y3_14_to_20_bits =
        ((y3_7_to_13_bits << 7) & TEMPERING_BITMASK_1) ^ ((((y2 >> 14) << 14) << 11) >> 11);
    let y3_21_to_27_bits =
        ((y3_14_to_20_bits << 7) & TEMPERING_BITMASK_1) ^ ((((y2 >> 21) << 21) << 4) >> 4);

    let y3_21_to_24_bits =
        y3_21_to_27_bits & ((((0xFFFFFFFF << (32 - 25)) >> (32 - 25)) >> 21) << 21);

    let y3_28_to_32_bits = ((y3_21_to_24_bits << 7) & TEMPERING_BITMASK_1) ^ ((y2 >> 28) << 28);

    let y3 =
        y3_lower_7_bits + y3_7_to_13_bits + y3_14_to_20_bits + y3_21_to_27_bits + y3_28_to_32_bits;

    // reverse
    // let mut y = x ^ ((x >> TEMPERING_MASK_1) & TEMPERING_MASK_2);
    let x_upper_11_bits = y3 & (0xFFFFFFFF << 21);
    let y3_middle_11_bits = y3 & ((((0xFFFFFFFF << 11) >> 11) >> 10) << 10);
    let x_middle_11_bits = (x_upper_11_bits >> 11) ^ y3_middle_11_bits;
    let y3_lower_10_bits = y3 & !(0xFFFFFFFF << 10);
    let x_lower_10_bits = (x_middle_11_bits >> 11) ^ y3_lower_10_bits;
    let x = x_upper_11_bits + x_middle_11_bits + x_lower_10_bits;
    x
}

pub fn clone_rng(seed: u32) -> mt19937::Mt19937 {
    use mt19937::*;
    use std::collections::VecDeque;

    let mut generator = Mt19937::new(seed);

    let mut recreated_state = VecDeque::new();

    for _ in 0..DEGREE_OF_RECURRENCE {
        let v = reverse_temper_transform(generator.generate());
        recreated_state.push_back(v);
    }

    Mt19937 {
        state: recreated_state,
    }
}

#[allow(dead_code)]
pub fn crack_mt19937_seed(output: u32) -> Option<u32> {
    let now = SystemTime::now();
    let since_the_epoch = now.duration_since(UNIX_EPOCH).unwrap();
    let now_epoch = since_the_epoch.as_secs() as u32;
    let twelve_hours_ago_epoch = now_epoch - 60 * 60 * 12;

    for i in twelve_hours_ago_epoch..now_epoch {
        if output == mt19937::generate(i as u32, 1)[0] {
            return Some(i as u32);
        }
    }
    None
}

pub fn generate_u32() -> u32 {
    use rand::prelude::*;
    let mut rng = rand::thread_rng();
    let first_sleep_amount_sec = rng.gen_range(40..1000);
    std::thread::sleep(Duration::new(first_sleep_amount_sec, 0));

    let now = SystemTime::now();
    let since_the_epoch = now.duration_since(UNIX_EPOCH).unwrap();
    let output = mt19937::generate(since_the_epoch.as_secs() as u32, 1);

    let second_sleep_amount_sec = rng.gen_range(40..1000);
    std::thread::sleep(Duration::new(second_sleep_amount_sec, 0));

    return output[0];
}
