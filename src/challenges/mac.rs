use crate::mac::PrefixHash;
use md4::Md4;
use sha1::{Digest, Sha1};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mac;
    use byteorder::{BigEndian, LittleEndian};
    const KEY: &[u8] = b"shhhhhh";
    const MESSAGE: &[u8] =
        b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

    #[test]
    fn test_sha1_alternate_new() {
        let mut altered_hasher = Sha1::new_with_state(0, 0, 0, 0, 0);
        altered_hasher.update([KEY, MESSAGE].concat());

        let mut hasher = Sha1::new();
        hasher.update([KEY, MESSAGE].concat());
        assert_ne!(
            hasher.finalize().to_vec(),
            altered_hasher.finalize().to_vec()
        );
    }
    #[test]
    fn test_get_glue_padding_same_sha1_state() {
        let mut hasher = Sha1::new();
        hasher.update(KEY);
        hasher.update(MESSAGE);
        let message_only = hasher.get_state();
        let after_padding = mac_to_regs::<BigEndian>(&hasher.finalize().to_vec());

        let mut raw_hasher = Sha1::new();
        raw_hasher.update(KEY);
        raw_hasher.update(MESSAGE);
        let message_only_raw_hasher = raw_hasher.get_state();

        let padded_message =
            get_glue_padding::<BigEndian>(KEY.len() + MESSAGE.len(), KEY.len() + MESSAGE.len());
        raw_hasher.update(&padded_message[..]);
        let after_padding_raw_hasher = raw_hasher.get_state();

        assert_eq!(message_only, message_only_raw_hasher);
        assert_eq!(after_padding, after_padding_raw_hasher);
    }

    #[test]
    fn test_brute_force_sha1_authenticate_append() {
        let authenticated_message = mac::Message::new::<Sha1>(MESSAGE, KEY);
        let serialized_message = authenticated_message.to_bytes();

        let mut has_authenticated = false;
        for possible_authenticated_message in
            generate_tampered_messages::<Sha1>(&serialized_message[..], b";admin=true", 7..8)
        {
            let deserialized_message =
                mac::Message::from_bytes::<Sha1>(&possible_authenticated_message[..]).unwrap();
            has_authenticated |= deserialized_message.authenticate::<Sha1>(KEY);
        }
        assert!(has_authenticated);
    }

    #[test]
    fn test_brute_force_md4_authenticate_append() {
        let authenticated_message = mac::Message::new::<Md4>(MESSAGE, KEY);
        let serialized_message = authenticated_message.to_bytes();
        let mut has_authenticated = false;
        for possible_authenticated_message in
            generate_tampered_messages::<Md4>(&serialized_message[..], b";admin=true", 7..8)
        {
            let deserialized_message =
                mac::Message::from_bytes::<Md4>(&possible_authenticated_message[..]).unwrap();
            has_authenticated |= deserialized_message.authenticate::<Md4>(KEY);
        }
        assert!(has_authenticated);
    }

    #[test]
    fn test_regs_to_mac() {
        const REGS: [u32; 5] = [
            0xDEADBEEFu32,
            0xCAFECAFEu32,
            0x12345678u32,
            0x57819287u32,
            0x78291738u32,
        ];
        let mac = regs_to_mac::<LittleEndian>(&REGS);
        let regs = mac_to_regs::<LittleEndian>(&mac[..]);
        assert_eq!(regs, REGS);
    }
}

fn regs_to_mac<T>(regs: &[u32]) -> Vec<u8>
where
    T: ByteOrder,
{
    regs.iter().fold(Vec::new(), |mut m, r| {
        let mut reg_bytes = Vec::new();
        reg_bytes.write_u32::<T>(*r).unwrap();
        for reg_byte in reg_bytes {
            m.push(reg_byte);
        }
        m
    })
}

fn mac_to_regs<T>(hash: &[u8]) -> Vec<u32>
where
    T: ByteOrder,
{
    use byteorder::ReadBytesExt;
    use std::io::Cursor;
    use std::mem::size_of;

    if hash.len() % size_of::<u32>() != 0 {}

    let number_of_regs = hash.len() / size_of::<u32>();
    let mut u32_reader = Cursor::new(hash);
    let mut result = Vec::new();
    for _ in 0..number_of_regs {
        result.push(u32_reader.read_u32::<T>().unwrap());
    }
    result
}

pub trait PrefixHashTamperableApi: PrefixHash {
    fn new_with_state(state: &[u32]) -> Self;
    fn get_state(&self) -> Vec<u32>;
}

impl PrefixHashTamperableApi for Sha1 {
    fn new_with_state(state: &[u32]) -> Sha1 {
        Sha1::new_with_state(state[0], state[1], state[2], state[3], state[4])
    }

    fn get_state(&self) -> Vec<u32> {
        self.get_state().to_vec()
    }
}
impl PrefixHashTamperableApi for Md4 {
    fn new_with_state(state: &[u32]) -> Md4 {
        Md4::new_with_state(state[0], state[1], state[2], state[3])
    }

    fn get_state(&self) -> Vec<u32> {
        self.get_state().to_vec()
    }
}

pub fn generate_tampered_messages<T>(
    authenticated_message: &[u8],
    append: &[u8],
    key_size_guess_range: std::ops::Range<usize>,
) -> Vec<Vec<u8>>
where
    T: PrefixHashTamperableApi + Digest,
{
    let state = mac_to_regs::<T::Endianity>(&authenticated_message[..T::prefix_length()]);
    let mut result: Vec<Vec<u8>> = Vec::new();
    let message_len = authenticated_message.len() - T::prefix_length();
    for key_size in key_size_guess_range {
        let padding =
            get_glue_padding::<T::Endianity>(key_size + message_len, key_size + message_len);
        let mut hasher = T::new_with_state(&state[..]);
        hasher.update(append);

        hasher.update(&get_glue_padding::<T::Endianity>(
            append.len(),
            key_size + message_len + padding.len() + append.len(),
        ));
        result.push(
            [
                &regs_to_mac::<T::Endianity>(&hasher.get_state()),
                &authenticated_message[T::prefix_length()..],
                &padding[..],
                append,
            ]
            .concat(),
        )
    }
    result
}

use bitvec::prelude::*;
use byteorder::{ByteOrder, WriteBytesExt};
pub fn get_glue_padding<T>(message_len: usize, total_len: usize) -> Vec<u8>
where
    T: ByteOrder,
{
    let mut padding: BitVec<Msb0, u8> = BitVec::new();
    const BLOCK_LEN: usize = 512;
    // u64 that encodes the length is at the end of the pad
    const MESSAGE_LEN_ENCODING_LEN: usize = 64;
    const FIRST_BIT_LEN: usize = 1;
    const CONGRUENT_ZERO_BYTES_PAD_LEN: usize =
        BLOCK_LEN - MESSAGE_LEN_ENCODING_LEN - FIRST_BIT_LEN;
    let remainder_message_block_len = (message_len * 8) % BLOCK_LEN;

    let zero_bytes_len;
    if remainder_message_block_len > CONGRUENT_ZERO_BYTES_PAD_LEN {
        zero_bytes_len = BLOCK_LEN - remainder_message_block_len + CONGRUENT_ZERO_BYTES_PAD_LEN;
    } else {
        zero_bytes_len = CONGRUENT_ZERO_BYTES_PAD_LEN - remainder_message_block_len;
    }

    padding.push(true);
    padding.append(&mut bitvec![Msb0, u8; 0; zero_bytes_len]);
    let mut result = padding.into_vec();
    let mut length_vec = Vec::new();
    length_vec.write_u64::<T>((total_len * 8) as u64).unwrap();
    result.append(&mut length_vec);
    result
}
