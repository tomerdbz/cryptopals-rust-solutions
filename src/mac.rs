use crate::error::Error;
use md4::Md4;
use sha1::Digest;
use sha1::Sha1;

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &[u8] = b"shhhhhh";
    const MESSAGE: &[u8] = b"Hello, World?";

    #[test]
    fn test_sha1_authenticate_message() {
        let message_with_mac = Message::new::<Sha1>(MESSAGE, KEY);
        assert!(message_with_mac.authenticate::<Sha1>(KEY));
    }
    #[test]
    fn test_md4_authenticate_message() {
        let message_with_mac = Message::new::<Md4>(MESSAGE, KEY);
        assert!(message_with_mac.authenticate::<Md4>(KEY));
    }

    #[test]
    fn test_sha1_authenticate_message_tampering_message() {
        let message_with_mac = Message::new::<Sha1>(MESSAGE, KEY);
        let mut serialized_message = message_with_mac.to_bytes();
        serialized_message[21] = b'J';
        let tampered_content_message =
            Message::from_bytes::<Sha1>(&serialized_message[..]).unwrap();
        assert_eq!(tampered_content_message.authenticate::<Sha1>(KEY), false);
    }
    #[test]
    fn test_md4_authenticate_message_tampering_message() {
        let message_with_mac = Message::new::<Md4>(MESSAGE, KEY);
        let mut serialized_message = message_with_mac.to_bytes();
        serialized_message[21] = b'J';
        let tampered_content_message = Message::from_bytes::<Md4>(&serialized_message[..]).unwrap();
        assert_eq!(tampered_content_message.authenticate::<Md4>(KEY), false);
    }

    #[test]
    fn test_sha1_authenticate_message_tampering_mac() {
        let message_with_mac = Message::new::<Sha1>(MESSAGE, KEY);
        let mut serialized_message = message_with_mac.to_bytes();
        serialized_message[19] = b'J';
        let tampered_mac_message = Message::from_bytes::<Sha1>(&serialized_message[..]).unwrap();

        assert_eq!(tampered_mac_message.authenticate::<Sha1>(KEY), false);
    }
    #[test]
    fn test_md4_authenticate_message_tampering_mac() {
        let message_with_mac = Message::new::<Md4>(MESSAGE, KEY);
        let mut serialized_message = message_with_mac.to_bytes();
        serialized_message[8] = b'J';
        let tampered_mac_message = Message::from_bytes::<Md4>(&serialized_message[..]).unwrap();

        assert_eq!(tampered_mac_message.authenticate::<Md4>(KEY), false);
    }
}

pub struct Message<'a> {
    message: &'a [u8],
    hash: Vec<u8>,
}
impl<'a> Message<'a> {
    pub fn new<T>(message: &'a [u8], key: &[u8]) -> Message<'a>
    where
        T: PrefixHash + Digest,
    {
        Message::<'a> {
            message,
            hash: Message::<'a>::generate_mac::<T>(message, key),
        }
    }

    pub fn get_message(&self) -> &'a [u8] {
        self.message
    }

    pub fn get_hash(&'a self) -> &'a [u8] {
        &self.hash[..]
    }

    pub fn from_bytes<T>(serialized_message: &'a [u8]) -> Result<Message<'a>, Error>
    where
        T: PrefixHash + Digest,
    {
        if serialized_message.len() <= T::prefix_length() {
            return Err(Error::InvalidArgument);
        }

        Ok(Message::<'a> {
            message: &serialized_message[T::prefix_length()..],
            hash: serialized_message[..T::prefix_length()].to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.hash, self.message].concat()
    }

    pub fn authenticate<T>(&self, key: &[u8]) -> bool
    where
        T: PrefixHash + Digest,
    {
        return self.hash == Message::<'a>::generate_mac::<T>(self.message, key);
    }

    fn generate_mac<T>(message: &[u8], secret_key: &[u8]) -> Vec<u8>
    where
        T: PrefixHash + Digest,
    {
        let mut hasher = T::new();
        hasher.update(secret_key);
        hasher.update(message);
        hasher.finalize().to_vec()
    }
}
use byteorder::{BigEndian, ByteOrder, LittleEndian};
pub trait PrefixHash {
    type Endianity: ByteOrder;
    fn prefix_length() -> usize;
}
use std::mem::size_of;
impl PrefixHash for Sha1 {
    type Endianity = BigEndian;
    fn prefix_length() -> usize {
        5 * size_of::<u32>()
    }
}
impl PrefixHash for Md4 {
    type Endianity = LittleEndian;
    fn prefix_length() -> usize {
        4 * size_of::<u32>()
    }
}
