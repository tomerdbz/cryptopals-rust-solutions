use crate::error::{Error, Res};
use rand::Rng;

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::{Digest, Sha1};

    #[test]
    fn test_pkcs7() {
        assert_eq!(
            pkcs7(b"YELLOW SUBMARINE", 20).unwrap(),
            b"YELLOW SUBMARINE\x04\x04\x04\x04"
        );
    }

    #[test]
    fn test_pkcs_1_5() {
        const MESSAGE: &[u8] = b"hi mom";
        const SHA1_DIGEST_INFO: [u8; 15] = [
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04,
            0x14,
        ];
        let message_hash = Sha1::digest(MESSAGE);

        let result = pkcs_1_5::apply_for_signature::<Sha1>(b"hi mom", 1024);

        let expected_result = [
            &[0, 1],
            &vec![0xff; 1024 - 2 - 1 - 15 - 20][..],
            &[0],
            &SHA1_DIGEST_INFO,
            &message_hash,
        ]
        .concat();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_remove_pkcs7_legit_input() {
        assert_eq!(
            remove_pkcs7(b"ICE ICE BABY\x04\x04\x04\x04").unwrap(),
            b"ICE ICE BABY"
        );
    }

    #[test]
    fn test_remove_pkcs7_error_input() {
        assert_eq!(
            remove_pkcs7(b"ICE ICE BABY\x05\x05\x05\x05"),
            Err(Error::InvalidArgument)
        );

        assert_eq!(
            remove_pkcs7(b"ICE ICE BABY\x01\x02\x03\x04"),
            Err(Error::InvalidArgument)
        );
    }
}

pub mod pkcs_1_5 {
    use super::*;
    use crate::rsa::RsaCreds;
    use sha1::{Digest, Sha1};

    pub trait HashAlgorithm: Digest {
        const OID: &'static [u8];

        fn info<'a>() -> asn1::ObjectIdentifier<'a> {
            asn1::ObjectIdentifier::from_string(&String::from_utf8_lossy(Self::OID)).unwrap()
        }
    }

    impl HashAlgorithm for Sha1 {
        const OID: &'static [u8] = b"1.3.14.3.2.26";
    }

    type Null = ();

    #[derive(asn1::Asn1Read, asn1::Asn1Write)]
    pub struct DigestInfo<'a> {
        digest_info: asn1::ObjectIdentifier<'a>,
        parameters: Null,
    }

    impl<'a> DigestInfo<'a> {
        pub fn to_hash(&self, message: &[u8]) -> Res<Vec<u8>> {
            // too bad no reflection...
            // TODO - a more extendable interface outside of this lib
            if self.digest_info == Sha1::info() {
                return Ok(Sha1::digest(message).to_vec());
            } else {
                return Err(Error::InvalidArgument);
            }
        }
    }

    #[derive(asn1::Asn1Read, asn1::Asn1Write)]
    pub struct Message<'a> {
        pub digest_info: DigestInfo<'a>,
        pub hash: &'a [u8],
    }

    pub fn apply_for_signature<T>(data: &[u8], block_length: usize) -> Vec<u8>
    where
        T: HashAlgorithm,
    {
        let hashed_data = T::digest(data);

        let result = asn1::write_single(&Message {
            digest_info: DigestInfo {
                digest_info: T::info(),
                parameters: (),
            },
            hash: &hashed_data,
        });

        let ff_vector_count = block_length - (result.len() + 2 + 1); // % block_length);
        [&[0, 1], &vec![0xff; ff_vector_count][..], &[0], &result].concat()
    }

    pub trait Pkcs1_5Encrypt {
        fn pkcs1_5_encrypt(&self, data: &[u8]) -> Res<Vec<u8>>;
        fn pkcs1_5_decrypt(&self, data: &[u8]) -> Res<Vec<u8>>;
    }

    impl Pkcs1_5Encrypt for RsaCreds {
        fn pkcs1_5_encrypt(&self, data: &[u8]) -> Res<Vec<u8>> {
            let message_len = data.len();
            let k = self.get_public_key().1.bits() as usize / 8;

            if message_len > (k - 11) {
                return Err(Error::InvalidArgument);
            }

            let random_vector_count = k - message_len - 3;
            let random_padding_vec = (0..random_vector_count)
                .map(|_| rand::thread_rng().gen_range(1..u8::MAX))
                .collect::<Vec<u8>>();

            Ok(self.encrypt(&[&[0, 2], &random_padding_vec[..], &[0], data].concat()))
        }

        fn pkcs1_5_decrypt(&self, data: &[u8]) -> Res<Vec<u8>> {
            if data.len() < 11 {
                return Err(Error::InvalidArgument);
            }
            let k = self.get_public_key().1.bits() as usize / 8;
            if k != data.len() {
                return Err(Error::InvalidArgument);
            }

            let padded_message = self.decrypt(data);
            if padded_message[0] != 2 {
                return Err(Error::InvalidArgument);
            }

            if let Ok((end_of_padding_string_index, _)) = padded_message[0..]
                .iter()
                .enumerate()
                .find(|(_, &b)| b == 0)
                .ok_or_else(|| Error::InvalidArgument)
            {
                return Ok(padded_message[end_of_padding_string_index + 1..].to_vec());
            } else {
                return Err(Error::InvalidArgument);
            }
        }
    }

    pub fn remove_pkcs1_5_for_encryption(data: &[u8]) -> Option<Vec<u8>> {
        let (last_ff_index, _) = data.iter().enumerate().find(|(_, &b)| b == 0)?;
        Some(data[last_ff_index + 1..].to_vec())
    }
}

pub fn pkcs7(data: &[u8], block_length: usize) -> Option<Vec<u8>> {
    let pad_length = block_length - data.len() % block_length;
    if pad_length > u8::MAX as usize {
        return None;
    }

    let mut padded_data: Vec<u8> = Vec::new();
    padded_data.append(&mut data.to_vec());
    padded_data.append(&mut vec![pad_length as u8; pad_length]);

    return Some(padded_data);
}

fn validate_pkcs7(data: &[u8]) -> Res<u8> {
    let pad_length = data.last().ok_or(Error::InvalidArgument)?;
    if *pad_length > 16 || *pad_length == 0 {
        return Err(Error::InvalidArgument);
    }
    if data[data.len() - *pad_length as usize..].to_vec() != vec![*pad_length; *pad_length as usize]
    {
        return Err(Error::InvalidArgument);
    }

    Ok(*pad_length)
}

pub fn remove_pkcs7(data: &[u8]) -> Res<Vec<u8>> {
    match validate_pkcs7(data) {
        Ok(pad_length) => {
            let mut unpadded_data: Vec<u8> = Vec::new();
            unpadded_data.append(&mut data[..data.len() - pad_length as usize].to_vec());
            return Ok(unpadded_data);
        }
        Err(other) => Err(other),
    }
}
