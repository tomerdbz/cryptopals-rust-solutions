use crate::padding;
use crate::rsa::RsaCreds;
use sha1::Sha1;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::number::cube_root;
    use crate::number::{biguint_to_message, message_to_biguint};
    const MESSAGE: &[u8] = b"hi mom";

    #[test]
    fn test_broken_authentication_accepts_valid_signature() {
        let client = Client::new();
        let signature = client.sign(MESSAGE, 128);

        assert!(server::verify(MESSAGE, &signature, &client));
    }

    #[test]
    fn test_broken_authentication_rejects_invalid_signature() {
        let client = Client::new();
        let mut signature = client.sign(MESSAGE, 128);
        signature[0] += 5;

        assert_eq!(false, server::verify(MESSAGE, &signature, &client));
    }

    #[test]
    fn test_broken_authentication_accepts_forged_signature() {
        let client = Client::new();

        let pkcs_1_5_pad = padding::pkcs_1_5::apply_for_signature::<Sha1>(MESSAGE, 128);
        let pkcs_1_5_minimal_pad = [
            &[pkcs_1_5_pad[0], pkcs_1_5_pad[1], pkcs_1_5_pad[2]][..],
            &pkcs_1_5_pad[2..]
                .iter()
                .filter(|&b| *b != 0xff)
                .cloned()
                .collect::<Vec<u8>>()[..],
        ]
        .concat();

        let garbage_amount = pkcs_1_5_pad.len() - pkcs_1_5_minimal_pad.len();
        let minimal_value =
            message_to_biguint(&[&pkcs_1_5_minimal_pad[..], &vec![0; garbage_amount][..]].concat());
        let maximal_value = message_to_biguint(
            &[&pkcs_1_5_minimal_pad[..], &vec![0xff; garbage_amount][..]].concat(),
        );

        let fake_signature = biguint_to_message(&cube_root(&minimal_value, &maximal_value));
        assert_eq!(true, server::verify(MESSAGE, &fake_signature, &client));
    }
}

pub struct Client {
    pub creds: RsaCreds,
}

impl Client {
    pub fn new() -> Self {
        Client {
            creds: RsaCreds::new(),
        }
    }

    pub fn sign(&self, message: &[u8], block_bytes_length: usize) -> Vec<u8> {
        self.creds
            .decrypt(&padding::pkcs_1_5::apply_for_signature::<Sha1>(
                message,
                block_bytes_length,
            ))
    }
}

pub mod server {
    use super::*;
    pub fn verify(original_message: &[u8], signature: &[u8], client: &Client) -> bool {
        let message = RsaCreds::encrypt_with_public_key(signature, client.creds.get_public_key());
        if message[0] != 1 || message[1] != 0xff {
            return false;
        }

        let first_index_after_ff = message
            .iter()
            .enumerate()
            .filter(|&(_, e)| *e != 0xff)
            .nth(1)
            .unwrap()
            .0;

        if message[first_index_after_ff] != 0 {
            return false;
        }

        if let Ok(result) =
            asn1::parse_single::<padding::pkcs_1_5::Message>(&message[first_index_after_ff + 1..])
        {
            if result.digest_info.to_hash(original_message).unwrap() == result.hash {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
}
