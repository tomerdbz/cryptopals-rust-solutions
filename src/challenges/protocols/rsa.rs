pub mod broken_authentication;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::number::ModInverse;
    use crate::number::{biguint_to_message, message_to_biguint};
    use num_bigint::{BigUint, RandomBits};
    use rand::Rng;
    const MESSAGE: &[u8] = b"../resources/cryptopals_set1_challenge6.txt";

    #[test]
    fn test_anti_replay_server_replies() {
        let mut server = AntiReplayServer::new(Duration::new(10, 0));
        let mut client = Client::new(&mut server);
        let ciphertext = client.encrypt(MESSAGE);
        assert_eq!(client.decrypt(&ciphertext[..]).unwrap(), MESSAGE);
    }

    #[test]
    fn test_anti_replay_cant_replay() {
        let mut server = AntiReplayServer::new(Duration::new(10, 0));
        let mut client = Client::new(&mut server);
        let ciphertext = client.encrypt(MESSAGE);
        client.decrypt(&ciphertext[..]);
        assert!(client.decrypt(&ciphertext[..]).is_none());
    }

    #[test]
    fn test_anti_replay_breakable() {
        let mut server = AntiReplayServer::new(Duration::new(10, 0));
        let (_, server_modulus) = server.get_public_key().clone();

        let mut rng = rand::thread_rng();
        let obfuscating_number: BigUint = rng.sample(RandomBits::new(16));
        let obfuscator = RsaCreds::encrypt_with_public_key(
            &biguint_to_message(&obfuscating_number),
            server.get_public_key(),
        );

        let mut client = Client::new(&mut server);
        let ciphertext = client.encrypt(MESSAGE);

        let ciphertext_as_number = BigUint::from_bytes_be(&ciphertext);
        let obfuscated_ciphertext =
            (&ciphertext_as_number * BigUint::from_bytes_be(&obfuscator)) % &server_modulus;

        let obfuscated_plaintext = message_to_biguint(
            &client
                .decrypt(&obfuscated_ciphertext.to_bytes_be())
                .unwrap(),
        );

        let plaintext_as_number = ((&obfuscated_plaintext % &server_modulus)
            * &obfuscating_number.invmod(&server_modulus).unwrap())
            % &server_modulus;

        let plaintext = biguint_to_message(&plaintext_as_number);

        assert_eq!(&plaintext, MESSAGE);
    }
}

pub trait AntiReplayServerFacade {
    fn get_public_key(&self) -> &(Exponent, Modulos);
    fn get_plaintext(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>>;
}

use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::time::{Duration, Instant};
type Hash = Vec<u8>;
use crate::rsa::{Exponent, Modulos, RsaCreds};
pub struct AntiReplayServer {
    past_requests: HashMap<Hash, Instant>,
    lease_time: Duration,
    creds: RsaCreds,
}

impl AntiReplayServerFacade for AntiReplayServer {
    fn get_public_key(&self) -> &(Exponent, Modulos) {
        self.creds.get_public_key()
    }
    fn get_plaintext(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let hash = Sha1::digest(ciphertext);

        let ciphertext_timestamp = self.past_requests.get(&hash[..]);

        if ciphertext_timestamp.is_none() {
            self.past_requests.insert(hash.to_vec(), Instant::now());
        } else {
            let timestamp = ciphertext_timestamp.unwrap();
            if timestamp.elapsed() < self.lease_time {
                return None;
            } else {
                let current_timestamp = self.past_requests.get_mut(&hash[..]).unwrap();
                *current_timestamp = Instant::now();
            }
        }

        Some(self.creds.decrypt(ciphertext))
    }
}

impl AntiReplayServer {
    pub fn new(lease_time: Duration) -> Self {
        AntiReplayServer {
            past_requests: HashMap::new(),
            lease_time,
            creds: RsaCreds::new(),
        }
    }
}

pub struct Client<'a, T>
where
    T: AntiReplayServerFacade,
{
    server: &'a mut T,
}

impl<'a, T> Client<'a, T>
where
    T: AntiReplayServerFacade,
{
    pub fn new(server: &'a mut T) -> Self {
        Client { server }
    }

    pub fn encrypt(&self, message: &[u8]) -> Vec<u8> {
        RsaCreds::encrypt_with_public_key(message, self.server.get_public_key())
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.server.get_plaintext(ciphertext)
    }
}
