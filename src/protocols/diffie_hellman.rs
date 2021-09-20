pub mod negotiated_groups_diffie_hellman;
pub mod secure_remote_password;

use crate::aes::{decrypt_cbc_ecb_128_bit, encrypt_cbc_ecb_128_bit};
use crate::diffie_hellman::DiffieHellman;
use num_bigint::{BigUint, ToBigUint};
use sha1::{Digest, Sha1};

#[cfg(test)]
mod tests {
    use super::*;
    const MESSAGE: &[u8] = b"Hello, World!";

    #[test]
    fn test_diffie_hellman_protocol() {
        let mut server = ProtocolServer::new();
        let mut client = ProtocolClient::new(&mut server);
        Client::syn(&mut client);

        assert_eq!(Client::send_message(&mut client, MESSAGE).unwrap(), MESSAGE);
    }
}

pub trait Client {
    fn syn(&mut self);
    fn send_message(&mut self, message: &[u8]) -> Option<Vec<u8>>;
}

// a facade from the client eyes to communicate with the server
pub trait ServerFacade {
    fn get_syn(&mut self, p: &BigUint, g: &BigUint, other_public_key: &BigUint);
    fn ack(&self) -> BigUint;
    fn echo_message(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>>;
}
pub struct ProtocolClient<'a, 'b, T> {
    p: BigUint,
    g: BigUint,
    state: ProtocolState<'a>,
    server: &'b mut T,
}

pub struct ProtocolServer<'a> {
    state: Option<ProtocolState<'a>>,
}

impl<'a> ProtocolServer<'a> {
    pub fn new() -> ProtocolServer<'a> {
        ProtocolServer { state: None }
    }
}

impl<'a> ServerFacade for ProtocolServer<'a> {
    fn get_syn(&mut self, p: &BigUint, g: &BigUint, other_public_key: &BigUint) {
        self.state = Some(ProtocolState::owning_new(p.clone(), g));
        self.state
            .as_mut()
            .unwrap()
            .set_other_public_key(other_public_key.clone());
    }
    fn ack(&self) -> BigUint {
        self.state.as_ref().unwrap().get_public_key().clone()
    }

    fn echo_message(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.state.as_mut().unwrap().set_other_iv(&ciphertext[..16]);
        decrypt_message(self.state.as_mut().unwrap(), &ciphertext[16..])
    }
}

impl<'a, 'b, T> ProtocolClient<'a, 'b, T>
where
    T: ServerFacade,
{
    pub fn new(server: &'b mut T) -> ProtocolClient<'a, 'b, T> {
        let p = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
        let g = BigUint::from(2u8);
        let cloned_p = p.clone();
        let cloned_g = g.clone();
        ProtocolClient {
            p,
            g,
            state: ProtocolState::owning_new(cloned_p, &cloned_g),
            server,
        }
    }
}
impl<'a, 'b, T> Client for ProtocolClient<'a, 'b, T>
where
    T: ServerFacade,
{
    fn syn(&mut self) {
        self.server
            .get_syn(&self.p, &self.g, self.state.get_public_key());

        self.state.set_other_public_key(self.server.ack());
    }

    fn send_message(&mut self, message: &[u8]) -> Option<Vec<u8>> {
        self.server
            .echo_message(&encrypt_message(&mut self.state, message)?)
    }
}

pub struct ProtocolState<'a> {
    diffie_hellman: DiffieHellman<'a>,
    iv: Vec<u8>,
    other_public_key: Option<BigUint>,
    other_iv: Option<Vec<u8>>,
}

impl<'a> ProtocolState<'a> {
    pub fn non_owning_new(p: &'a BigUint, g: &'a BigUint) -> ProtocolState<'a> {
        ProtocolState {
            diffie_hellman: DiffieHellman::non_owning_new(p, g),
            iv: (0..16).map(|_| rand::random::<u8>()).collect(),
            other_iv: None,
            other_public_key: None,
        }
    }
    pub fn owning_new(p: BigUint, g: &BigUint) -> ProtocolState<'a> {
        ProtocolState {
            diffie_hellman: DiffieHellman::owning_new(p, g),
            iv: (0..16).map(|_| rand::random::<u8>()).collect(),
            other_iv: None,
            other_public_key: None,
        }
    }
    pub fn get_public_key(&'a self) -> &'a BigUint {
        self.diffie_hellman.get_public_key()
    }

    pub fn set_other_public_key(&mut self, other_public_key: BigUint) {
        self.other_public_key = Some(other_public_key);
        self.diffie_hellman
            .generate_session_key(self.other_public_key.as_ref().unwrap());
    }
    pub fn get_other_public_key(&self) -> Option<&BigUint> {
        self.other_public_key.as_ref()
    }

    pub fn get_iv(&self) -> &Vec<u8> {
        &self.iv
    }
    pub fn get_other_iv(&self) -> Option<&Vec<u8>> {
        self.other_iv.as_ref()
    }
    pub fn set_other_iv(&mut self, other_iv: &[u8]) {
        self.other_iv = Some(other_iv.to_vec());
    }
}

pub fn encrypt_message<'a>(state: &mut ProtocolState<'a>, message: &[u8]) -> Option<Vec<u8>> {
    let key = Sha1::digest(&state.diffie_hellman.get_session_key()?.to_bytes_le());

    Some(
        [
            &state.get_iv()[..],
            &encrypt_cbc_ecb_128_bit(message, &key[..16], &state.get_iv())[..],
        ]
        .concat(),
    )
}
pub fn decrypt_message<'a>(state: &mut ProtocolState<'a>, cipher: &[u8]) -> Option<Vec<u8>> {
    let key = Sha1::digest(&state.diffie_hellman.get_session_key()?.to_bytes_le());
    Some(decrypt_cbc_ecb_128_bit(&cipher[..], &key[..16], &state.get_other_iv()?).unwrap())
}

pub fn get_key_from_int(i: usize) -> Vec<u8> {
    let session_key = ToBigUint::to_biguint(&i).unwrap();
    Sha1::digest(&session_key.to_bytes_le()).to_vec()
}
