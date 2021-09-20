use crate::diffie_hellman::{DiffieHellman, ModExp};
use num_bigint::{BigUint, ToBigUint};
use sha2::{Digest, Sha256};
use std::ops::{Add, Mul};

#[cfg(test)]
mod tests {
    use super::*;
    const EMAIL: &[u8] = b"guesswho@crpyto.com";
    const PASSWORD: &[u8] = b"lolzzzz";

    #[test]
    fn test_secure_remote_password() {
        let n = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
        let mut server = SRPServer::new(&n, EMAIL, PASSWORD);
        let mut client = SRPClient::new(&mut server, &n, EMAIL, PASSWORD);

        client.exchange_public_keys();
        let is_verified = client.send_verification();

        assert!(is_verified);
    }

    #[test]
    fn test_simple_secure_remote_password() {
        let n = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
        let mut server = SimpleSRPServer::new(&n, EMAIL, PASSWORD);
        let mut client = SimpleSRPClient::new(&mut server, &n, EMAIL, PASSWORD);

        client.simple_exchange_public_keys();
        let is_verified = client.send_verification();

        assert!(is_verified);
    }
}

pub struct SRPServer<'a> {
    g: BigUint,
    k: BigUint,
    n: BigUint,
    email: Vec<u8>,
    salt: Vec<u8>,
    v: BigUint,
    client_public_key: Option<BigUint>,
    diffie_hellman: DiffieHellman<'a>,
    server_public_key: Option<BigUint>,
}

impl<'a> SRPServerFacade for SRPServer<'a> {
    fn new(n: &BigUint, email: &[u8], password: &[u8]) -> SRPServer<'a> {
        let salt: Vec<u8> = (0..8).map(|_| rand::random::<u8>()).collect();
        let x_hash = Sha256::digest(&[&salt, password].concat());
        let x = BigUint::from_bytes_le(&x_hash);
        let g = ToBigUint::to_biguint(&2).unwrap();
        let k = ToBigUint::to_biguint(&3).unwrap();
        let v = g.modexp(&x, n);

        SRPServer {
            n: n.clone(),
            email: email.to_vec(),
            salt,
            v,
            client_public_key: None,
            diffie_hellman: DiffieHellman::owning_new(n.clone(), &g),
            server_public_key: None,
            g,
            k,
        }
    }
    fn exchange_public_keys(
        &mut self,
        email: &[u8],
        client_public_key: &BigUint,
    ) -> Option<(Vec<u8>, BigUint)> {
        if email != self.email {
            return None;
        }

        self.server_public_key = Some(
            (self.k.clone().mul(&self.v)
                + self
                    .g
                    .modexp(self.diffie_hellman.get_private_key(), &self.n))
                % &self.n,
        );

        self.client_public_key = Some(client_public_key.clone());
        Some((
            self.salt.clone(),
            self.server_public_key.as_ref().unwrap().clone(),
        ))
    }

    fn verify(&self, hmac: &[u8]) -> bool {
        let u_hash = Sha256::digest(
            &[
                self.client_public_key.as_ref().unwrap().to_bytes_le(),
                self.server_public_key.as_ref().unwrap().to_bytes_le(),
            ]
            .concat(),
        );
        let u = BigUint::from_bytes_le(&u_hash);

        let base = self
            .client_public_key
            .as_ref()
            .unwrap()
            .mul(self.v.modexp(&u, &self.n))
            % &self.n;

        let exp = self.diffie_hellman.get_private_key();

        let session_key = base.modexp(exp, &self.n);
        let key = Sha256::digest(&session_key.to_bytes_le());

        return hmac_sha256(&key[..], &self.salt) == hmac;
    }
}

pub trait SimpleSRPServerFacade {
    fn simple_exchange_public_keys(
        &mut self,
        email: &[u8],
        client_public_key: &BigUint,
    ) -> Option<(Vec<u8>, BigUint, u16)>;
    fn simple_verify(&mut self, hmac: &[u8]) -> bool;
}

pub struct SimpleSRPServer<'a> {
    server: SRPServer<'a>,
    random: Option<u16>,
}

impl<'a> SimpleSRPServerFacade for SimpleSRPServer<'a> {
    fn simple_exchange_public_keys(
        &mut self,
        email: &[u8],
        client_public_key: &BigUint,
    ) -> Option<(Vec<u8>, BigUint, u16)> {
        if self.server.email != email {
            return None;
        }
        self.server.client_public_key = Some(client_public_key.clone());
        self.random = Some(rand::random::<u16>());
        Some((
            self.server.salt.clone(),
            self.server
                .g
                .modexp(self.server.diffie_hellman.get_private_key(), &self.server.n),
            self.random.as_ref().unwrap().clone(),
        ))
    }

    fn simple_verify(&mut self, hmac: &[u8]) -> bool {
        let random_as_biguint = ToBigUint::to_biguint(self.random.as_ref().unwrap()).unwrap();
        let base = self
            .server
            .client_public_key
            .as_ref()
            .unwrap()
            .mul(self.server.v.modexp(&random_as_biguint, &self.server.n))
            % &self.server.n;

        let session_key = base.modexp(self.server.diffie_hellman.get_private_key(), &self.server.n);
        let key = Sha256::digest(&session_key.to_bytes_le());

        return hmac_sha256(&key[..], &self.server.salt) == hmac;
    }
}
impl<'a> SimpleSRPServer<'a> {
    pub fn new(n: &BigUint, email: &[u8], password: &[u8]) -> Self {
        SimpleSRPServer {
            server: SRPServer::new(n, email, password),
            random: None,
        }
    }
}

pub trait SRPServerFacade {
    fn new(n: &BigUint, email: &[u8], password: &[u8]) -> Self;

    // sends email and public key
    // gets salt and server "password specific" public key
    fn exchange_public_keys(
        &mut self,
        email: &[u8],
        client_public_key: &BigUint,
    ) -> Option<(Vec<u8>, BigUint)>;

    fn verify(&self, hmac: &[u8]) -> bool;
}

pub struct SRPClient<'a, T> {
    k: BigUint,
    g: BigUint,
    server: &'a mut T,
    n: BigUint,
    email: Vec<u8>,
    password: Vec<u8>,
    diffie_hellman: DiffieHellman<'a>,
    server_salt: Option<Vec<u8>>,
    server_public_key: Option<BigUint>,
}

pub struct SimpleSRPClient<'a, T>
where
    T: SimpleSRPServerFacade,
{
    client: SRPClient<'a, T>,
    server_random: Option<u16>,
}

impl<'a, T> SimpleSRPClient<'a, T>
where
    T: SimpleSRPServerFacade,
{
    pub fn new(server: &'a mut T, n: &BigUint, email: &[u8], password: &[u8]) -> Self {
        SimpleSRPClient {
            client: SRPClient::new(server, n, email, password),
            server_random: None,
        }
    }
    pub fn simple_exchange_public_keys(&mut self) {
        if let Some((salt, server_public_key, random)) =
            self.client.server.simple_exchange_public_keys(
                &self.client.email,
                self.client.diffie_hellman.get_public_key(),
            )
        {
            self.client.server_salt = Some(salt);
            self.client.server_public_key = Some(server_public_key);
            self.server_random = Some(random);
        } else {
            panic!("email isn't recognized by server..");
        }
    }

    pub fn send_verification(&mut self) -> bool {
        let x_hash = Sha256::digest(
            &[
                self.client.server_salt.as_ref().unwrap(),
                &self.client.password[..],
            ]
            .concat(),
        );
        let x = BigUint::from_bytes_le(&x_hash);

        let server_random_as_biguint =
            ToBigUint::to_biguint(self.server_random.as_ref().unwrap()).unwrap();

        let session_key = self.client.server_public_key.as_ref().unwrap().modexp(
            &(self.client.diffie_hellman.get_private_key() + x.mul(server_random_as_biguint)),
            &self.client.n,
        );

        let key = Sha256::digest(&session_key.to_bytes_le());
        self.client.server.simple_verify(&hmac_sha256(
            &key[..],
            self.client.server_salt.as_ref().unwrap(),
        ))
    }
}

impl<'a, T> SRPClient<'a, T> {
    pub fn new(server: &'a mut T, n: &BigUint, email: &[u8], password: &[u8]) -> Self {
        let g = ToBigUint::to_biguint(&2).unwrap();
        let k = ToBigUint::to_biguint(&3).unwrap();
        SRPClient {
            server,
            n: n.clone(),
            email: email.to_vec(),
            password: password.to_vec(),
            diffie_hellman: DiffieHellman::owning_new(n.clone(), &g),
            server_salt: None,
            server_public_key: None,
            g,
            k,
        }
    }
}
impl<'a, T> SRPClient<'a, T>
where
    T: SRPServerFacade,
{
    pub fn exchange_public_keys(&mut self) {
        if let Some((salt, server_public_key)) = self
            .server
            .exchange_public_keys(&self.email, self.diffie_hellman.get_public_key())
        {
            self.server_salt = Some(salt);
            self.server_public_key = Some(server_public_key);
        } else {
            panic!("email isn't recognized by server..");
        }
    }
    pub fn send_verification(&mut self) -> bool {
        let u_hash = Sha256::digest(
            &[
                self.diffie_hellman.get_public_key().to_bytes_le(),
                self.server_public_key.as_ref().unwrap().to_bytes_le(),
            ]
            .concat(),
        );
        let u = BigUint::from_bytes_le(&u_hash);

        let x_hash =
            Sha256::digest(&[&self.server_salt.as_ref().unwrap()[..], &self.password[..]].concat());
        let x = BigUint::from_bytes_le(&x_hash);
        // adding to n to prevent overflow (sub something bigger than server_public_key)
        let base = self.server_public_key.as_ref().unwrap().add(&self.n)
            - (self.k.clone().mul(self.g.modexp(&x, &self.n)) % &self.n) % &self.n;
        let exp = self.diffie_hellman.get_private_key() + u.mul(x);
        let session_key = base.modexp(&exp, &self.n);
        let key = Sha256::digest(&session_key.to_bytes_le());

        self.server.verify(&hmac_sha256(
            &key[..],
            &self.server_salt.as_ref().unwrap()[..],
        ))
    }
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    let used_key;
    if key.len() > 64 {
        used_key = Sha256::digest(key).to_vec();
    } else if key.len() < 64 {
        used_key = [key, &vec![0; 64 - key.len()]].concat();
    } else {
        used_key = key.to_vec();
    }

    let outer_key_pad: Vec<u8> = used_key.iter().map(|b| b ^ 0x5C).collect();
    let inner_key_pad: Vec<u8> = used_key.iter().map(|b| b ^ 0x36).collect();

    Sha256::digest(
        &[
            &outer_key_pad[..],
            &Sha256::digest(&[&inner_key_pad, message].concat())[..],
        ]
        .concat(),
    )
    .to_vec()
}
