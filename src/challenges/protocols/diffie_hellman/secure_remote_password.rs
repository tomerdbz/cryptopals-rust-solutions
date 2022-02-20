use crate::diffie_hellman::DiffieHellman;
use crate::number::ModExp;
use crate::protocols::diffie_hellman::secure_remote_password::{
    hmac_sha256, SRPServerFacade, SimpleSRPServerFacade,
};
use num_bigint::BigUint;
use num_bigint::ToBigUint;
use sha2::{Digest, Sha256};
use std::ops::Mul;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::diffie_hellman::secure_remote_password::{SRPServer, SimpleSRPClient};
    const EMAIL: &[u8] = b"guesswho@crpyto.com";
    const PASSWORD: &[u8] = b"lolzzzz";

    #[test]
    fn test_secure_remote_password_malicious_client() {
        let n = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
        let mut server = SRPServer::new(&n, EMAIL, PASSWORD);
        let mut client = MaliciousClient::new(&mut server, EMAIL);

        client.exchange_public_keys();
        let is_verified = client.send_verification();

        assert!(is_verified);
    }
    #[test]
    fn test_simple_secure_remote_offline_dict_attack() {
        let n = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
        let password_dict: &[&[u8]] = &[b"miguele", b"mcdonal", b"whyoper", PASSWORD];
        let mut server = SimpleSRPMitm::new(&n, &password_dict);
        let mut client = SimpleSRPClient::new(&mut server, &n, EMAIL, PASSWORD);

        client.simple_exchange_public_keys();
        client.send_verification();

        assert_eq!(PASSWORD, server.get_password().unwrap());
    }
}

pub struct MaliciousClient<'a, T>
where
    T: SRPServerFacade,
{
    email: Vec<u8>,
    server: &'a mut T,
    server_salt: Option<Vec<u8>>,
}

impl<'a, T> MaliciousClient<'a, T>
where
    T: SRPServerFacade,
{
    pub fn new(server: &'a mut T, email: &[u8]) -> Self {
        MaliciousClient {
            email: email.to_vec(),
            server,
            server_salt: None,
        }
    }

    pub fn exchange_public_keys(&mut self) {
        if let Some((salt, _)) = self
            .server
            .exchange_public_keys(&self.email, ToBigUint::to_biguint(&0).as_ref().unwrap())
        {
            self.server_salt = Some(salt);
        } else {
            panic!("email isn't recognized by server..");
        }
    }
    pub fn send_verification(&mut self) -> bool {
        let session_key = ToBigUint::to_biguint(&0).unwrap();
        let key = Sha256::digest(&session_key.to_bytes_le());

        self.server.verify(&hmac_sha256(
            &key[..],
            &self.server_salt.as_ref().unwrap()[..],
        ))
    }
}

pub struct SimpleSRPMitm<'a> {
    salt: Vec<u8>,
    g: BigUint,
    u: u16,
    b_public_key: BigUint,
    b: BigUint,
    n: BigUint,
    client_public_key: Option<BigUint>,
    password_dict: &'a [&'a [u8]],
    cracked_password: Option<&'a [u8]>,
}

impl<'a> SimpleSRPServerFacade for SimpleSRPMitm<'a> {
    fn simple_exchange_public_keys(
        &mut self,
        _: &[u8],
        client_public_key: &BigUint,
    ) -> Option<(Vec<u8>, BigUint, u16)> {
        self.client_public_key = Some(client_public_key.clone());
        Some((self.salt.clone(), self.b_public_key.clone(), self.u))
    }

    fn simple_verify(&mut self, hmac: &[u8]) -> bool {
        let crack_password = || {
            let x_dict = self.password_dict.iter().map(|p| {
                (
                    p,
                    BigUint::from_bytes_le(&Sha256::digest(&[&self.salt[..], p].concat())),
                )
            });

            let v_dict = x_dict.map(|x| (x.0, self.g.modexp(&x.1, &self.n)));

            let u_as_biguint = ToBigUint::to_biguint(&self.u).unwrap();
            let s_dict = v_dict.map(|v| {
                (
                    v.0,
                    self.client_public_key
                        .as_ref()
                        .unwrap()
                        .mul(v.1.modexp(&u_as_biguint, &self.n))
                        .modexp(&self.b, &self.n),
                )
            });

            let k_dict = s_dict.map(|s| (s.0, Sha256::digest(&s.1.to_bytes_le())));
            let hmac_dict = k_dict.map(|k| (k.0, hmac_sha256(&k.1, &self.salt)));

            for (password, password_hmac) in hmac_dict {
                if password_hmac == hmac {
                    return Some(*password);
                }
            }

            return None;
        };

        self.cracked_password = crack_password();
        return true;
    }
}

impl<'a> SimpleSRPMitm<'a> {
    pub fn new(n: &BigUint, password_dict: &'a [&'a [u8]]) -> Self {
        let salt: Vec<u8> = (0..8).map(|_| rand::random::<u8>()).collect();
        let g = ToBigUint::to_biguint(&2).unwrap();
        let diffie_hellman = DiffieHellman::owning_new(n.clone(), &g);
        let u = rand::random::<u16>();
        let b = diffie_hellman.get_private_key();
        let b_public_key = g.modexp(diffie_hellman.get_private_key(), &n);

        SimpleSRPMitm {
            g,
            u,
            salt,
            password_dict,
            b_public_key,
            b: b.clone(),
            n: n.clone(),
            client_public_key: None,
            cracked_password: None,
        }
    }

    pub fn get_password(&self) -> Option<&'a [u8]> {
        self.cracked_password
    }
}
