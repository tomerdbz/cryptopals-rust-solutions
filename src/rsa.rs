use crate::number::{
    biguint_to_message, generate_weak_prime, message_to_biguint, ModExp, ModInverse,
};
use num_bigint::{BigUint, ToBigUint};

#[cfg(test)]
mod tests {
    use super::*;
    const MESSAGE: &[u8] = b"../resources/cryptopals_set1_challenge6.txt";

    #[test]
    fn test_rsa_encrypt_decrypt() {
        let rsa = RsaCreds::new();
        let ciphertext = rsa.encrypt(MESSAGE);

        assert_eq!(MESSAGE, rsa.decrypt(&ciphertext));
    }
}

pub type Exponent = BigUint;
pub type Modulos = BigUint;

pub struct RsaCreds {
    public_key: (Exponent, Modulos),
    private_key: (Exponent, Modulos),
}

impl RsaCreds {
    pub fn new() -> Self {
        Self::new_with_key_length(2048)
    }

    pub fn new_with_n_etta(n: BigUint, etta: BigUint) -> Self {
        let e = ToBigUint::to_biguint(&3).unwrap();
        let d = e.invmod(&etta).unwrap();
        RsaCreds {
            public_key: (e, n.clone()),
            private_key: (d, n),
        }
    }

    pub fn new_with_key_length(key_length_bits: u16) -> Self {
        let e = ToBigUint::to_biguint(&3).unwrap();
        let (n, etta) = generate_rsa_n_etta(&e, key_length_bits);

        let d = e.invmod(&etta).unwrap();
        RsaCreds {
            public_key: (e, n.clone()),
            private_key: (d, n),
        }
    }

    pub fn encrypt_with_public_key(message: &[u8], public_key: &(Exponent, Modulos)) -> Vec<u8> {
        let message_as_biguint = message_to_biguint(message);
        if message_as_biguint > public_key.1 {
            panic!("Unable to encrypt with a message bigger than n..");
        }

        biguint_to_message(&message_as_biguint.modexp(&public_key.0, &public_key.1))
    }

    pub fn encrypt(&self, message: &[u8]) -> Vec<u8> {
        Self::encrypt_with_public_key(message, &self.public_key)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        let ciphertext_as_biguint = message_to_biguint(ciphertext);
        let result = biguint_to_message(
            &ciphertext_as_biguint.modexp(&self.private_key.0, &self.private_key.1),
        );

        result
    }

    pub fn get_public_key(&self) -> &(Exponent, Modulos) {
        &self.public_key
    }
}

// we might need a couple of tries to get an etta that is co-prime to e
fn generate_rsa_n_etta(e: &BigUint, key_length_bits: u16) -> (BigUint, BigUint) {
    let mut n = None;
    let mut etta = None;

    while n.is_none() {
        let p_raw = generate_weak_prime(key_length_bits / 2).unwrap();
        let q_raw = generate_weak_prime(key_length_bits / 2).unwrap();
        let p = BigUint::parse_bytes((&**p_raw.to_hex_str().unwrap()).as_bytes(), 16).unwrap();
        let q = BigUint::parse_bytes((&**q_raw.to_hex_str().unwrap()).as_bytes(), 16).unwrap();

        let et = (&p - &1u8) * (&q - &1u8);
        if e.invmod(&et).is_some() {
            n = Some(&p * &q);
            etta = Some(et);
        }
    }

    return (n.unwrap(), etta.unwrap());
}
