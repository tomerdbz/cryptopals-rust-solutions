use crate::diffie_hellman::ModExp;
use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};
use num_traits::{One, Zero};
use openssl::bn::BigNum;
use openssl::error::ErrorStack;

#[cfg(test)]
mod tests {
    use super::*;
    const MESSAGE: &[u8] = b"../resources/cryptopals_set1_challenge6.txt";

    #[test]
    fn test_mod_inverse() {
        let a = ToBigUint::to_biguint(&11).unwrap();
        let m = ToBigUint::to_biguint(&26).unwrap();

        assert_eq!(ToBigUint::to_biguint(&19).unwrap(), a.invmod(&m).unwrap());
    }

    #[test]
    fn test_rsa_encrypt_decrypt() {
        let rsa = RsaCreds::new();
        let ciphertext = rsa.encrypt(MESSAGE);

        assert_eq!(MESSAGE, rsa.decrypt(&ciphertext));
    }
}

pub struct RsaCreds {
    public_key: (BigUint, BigUint),
    private_key: (BigUint, BigUint),
}

impl RsaCreds {
    pub fn new() -> Self {
        let e = ToBigUint::to_biguint(&3).unwrap();
        let (n, etta) = generate_rsa_n_etta(&e);

        let d = e.invmod(&etta).unwrap();
        RsaCreds {
            public_key: (e, n.clone()),
            private_key: (d, n),
        }
    }

    pub fn encrypt(&self, message: &[u8]) -> Vec<u8> {
        message_to_biguint(message)
            .modexp(&self.public_key.0, &self.public_key.1)
            .to_bytes_le()
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        biguint_to_message(
            &BigUint::from_bytes_le(ciphertext).modexp(&self.private_key.0, &self.private_key.1),
        )
    }

    pub fn get_public_key(&self) -> &(BigUint, BigUint) {
        &self.public_key
    }
}

pub fn message_to_biguint(message: &[u8]) -> BigUint {
    BigUint::parse_bytes(&hex::encode(message).as_bytes(), 16).unwrap()
}

pub fn biguint_to_message(biguint: &BigUint) -> Vec<u8> {
    hex::decode(&biguint.to_str_radix(16)).unwrap()
}

pub trait ModInverse {
    fn invmod(&self, modulus: &BigUint) -> Option<BigUint>;
}

impl ModInverse for BigUint {
    fn invmod(&self, m: &BigUint) -> Option<BigUint> {
        // this implementation returns None if self and m are not co-prime
        let one: BigUint = One::one();
        let zero: BigUint = Zero::zero();

        if *m == zero || *m == one {
            return None;
        }

        let mut next_iteration_scalar = self.clone();
        let mut next_iteration_mod = m.clone();
        let mut a_multiplier: BigInt = One::one();
        let mut m_multiplier: BigInt = Zero::zero();

        // performing extended euclidean algorithm
        while next_iteration_scalar > one {
            let current_iteration_scalar = next_iteration_scalar;
            let current_iteration_mod = next_iteration_mod;

            if &current_iteration_mod == &zero {
                return None;
            }

            let result =
                ToBigInt::to_bigint(&(current_iteration_scalar.clone() / &current_iteration_mod))
                    .unwrap();
            let remainder = current_iteration_scalar % &current_iteration_mod;

            let last_m_multiplier = m_multiplier.clone();
            let last_a_multiplier = a_multiplier;
            m_multiplier = last_a_multiplier - result * &last_m_multiplier;
            a_multiplier = ToBigInt::to_bigint(&last_m_multiplier).unwrap();

            next_iteration_mod = remainder;
            next_iteration_scalar = current_iteration_mod;
        }

        if a_multiplier < ToBigInt::to_bigint(&zero).unwrap() {
            a_multiplier += ToBigInt::to_bigint(m).unwrap();
        }

        Some(ToBigUint::to_biguint(&a_multiplier).unwrap())
    }
}

// we might need a couple of tries to get an etta that is co-prime to e
fn generate_rsa_n_etta(e: &BigUint) -> (BigUint, BigUint) {
    let mut n = None;
    let mut etta = None;

    while n.is_none() {
        let p_raw = generate_weak_prime(528).unwrap();
        let q_raw = generate_weak_prime(528).unwrap();
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

fn generate_weak_prime(bits: u16) -> Result<BigNum, ErrorStack> {
    let mut big = BigNum::new()?;

    big.generate_prime(bits as i32, false, None, None)?;
    Ok(big)
}
