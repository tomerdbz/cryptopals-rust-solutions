use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_traits::{One, Zero};
use std::borrow::Cow;
use std::ops::DivAssign;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modexp() {
        let mut rng = rand::thread_rng();
        let a: BigUint = rng.gen_biguint(32);
        let small_e = (rand::random::<u8>() % 4) as u32;
        let small_e_as_biguint = BigUint::from(small_e);
        let modulus: BigUint = rng.gen_biguint(8);
        assert_eq!(
            a.modexp(&small_e_as_biguint, &modulus),
            a.pow(small_e) % modulus
        )
    }

    #[test]
    fn test_diffie_hellman() {
        let p = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
        let g = BigUint::from(2u8);
        let mut alice_diffie_hellman = DiffieHellman::non_owning_new(&p, &g);
        let alice_public_key = alice_diffie_hellman.get_public_key().clone();
        let mut bob_diffie_hellman = DiffieHellman::non_owning_new(&p, &g);
        let bob_public_key = bob_diffie_hellman.get_public_key().clone();
        bob_diffie_hellman.generate_session_key(&alice_public_key);
        alice_diffie_hellman.generate_session_key(&bob_public_key);

        assert_eq!(
            bob_diffie_hellman.get_session_key(),
            alice_diffie_hellman.get_session_key()
        );
    }
}

pub struct DiffieHellman<'a> {
    p: Cow<'a, BigUint>,
    private_key: BigUint,
    public_key: BigUint,
    session_key: Option<BigUint>,
}

impl<'a> DiffieHellman<'a> {
    pub fn non_owning_new(p: &'a BigUint, g: &BigUint) -> DiffieHellman<'a> {
        let (private, public) = DiffieHellman::gen_private_and_public_key(p, g);
        DiffieHellman::<'a> {
            p: Cow::Borrowed(p),
            private_key: private,
            public_key: public,
            session_key: None,
        }
    }
    pub fn owning_new(p: BigUint, g: &BigUint) -> DiffieHellman<'a> {
        let (private, public) = DiffieHellman::gen_private_and_public_key(&p, &g);
        DiffieHellman::<'a> {
            p: Cow::Owned(p),
            private_key: private,
            public_key: public,
            session_key: None,
        }
    }

    fn gen_private_and_public_key(p: &BigUint, g: &BigUint) -> (BigUint, BigUint) {
        let mut rng = rand::thread_rng();

        let private_key = rng.gen_biguint(256) % p;
        let public_key = g.modexp(&private_key, p);
        (private_key, public_key)
    }
    pub fn get_public_key(&'a self) -> &'a BigUint {
        &self.public_key
    }

    pub fn get_private_key(&self) -> &BigUint {
        &self.private_key
    }

    pub fn generate_session_key(&mut self, other_public_key: &BigUint) {
        self.session_key = Some(other_public_key.modexp(&self.private_key, &self.p));
    }

    pub fn get_session_key(&self) -> Option<&BigUint> {
        self.session_key.as_ref()
    }
}

pub trait ModExp {
    fn modexp(&self, exponent: &BigUint, modulus: &BigUint) -> BigUint;
}

impl ModExp for BigUint {
    fn modexp(&self, exponent: &BigUint, modulus: &BigUint) -> BigUint {
        if *modulus == ToBigUint::to_biguint(&1).unwrap() {
            return Zero::zero();
        }

        let zero: BigUint = Zero::zero();

        if self == &zero {
            return zero;
        }

        let mut result: BigUint = One::one();
        if exponent == &zero {
            return result;
        }

        let mut base = self.clone() % modulus;
        let mut exp = exponent.clone();

        while exp > Zero::zero() {
            // if exp % 2 == 1
            if exp.bit(0) {
                result = (result * base.clone()) % modulus;
            }

            exp.div_assign(2u32);
            base = (base.pow(2)) % modulus;
        }
        return result;
    }
}
