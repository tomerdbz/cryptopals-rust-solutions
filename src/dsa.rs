use crate::number::{message_to_biguint, ModExp, ModInverse};
use num_bigint::{BigUint, RandBigInt, ToBigInt, ToBigUint};
use num_traits::Zero;
use sha1::Digest;

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::Sha1;
    const BASE64_MESSAGE: &[u8] = b"Rm9yIHRob3NlIHRoYXQgZW52eSBhIE1DIGl0IGNhbiBiZSBoYXphcmRvdXMgdG8geW91ciBoZWFsdGgKU28gYmUgZnJpZW5kbHksIGEgbWF0dGVyIG9mIGxpZmUgYW5kIGRlYXRoLCBqdXN0IGxpa2UgYSBldGNoLWEtc2tldGNoCg==";

    #[test]
    fn test_dsa_sign_verify() {
        P.with(|p| {
            Q.with(|q| {
                G.with(|g| {
                    let dsa_parameters = DsaParameters { p, q, g };
                    let dsa = DsaCreds::new(&dsa_parameters);
                    let signature = dsa.sign::<Sha1>(BASE64_MESSAGE);
                    let verification = DsaCreds::verify::<Sha1>(
                        &dsa_parameters,
                        dsa.get_public_key(),
                        &signature,
                        BASE64_MESSAGE,
                    );
                    assert!(verification);
                });
            });
        });
    }
}

pub fn biguint_sub_mod(n1: &BigUint, n2: &BigUint, m: &BigUint) -> BigUint {
    let sub = (ToBigInt::to_bigint(n1).unwrap() - ToBigInt::to_bigint(n2).unwrap())
        % ToBigInt::to_bigint(m).unwrap();
    ToBigUint::to_biguint(
        &((sub + ToBigInt::to_bigint(m).unwrap()) % ToBigInt::to_bigint(m).unwrap()),
    )
    .unwrap()
}

thread_local!(pub static P: BigUint = BigUint::parse_bytes(b"800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16).unwrap());
thread_local!(pub static Q: BigUint = BigUint::parse_bytes(b"f4f47f05794b256174bba6e9b396a7707e563c5b", 16).unwrap());
thread_local!(pub static G: BigUint = BigUint::parse_bytes(b"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16).unwrap());

pub struct DsaParameters<'a> {
    pub g: &'a BigUint,
    pub p: &'a BigUint,
    pub q: &'a BigUint,
}

#[derive(PartialOrd, PartialEq)]
pub struct Signature {
    pub r: BigUint,
    pub s: BigUint,
}

pub struct DsaCreds<'a> {
    pub dsa_parameters: &'a DsaParameters<'a>,
    pub public_key: BigUint,
    pub private_key: BigUint,
}

impl<'a> DsaCreds<'a> {
    pub fn new(dsa_parameters: &'a DsaParameters<'a>) -> Self {
        let mut rng = rand::thread_rng();
        let private_key = rng.gen_biguint(dsa_parameters.q.bits()) % (dsa_parameters.q - 1u8);
        let public_key = dsa_parameters.g.modexp(&private_key, &dsa_parameters.p);
        DsaCreds::<'a> {
            public_key,
            private_key,
            dsa_parameters,
        }
    }

    pub fn get_public_key(&self) -> &BigUint {
        return &self.public_key;
    }

    pub fn sign<T: Digest>(&self, message: &[u8]) -> Signature {
        let zero: BigUint = Zero::zero();
        let mut r: BigUint = zero.clone();
        let mut s: BigUint = zero.clone();
        while &r == &zero || &s == &zero {
            let mut rng = rand::thread_rng();
            let k = rng.gen_biguint(self.dsa_parameters.q.bits()) % (self.dsa_parameters.q - 1u8);
            r = self.dsa_parameters.g.modexp(&k, self.dsa_parameters.p) % self.dsa_parameters.q;

            if &r != &zero {
                s = (k.invmod(self.dsa_parameters.q).unwrap()
                    * (message_to_biguint(&T::digest(&message)[..]) + &self.private_key * &r))
                    % self.dsa_parameters.q;
            }
        }

        return Signature { r, s };
    }

    pub fn verify<T: Digest>(
        dsa_parameters: &DsaParameters,
        public_key: &BigUint,
        signature: &Signature,
        message: &[u8],
    ) -> bool {
        let zero: BigUint = Zero::zero();
        if &signature.r == &zero || &signature.r >= dsa_parameters.q {
            return false;
        }
        if &signature.s == &zero || &signature.s >= dsa_parameters.q {
            return false;
        }

        let w = signature.s.invmod(&dsa_parameters.q).unwrap();
        let u1 = (message_to_biguint(&T::digest(message)[..]) * &w) % dsa_parameters.q;
        let u2 = (&signature.r * &w) % dsa_parameters.q;
        let v = ((dsa_parameters.g.modexp(&u1, dsa_parameters.p)
            * public_key.modexp(&u2, dsa_parameters.p))
            % dsa_parameters.p)
            % dsa_parameters.q;

        return &v == &signature.r;
    }
}
