use crate::dsa::{DsaCreds, DsaParameters, Signature, biguint_sub_mod};
use num_bigint::{BigUint, ToBigUint};
use sha1::Digest;
use crate::number::{ModInverse, ModExp};
use crate::number::message_to_biguint;
use num_bigint::{RandBigInt};
use num_traits::Zero;

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::Sha1;
    use crate::dsa::{P, Q, G};
    use crate::number::biguint_to_message;
    const BASE64_MESSAGE: &[u8] = b"Rm9yIHRob3NlIHRoYXQgZW52eSBhIE1DIGl0IGNhbiBiZSBoYXphcmRvdXMgdG8geW91ciBoZWFsdGgKU28gYmUgZnJpZW5kbHksIGEgbWF0dGVyIG9mIGxpZmUgYW5kIGRlYXRoLCBqdXN0IGxpa2UgYSBldGNoLWEtc2tldGNoCg==";

    fn parse_dsa_signatures() -> Vec<(Vec<u8>, BigUint, Signature)> {
        const DSA_SIGNED_MESSAGES: &str =
            include_str!("../../resources/cryptopals_set6_challenge44.txt");
        let mut lines = DSA_SIGNED_MESSAGES.split("\n");
        let mut has_input = true;
        let mut parse_msg_signature = || -> Option<(Vec<u8>, BigUint, Signature)> {
            let message = lines.next()?.split(": ").last()?;
            let s = lines.next()?.split(": ").last()?;
            let r = lines.next()?.split(": ").last()?;
            let hash = lines.next()?.split(": ").last()?;

            return Some((
                message.as_bytes().to_vec(),
                BigUint::parse_bytes(hash.as_bytes(), 16).unwrap(),
                Signature {
                    s: BigUint::parse_bytes(s.as_bytes(), 10).unwrap(),
                    r: BigUint::parse_bytes(r.as_bytes(), 10).unwrap(),
                },
            ));
        };

        let mut result = Vec::new();
        while has_input {
            if let Some(msg_hash_and_signature) = parse_msg_signature() {
                result.push(msg_hash_and_signature);
            } else {
                has_input = false;
            }
        }

        return result;
    }

    #[ignore]
    #[test]
    fn test_dsa_break_for_small_k() {
        P.with(|p| {
            Q.with(|q| {
                G.with(|g| {
                    let msg = base64::decode(BASE64_MESSAGE).unwrap();
                    let dsa_parameters = DsaParameters { p, g, q };
                    let signature = Signature {
                        r: BigUint::parse_bytes(
                            b"548099063082341131477253921760299949438196259240",
                            10,
                        )
                        .unwrap(),
                        s: BigUint::parse_bytes(
                            b"857042759984254168557880549501802188789837994940",
                            10,
                        )
                        .unwrap(),
                    };

                    let public_key = BigUint::parse_bytes(b"84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16).unwrap();

                    assert!(DsaCreds::verify::<Sha1>(
                        &dsa_parameters,
                        &public_key,
                        &signature,
                        &msg,
                    ));

                    let private_key = get_private_key::<Sha1>(0..u16::MAX as usize, &dsa_parameters, &signature, &msg).unwrap();

                    assert_eq!(hex::encode(Sha1::digest(hex::encode(biguint_to_message(&private_key)).as_bytes())), 
                    "0954edd5e0afe5542a4adf012611a91912a3ec16");
                })
            })
        });
    }

    #[test]
    fn test_dsa_break_k_reuse() {
        Q.with(|q| {
            let dsa_signatures = parse_dsa_signatures();
            let mut first_message_same_k = None;
            let mut second_message_same_k = None;

            // find two different messages with reused k's
            for (_, hash, signature) in &dsa_signatures {
                if let Some((_, other_hash, other_signature)) = dsa_signatures
                    .iter()
                    .filter(|(_, h, s)| {
                        if h == hash {
                            return false;
                        }
                        if signature.r == s.r {
                            return true;
                        }

                        return false;
                    })
                    .next()
                {
                    first_message_same_k = Some((hash, signature));
                    second_message_same_k = Some((other_hash, other_signature));
                    break;
                }
            }

            if first_message_same_k == None {
                panic!("Unable to find two messages with the same k");
            }

            let hash_subtraction = biguint_sub_mod(
                first_message_same_k.as_ref().unwrap().0,
                second_message_same_k.as_ref().unwrap().0,
                q,
            );

            let s_subtraction = biguint_sub_mod(
                &first_message_same_k.as_ref().unwrap().1.s,
                &second_message_same_k.as_ref().unwrap().1.s,
                q,
            );
            let s_sub_inverse = s_subtraction.invmod(q).unwrap();

            let k = hash_subtraction * s_sub_inverse % q;
            let private_key = (biguint_sub_mod(
                &(&first_message_same_k.as_ref().unwrap().1.s * k),
                first_message_same_k.as_ref().unwrap().0,
                q,
            ) * &first_message_same_k
                .as_ref()
                .unwrap()
                .1
                .r
                .invmod(q)
                .unwrap())
                % q;

            assert_eq!(
                hex::encode(
                    Sha1::digest(hex::encode(&biguint_to_message(&private_key)).as_bytes())
                        .to_vec()
                ),
                "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
            );
        });
    }

    #[test]
    fn test_dsa_break_with_g_corrupted_to_0() {
        P.with(|p| {
            Q.with(|q| {
                G.with(|g| {
                    // consider someone generates a public-private key pair
                    let mut mutable_g = g.clone();
                    let mutable_g_ptr = &mut mutable_g as *mut BigUint;
                    let dsa_parameters = DsaParameters { p, q, g:&mut mutable_g };
                    let dsa = DsaCreds::new(&dsa_parameters);

                    // consider we somehow corrupt g
                    unsafe {
                    *(mutable_g_ptr) = ToBigUint::to_biguint(&0).unwrap();
                    }

                    // now we sign
                    let signature = dsa.unsafe_sign::<Sha1>(BASE64_MESSAGE);

                    // this signature is valid for every message in case no validations for r occur
                    assert!(DsaCreds::unsafe_verify::<Sha1>(&dsa_parameters, dsa.get_public_key(), &signature, b"Complete nonsense ha?")); 
                });
            });
        });        
    }

    #[test]
    fn test_dsa_break_with_g_corrupted_to_p_plus_1() {
        P.with(|p| {
            Q.with(|q| {
                G.with(|g| {
                    // consider someone generates a public-private key pair
                    let mut mutable_g = g.clone();
                    let mutable_g_ptr = &mut mutable_g as *mut BigUint;
                    let dsa_parameters = DsaParameters { p, q, g:&mut mutable_g };
                    let dsa = DsaCreds::new(&dsa_parameters);

                    // consider we somehow corrupt g
                    unsafe {
                        *(mutable_g_ptr) = p + ToBigUint::to_biguint(&1).unwrap();
                    }

                    // now we generate a magical signature
                    let mut rng = rand::thread_rng();
                    let z = rng.gen_biguint(q.bits());
                    let r = dsa.get_public_key().modexp(&z, &p) % q;
                    let s = (&r * z.invmod(q).unwrap()) % q;
                    let signature = Signature{r: r, s: s};

                    // this signature is valid for every message in case no validations for r occur
                    assert!(DsaCreds::unsafe_verify::<Sha1>(&dsa_parameters, dsa.get_public_key(), &signature, b"Complete nonsense ha?")); 
                });
            });
        });        
    }
 
}

pub trait DsaUnsafe {
    fn unsafe_sign<T: Digest>(&self, message: &[u8]) -> Signature;
    fn unsafe_verify<T: Digest>(
        dsa_parameters: &DsaParameters,
        public_key: &BigUint,
        signature: &Signature,
        message: &[u8],
    ) -> bool; 
}

impl DsaUnsafe for DsaCreds<'_> {
    fn unsafe_sign<T: Digest>(&self, message: &[u8]) -> Signature {
        let zero: BigUint = Zero::zero();
        let mut r: BigUint = zero.clone();
        let mut s: BigUint = zero.clone();
        while &r == &zero && &s == &zero {
            let mut rng = rand::thread_rng();
            let k = rng.gen_biguint(self.dsa_parameters.q.bits()) % (self.dsa_parameters.q - 1u8);
            r = self.dsa_parameters.g.modexp(&k, self.dsa_parameters.p) % self.dsa_parameters.q;
            s = (k.invmod(self.dsa_parameters.q).unwrap()
                * (message_to_biguint(&T::digest(&message)[..]) + &self.private_key * &r))
                % self.dsa_parameters.q;
        }

        return Signature { r, s };
    }

    fn unsafe_verify<T: Digest>(
        dsa_parameters: &DsaParameters,
        public_key: &BigUint,
        signature: &Signature,
        message: &[u8],
    ) -> bool {
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

pub fn get_private_key<T: Digest>(
    k_range: std::ops::Range<usize>,
    dsa_parameters: &DsaParameters,
    signature: &Signature,
    message: &[u8],
) -> Option<BigUint> {
    let message_hash_as_int = message_to_biguint(&T::digest(message)[..]);
    let r_invmod = signature.r.invmod(dsa_parameters.q).unwrap();
    let result = k_range
        .map(|k| {
            let private_key =
                (biguint_sub_mod(&(&signature.s * k), &message_hash_as_int, dsa_parameters.q)
                    * &r_invmod)
                    % dsa_parameters.q;

            (private_key, k)
        })
        .map(|(x, k)| {
            let r = dsa_parameters
                .g
                .modexp(&ToBigUint::to_biguint(&k).unwrap(), dsa_parameters.p)
                % dsa_parameters.q;

            let s = (ToBigUint::to_biguint(&k)
                .unwrap()
                .invmod(dsa_parameters.q)
                .unwrap()
                * (&message_hash_as_int + &x * &r))
                % dsa_parameters.q;

            (Signature { r, s }, x)
        })
        .filter(|(s, _)| {
            return s == signature;
        })
        .next();

    if result.is_none() {
        return None;
    } else {
        return Some(result.unwrap().1);
    }
}