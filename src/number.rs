use num_bigint::{BigInt, BigUint, ToBigInt, ToBigUint};
use num_traits::{One, Zero};
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use std::ops::DivAssign;

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::RandBigInt;

    #[test]
    fn test_mod_inverse() {
        let a = ToBigUint::to_biguint(&11).unwrap();
        let m = ToBigUint::to_biguint(&26).unwrap();

        assert_eq!(ToBigUint::to_biguint(&19).unwrap(), a.invmod(&m).unwrap());
    }

    #[test]
    fn test_modexp() {
        let mut rng = rand::thread_rng();
        let a: BigUint = rng.gen_biguint(32);
        let small_e = (rand::random::<u8>() % 4) as u32;
        let small_e_as_biguint = BigUint::from(small_e);
        let modulus: BigUint = rng.gen_biguint(8);
        let expected = a.modpow(&small_e_as_biguint, &modulus);
        assert_eq!(a.modexp(&small_e_as_biguint, &modulus), expected);
    }

    #[test]
    fn test_cube_root() {
        let mut rng = rand::thread_rng();
        let a: BigUint = rng.gen_biguint(32);
        let b: BigUint = &a + rng.gen_biguint(32);
        let estimate_of_cube_root = cube_root(&a, &b);

        assert!(estimate_of_cube_root.pow(3) > a);
        assert!(estimate_of_cube_root.pow(3) < b);
    }
}

pub trait ModInverse {
    fn invmod(&self, modulus: &BigUint) -> Option<BigUint>;
}

impl ModInverse for BigUint {
    fn invmod(&self, m: &BigUint) -> Option<BigUint> {
        // TODO: clarify this function
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

pub fn estimate_cube_root(n: &BigUint) -> BigUint {
    // a quick estimate for newton's method
    // basically relying on the fact that: (2^x)^3 == n for some x
    // and how do we estimate x?
    // well - this leads to: x == lg(n) / 3
    let hex_digits = n.to_str_radix(16).len();
    let log_n_estimate = hex_digits * 4;

    let two_power_cube_root_estimate = log_n_estimate / 3;

    return ToBigUint::to_biguint(&2)
        .unwrap()
        .pow(two_power_cube_root_estimate as u32);
}

pub fn cube_root(lower_range: &BigUint, upper_range: &BigUint) -> BigUint {
    let lower_range_as_int = ToBigInt::to_bigint(lower_range).unwrap();
    let upper_range_as_int = ToBigInt::to_bigint(upper_range).unwrap();
    let mut estimate = ToBigInt::to_bigint(
        &((estimate_cube_root(lower_range) + estimate_cube_root(upper_range)) / 2u8),
    )
    .unwrap();
    let range_middle = (&lower_range_as_int + &upper_range_as_int) / 2u8;
    while &estimate.pow(3) <= &lower_range_as_int || &estimate.pow(3) >= &upper_range_as_int {
        let f_estimate = estimate.pow(3) - &range_middle;
        let dervied_f_estimate = estimate.pow(2) * 3u8;
        estimate = estimate - (f_estimate / dervied_f_estimate);
    }

    return ToBigUint::to_biguint(&estimate).unwrap();
}

pub fn generate_weak_prime(bits: u16) -> Result<BigNum, ErrorStack> {
    let mut big = BigNum::new()?;

    big.generate_prime(bits as i32, false, None, None)?;
    Ok(big)
}

pub fn message_to_biguint(message: &[u8]) -> BigUint {
    BigUint::from_bytes_be(message)
}

pub fn biguint_to_message(biguint: &BigUint) -> Vec<u8> {
    biguint.to_bytes_be()
}
