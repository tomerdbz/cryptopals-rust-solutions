#[cfg(test)]
mod tests {

    #[test]
    fn test_cookie_parsing() {
        let cookie = super::parsers::Cookie::from_str("foo=bar&baz=qux&zap=zazzle").unwrap();

        assert_eq!(&cookie["foo"], "bar");
        assert_eq!(&cookie["baz"], "qux");
        assert_eq!(&cookie["zap"], "zazzle");
    }

    #[test]
    fn test_profile_for_legit_input() {
        let cookie = super::parsers::profile_for("tomer@gmail.com").unwrap();
        assert_eq!(&cookie["role"], "user");
        assert_eq!(&cookie["uid"], "10");
    }

    #[test]
    fn test_profile_for_invalid_input() {
        let cookie = super::parsers::profile_for("tomer@gmail.com&role=admin");
        assert!(!cookie.is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_cookie() {
        let cookie = super::parsers::Cookie::from_str("foo=bar&baz=qux&zap=zazzle").unwrap();
        let encrypted_data = super::oracles::ecb_challenges::encrypt_cookie(&cookie);
        let decrypted_cookie = super::oracles::ecb_challenges::decrypt_cookie(&encrypted_data);

        assert_eq!(cookie, decrypted_cookie);
    }

    #[test]
    fn test_make_admin_role() {
        let admin_cookie = super::oracles::ecb_challenges::make_admin_role();

        assert_eq!(&admin_cookie["role"], "admin");
    }
}

use std::collections::HashMap;
use std::ops::Index;

#[derive(Debug, PartialEq)]
pub struct Cookie {
    attrs: HashMap<String, String>,
    string_repr: String,
}

#[derive(Debug)]
pub enum ParsingError {
    InvalidArgument,
}

impl Index<&str> for Cookie {
    type Output = str;

    fn index(&self, attr: &str) -> &Self::Output {
        HashMap::get(&self.attrs, attr).unwrap()
    }
}

impl ToString for Cookie {
    fn to_string(&self) -> String {
        self.string_repr.clone()
    }
}

impl Cookie {
    pub fn from_str(s: &str) -> Result<Cookie, ParsingError> {
        let mut cookie = Cookie {
            attrs: HashMap::new(),
            string_repr: String::from(s),
        };
        {
            for key_value in cookie.string_repr.split("&") {
                let key_value_vec: Vec<&str> = key_value.split("=").collect();

                if key_value_vec.len() != 2 {
                    return Err(ParsingError::InvalidArgument);
                }

                cookie.attrs.insert(
                    String::from(key_value_vec[0]),
                    String::from(key_value_vec[1]),
                );
            }
        }

        Ok(cookie)
    }
}

pub fn profile_for(email: &str) -> Result<Cookie, ParsingError> {
    if email.contains("&") {
        return Err(ParsingError::InvalidArgument);
    }
    Cookie::from_str(&(["email=", email, "&uid=10&role=user"].concat()))
}

use crate::aes;
use crate::challenges;
use crate::padding;

use std::collections::HashMap;

pub fn encrypt_cookie(cookie: &Cookie) -> Vec<u8> {
    AES_KEY.with(|aes_key| {
        let data_to_encrypt = cookie.to_string();
        if data_to_encrypt.len() % 16 != 0 {
            return super::encrypt_aes_128_ecb(
                &padding::pkcs7(data_to_encrypt.as_bytes(), 16).unwrap()[..],
                &aes_key[..],
            )
            .unwrap();
        } else {
            return aes::encrypt_aes_128_ecb(data_to_encrypt.as_bytes(), &aes_key[..]).unwrap();
        }
    })
}

pub fn decrypt_cookie(data: &[u8]) -> Cookie {
    Cookie::from_str(&AES_KEY.with(|aes_key| {
        let decrypted = aes::decrypt_aes_128_ecb(data, aes_key).unwrap();
        return String::from_utf8(super::padding::remove_pkcs7(&decrypted).unwrap_or(decrypted))
            .unwrap();
    }))
    .unwrap()
}

fn profile_for_ciphertext_generator(email: &str) -> Vec<u8> {
    encrypt_cookie(&profile_for(email).unwrap())
}

pub fn make_admin_role() -> Cookie {
    /*
            if I can then replace the encrypted "user" with encrypted "admin" - i won.
    obv - I know this is PKCS7 padding so the above is actually: (C is 0xC)
    (*)

    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    email=AAAAAAAAAA AAA&uid=10&role= userCCCCCCCCCCCC

    I can manually create:

    FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF
    email=AAAAAAAAAA adminBBBBBBBBBBB &uid=10&role=use r

    then I can take the second block and replace with the third block in (*)

            */
    let to_replace_third_block = profile_for_ciphertext_generator("AAAAAAAAAAAAA");
    let take_second_block = profile_for_ciphertext_generator(
        &String::from_utf8(b"AAAAAAAAAAadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b".to_vec())
            .unwrap(),
    );
    return decrypt_cookie(&[&to_replace_third_block[..32], &take_second_block[16..32]].concat());
}
