use crate::aes::{decrypt_cbc_ecb_128_bit, encrypt_cbc_ecb_128_bit};
use crate::challenges::protocols::diffie_hellman::{
    DiffieHellmanParameter, GParameter, ProtocolMitm,
};
use crate::protocols::diffie_hellman::get_key_from_int;
use crate::protocols::diffie_hellman::negotiated_groups_diffie_hellman::NegotiatedServerFacade;
use num_bigint::{BigUint, ToBigUint};
use sha1::{Digest, Sha1};
use std::ops::Sub;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::diffie_hellman::negotiated_groups_diffie_hellman::NegotiatedClient;
    use crate::protocols::diffie_hellman::{ProtocolClient, ProtocolServer};
    const MESSAGE: &[u8] = b"Hello, World!";

    #[test]
    fn test_diffie_hellman_negotiated_protocol_mitm_g_1() {
        let mut server = ProtocolServer::new();

        let mut mitm = ProtocolMitm::new_negotiated(&mut server, GParameter::One);

        let mut client = ProtocolClient::new(&mut mitm);
        NegotiatedClient::syn(&mut client);

        client.exchange_public_keys();

        NegotiatedClient::send_message(&mut client, MESSAGE).unwrap();
        assert_eq!(mitm.get_messages()[0], MESSAGE);
    }
    #[test]
    fn test_diffie_hellman_negotiated_protocol_mitm_g_p() {
        let mut server = ProtocolServer::new();

        let mut mitm = ProtocolMitm::new_negotiated(&mut server, GParameter::P);

        let mut client = ProtocolClient::new(&mut mitm);
        NegotiatedClient::syn(&mut client);

        client.exchange_public_keys();

        NegotiatedClient::send_message(&mut client, MESSAGE).unwrap();
        assert_eq!(mitm.get_messages()[0], MESSAGE);
    }
    #[test]
    fn test_diffie_hellman_negotiated_protocol_mitm_g_p_minus_1() {
        let mut server = ProtocolServer::new();

        let mut mitm =
            ProtocolMitm::new_negotiated(&mut server, GParameter::PMinus1(BigUint::default()));

        let mut client = ProtocolClient::new(&mut mitm);
        NegotiatedClient::syn(&mut client);

        client.exchange_public_keys();

        NegotiatedClient::send_message(&mut client, MESSAGE).unwrap();
        assert_eq!(mitm.get_messages()[0], MESSAGE);
    }
}

impl<'b, T> ProtocolMitm<'b, T>
where
    T: NegotiatedServerFacade,
{
    pub fn new_negotiated(server: &'b mut T, g: GParameter) -> ProtocolMitm<'b, T>
    where
        T: NegotiatedServerFacade,
    {
        ProtocolMitm {
            server,
            parameter: Some(DiffieHellmanParameter::G(g)),
            messages: Vec::new(),
        }
    }
}

impl<'b, T> NegotiatedServerFacade for ProtocolMitm<'b, T>
where
    T: NegotiatedServerFacade,
{
    fn get_syn(&mut self, p: &BigUint, _: &BigUint) {
        if let Some(DiffieHellmanParameter::G(g)) = self.parameter.as_mut() {
            match g {
                GParameter::One => {
                    self.server
                        .get_syn(p, ToBigUint::to_biguint(&1).as_ref().unwrap());
                }
                GParameter::P => {
                    self.server.get_syn(p, p);
                }
                GParameter::PMinus1(p_minus_1) => {
                    *p_minus_1 = p.sub(1u32);
                    self.server.get_syn(p, p_minus_1);
                }
            }
        } else {
            panic!("Invalid parameter was sent. state is undefined..");
        }
    }

    fn exchange_public_keys(&mut self, _: &BigUint) -> BigUint {
        if let Some(DiffieHellmanParameter::G(g)) = self.parameter.as_mut() {
            match g {
                GParameter::P => {
                    return self
                        .server
                        .exchange_public_keys(ToBigUint::to_biguint(&0).as_ref().unwrap());
                }
                // GParameter::One or GParameter::PMinus1
                _ => {
                    // give 1 as client pub key
                    // On g == 1 case this is will lead to the same session key as client
                    // on g == p - 1, we will find out as we decrypt if the client has 1 or -1
                    // and encrypt it with session_key == 1 before giving it to the server
                    return self
                        .server
                        .exchange_public_keys(ToBigUint::to_biguint(&1).as_ref().unwrap());
                }
            }
        } else {
            panic!("Invalid parameter was sent. state is undefined..");
        }
    }
    fn ack(&self) {
        self.server.ack()
    }

    fn echo_message(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if let DiffieHellmanParameter::G(g) = self.parameter.as_ref().unwrap() {
            match g {
                GParameter::PMinus1(p_minus_1) => {
                    let one_key = get_key_from_int(1);
                    let decryption_with_one_key = decrypt_cbc_ecb_128_bit(
                        &ciphertext[16..],
                        &one_key[..16],
                        &ciphertext[..16],
                    );

                    if decryption_with_one_key.is_ok() {
                        self.messages.push(decryption_with_one_key.unwrap());
                        // bet was correct - just give it to the server
                        return self.server.echo_message(ciphertext);
                    }

                    let minus_1_key = Sha1::digest(&p_minus_1.to_bytes_le());
                    let decryption_with_minus_1 = decrypt_cbc_ecb_128_bit(
                        &ciphertext[16..],
                        &minus_1_key[..16],
                        &ciphertext[..16],
                    );

                    if decryption_with_minus_1.is_ok() {
                        // bet was wrong, re-encrypt with 1 so server will get what he expects
                        let result = self.server.echo_message(
                            &[
                                &ciphertext[..16],
                                &encrypt_cbc_ecb_128_bit(
                                    decryption_with_minus_1.as_ref().unwrap(),
                                    &one_key[..16],
                                    &ciphertext[..16],
                                )[..],
                            ]
                            .concat(),
                        );
                        self.messages.push(decryption_with_minus_1.unwrap());

                        return result;
                    } else {
                        panic!("Unexpected session key. Mitm operation failed...");
                    }
                }
                GParameter::P => {
                    let key = get_key_from_int(0);
                    self.messages.push(
                        decrypt_cbc_ecb_128_bit(&ciphertext[16..], &key[..16], &ciphertext[..16])
                            .unwrap(),
                    );

                    self.server.echo_message(ciphertext)
                }
                GParameter::One => {
                    let key = get_key_from_int(1);
                    self.messages.push(
                        decrypt_cbc_ecb_128_bit(&ciphertext[16..], &key[..16], &ciphertext[..16])
                            .unwrap(),
                    );

                    self.server.echo_message(ciphertext)
                }
            }
        } else {
            panic!("Invalid parameter was sent. state is undefined..");
        }
    }
}
