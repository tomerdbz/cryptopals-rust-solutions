pub mod negotiated_groups_diffie_hellman;
pub mod secure_remote_password;
use crate::aes::decrypt_cbc_ecb_128_bit;
use crate::protocols::diffie_hellman::{get_key_from_int, ServerFacade};
use num_bigint::BigUint;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::diffie_hellman::{Client, ProtocolClient, ProtocolServer};
    const MESSAGE: &[u8] = b"Hello, World!";

    #[test]
    fn test_diffie_hellman_protocol_mitm() {
        let mut server = ProtocolServer::new();

        let mut mitm = ProtocolMitm::new(&mut server);

        let mut client = ProtocolClient::new(&mut mitm);
        Client::syn(&mut client);
        Client::send_message(&mut client, b"Hello, World!");

        assert_eq!(mitm.get_messages()[0], MESSAGE);
    }
}

pub enum GParameter {
    One,
    P,
    PMinus1(BigUint),
}

pub enum DiffieHellmanParameter {
    P(BigUint),
    G(GParameter),
}

pub struct ProtocolMitm<'b, T> {
    server: &'b mut T,
    parameter: Option<DiffieHellmanParameter>,
    messages: Vec<Vec<u8>>,
}

impl<'b, T> ProtocolMitm<'b, T> {
    pub fn new(server: &'b mut T) -> ProtocolMitm<'b, T>
    where
        T: ServerFacade,
    {
        ProtocolMitm {
            server,
            parameter: None,
            messages: Vec::new(),
        }
    }
}

impl<'b, T> ProtocolMitm<'b, T> {
    pub fn get_messages(&self) -> &Vec<Vec<u8>> {
        &self.messages
    }
}

impl<'b, T> ServerFacade for ProtocolMitm<'b, T>
where
    T: ServerFacade,
{
    fn get_syn(&mut self, p: &BigUint, g: &BigUint, _: &BigUint) {
        self.parameter = Some(DiffieHellmanParameter::P(p.clone()));
        self.server.get_syn(p, g, p);
    }
    fn ack(&self) -> BigUint {
        if let DiffieHellmanParameter::P(p) = self.parameter.as_ref().unwrap() {
            return p.clone();
        } else {
            panic!("Invalid parameter was sent. state is undefined..");
        }
    }

    fn echo_message(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let result = self.server.echo_message(ciphertext);

        let key = get_key_from_int(0);

        self.messages.push(
            decrypt_cbc_ecb_128_bit(&ciphertext[16..], &key[..16], &ciphertext[..16]).unwrap(),
        );

        result
    }
}
