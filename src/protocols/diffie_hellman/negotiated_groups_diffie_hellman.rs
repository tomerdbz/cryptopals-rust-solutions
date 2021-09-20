use crate::protocols::diffie_hellman::{
    decrypt_message, encrypt_message, ProtocolClient, ProtocolServer, ProtocolState,
};
use num_bigint::BigUint;

#[cfg(test)]
mod tests {
    use super::*;
    const MESSAGE: &[u8] = b"Hello, World!";

    #[test]
    fn test_diffie_hellman_negotiated_protocol() {
        let mut server = ProtocolServer::new();
        let mut client = ProtocolClient::new(&mut server);
        NegotiatedClient::syn(&mut client);

        client.exchange_public_keys();

        assert_eq!(
            NegotiatedClient::send_message(&mut client, MESSAGE).unwrap(),
            MESSAGE
        );
    }
}
pub trait NegotiatedClient {
    fn syn(&mut self);
    fn exchange_public_keys(&mut self);
    fn send_message(&mut self, message: &[u8]) -> Option<Vec<u8>>;
}

pub trait NegotiatedServerFacade {
    fn get_syn(&mut self, p: &BigUint, g: &BigUint);
    fn ack(&self);
    fn exchange_public_keys(&mut self, other_public_key: &BigUint) -> BigUint;
    fn echo_message(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>>;
}

impl<'a> NegotiatedServerFacade for ProtocolServer<'a> {
    fn get_syn(&mut self, p: &BigUint, g: &BigUint) {
        self.state = Some(ProtocolState::owning_new(p.clone(), g));
    }
    fn ack(&self) {}

    fn exchange_public_keys(&mut self, other_public_key: &BigUint) -> BigUint {
        self.state
            .as_mut()
            .unwrap()
            .set_other_public_key(other_public_key.clone());

        self.state.as_ref().unwrap().get_public_key().clone()
    }
    fn echo_message(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.state.as_mut().unwrap().set_other_iv(&ciphertext[..16]);
        decrypt_message(self.state.as_mut().unwrap(), &ciphertext[16..])
    }
}

impl<'a, 'b, T> NegotiatedClient for ProtocolClient<'a, 'b, T>
where
    T: NegotiatedServerFacade,
{
    fn syn(&mut self) {
        self.server.get_syn(&self.p, &self.g);

        self.server.ack();
    }

    fn exchange_public_keys(&mut self) {
        self.state.set_other_public_key(
            self.server
                .exchange_public_keys(self.state.get_public_key()),
        );
    }

    fn send_message(&mut self, message: &[u8]) -> Option<Vec<u8>> {
        self.server
            .echo_message(&encrypt_message(&mut self.state, message)?)
    }
}
