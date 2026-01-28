use argon2::Argon2;
use opaque_ke::{CipherSuite, Ristretto255, key_exchange::tripledh::TripleDh};
use sha2::Sha512;

// рабочий код
const SERVER_SETUP_SIZE: usize = 128;

pub type ServerSetup = opaque_ke::ServerSetup<DefaultCipherSuite>;

pub struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}

impl DefaultCipherSuite {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_server_setup() -> ServerSetup {
        use rand_core::OsRng;
        let mut rng = OsRng;
        ServerSetup::new(&mut rng)
    }

    pub fn serialize(setup: &ServerSetup) -> Vec<u8> {
        setup.serialize().to_vec()
    }

    pub fn deserialize(
        bytes: &[u8],
    ) -> Result<ServerSetup, Box<dyn std::error::Error>> {
        if bytes.len() != SERVER_SETUP_SIZE {
            return Err(
                format!("Expected {} bytes, got {}", SERVER_SETUP_SIZE, bytes.len()).into(),
            );
        }

        use generic_array::{GenericArray, typenum::U128};
        let array = GenericArray::<u8, U128>::from_slice(bytes);

        ServerSetup::deserialize(&array).map_err(|e| e.into())
    }
}

pub fn deserialize_server_setup(hex_str: &str) -> Result<ServerSetup, Box<dyn std::error::Error>> {
    let bytes = hex::decode(hex_str)?;
    DefaultCipherSuite::deserialize(&bytes)
}
