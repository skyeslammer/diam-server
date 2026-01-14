use argon2::Argon2;
use opaque_ke::{CipherSuite, Ristretto255, key_exchange::tripledh::TripleDh};
use sha2::Sha512;

// рабочий код
const SERVER_SETUP_SIZE: usize = 96;

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

    pub fn generate_server_setup() -> opaque_ke::ServerSetup<Self> {
        use rand_core::OsRng;
        let mut rng = OsRng;
        opaque_ke::ServerSetup::<Self>::new(&mut rng)
    }

    pub fn serialize(setup: &opaque_ke::ServerSetup<DefaultCipherSuite>) -> Vec<u8> {
        setup.serialize().to_vec()
    }

    pub fn deserialize(
        bytes: &[u8],
    ) -> Result<opaque_ke::ServerSetup<DefaultCipherSuite>, Box<dyn std::error::Error>> {
        if bytes.len() != SERVER_SETUP_SIZE {
            return Err(
                format!("Expected {} bytes, got {}", SERVER_SETUP_SIZE, bytes.len()).into(),
            );
        }

        use generic_array::{GenericArray, typenum::U96};
        let array = GenericArray::<u8, U96>::from_slice(bytes);

        opaque_ke::ServerSetup::<DefaultCipherSuite>::deserialize(&array).map_err(|e| e.into())
    }
}
