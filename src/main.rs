use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, edwards::EdwardsPoint, scalar::Scalar};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

fn keypair_from_scalar(scalar: &Scalar) -> Result<Keypair, Box<dyn std::error::Error>> {
    let sk = SecretKey::from_bytes(scalar.as_bytes())?;
    let pk: PublicKey = (&sk).into();
    Ok(Keypair {
        secret: sk,
        public: pk,
    })
}

fn pk_from_scalar(scalar: &Scalar) -> EdwardsPoint {
    let mut h = Sha512::new();
    let mut hash: [u8; 64] = [0u8; 64];
    let mut digest: [u8; 32] = [0u8; 32];

    h.update(scalar.as_bytes());
    hash.copy_from_slice(h.finalize().as_slice());
    digest.copy_from_slice(&hash[..32]);
    digest[0] &= 248;
    digest[31] &= 127;
    digest[31] |= 64;

    &Scalar::from_bits(digest) * &ED25519_BASEPOINT_TABLE
}

fn expand_scalar(scalar: &Scalar) -> (Scalar, [u8; 32]) {
    let mut h = Sha512::new();
    let mut hash: [u8; 64] = [0u8; 64];
    let mut lower: [u8; 32] = [0u8; 32];
    let mut upper: [u8; 32] = [0u8; 32];

    h.update(scalar.as_bytes());
    hash.copy_from_slice(h.finalize().as_slice());

    lower.copy_from_slice(&hash[00..32]);
    upper.copy_from_slice(&hash[32..64]);

    lower[0] &= 248;
    lower[31] &= 63;
    lower[31] |= 64;

    let (key, nonce) = (Scalar::from_bits(lower), upper);
    (key, nonce)
}

struct ExpandedSecretKey {
    key: Scalar,
    nonce: [u8; 32],
}

impl ExpandedSecretKey {
    fn generate<R>(csprng: &mut R) -> Self
    where
        R: rand::CryptoRng + rand::RngCore,
    {
        let mut rand_data = [0u8; 32];
        csprng.fill_bytes(&mut rand_data);
        let mut h = Sha512::new();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        h.update(&rand_data);
        hash.copy_from_slice(h.finalize().as_slice());

        lower.copy_from_slice(&hash[00..32]);
        upper.copy_from_slice(&hash[32..64]);

        lower[0] &= 248;
        lower[31] &= 63;
        lower[31] |= 64;

        Self {
            key: Scalar::from_bits(lower),
            nonce: upper,
        }
    }
    fn validate(R: &EdwardsPoint) -> bool {
        !R.is_small_order()
    }
    fn challenge(&self, pk: &EdwardsPoint, message: &[u8]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(self.public_key().compress().as_bytes());
        hasher.update(pk.compress().as_bytes());
        hasher.update(&message);
        Scalar::from_hash(hasher)
    }
    fn public_key(&self) -> EdwardsPoint {
        &self.key * &ED25519_BASEPOINT_TABLE
    }
    fn sign(&self, message: &[u8]) -> Signature {
        let mut hasher = Sha512::new();
        hasher.update(self.nonce);
        hasher.update(&message);
        let r = Scalar::from_hash(hasher);
        let R = &r * &ED25519_BASEPOINT_TABLE;

        hasher = Sha512::new();
        hasher.update(R.compress().as_bytes());
        hasher.update(self.public_key().compress().as_bytes()); // A
        hasher.update(&message); // M
        let challenge = &Scalar::from_hash(hasher);
        let s = &(challenge * self.key) + &r; // H(R, A, M) * s + r

        Signature { R, s }
    }
}

struct Signature {
    R: EdwardsPoint,
    s: Scalar,
}

impl Signature {
    fn verify(&self, pk: &EdwardsPoint, message: &[u8]) -> bool {
        let mut hasher = Sha512::new();
        hasher.update(self.R.compress().as_bytes());
        hasher.update(pk.compress().as_bytes());
        hasher.update(&message);
        &self.s * &ED25519_BASEPOINT_TABLE - &Scalar::from_hash(hasher) * pk == self.R
    }
}

fn signature(message: &[u8], sk: &Scalar) -> Scalar {
    let mut hasher = Sha512::new();

    let (key_exp, nonce_exp) = expand_scalar(sk);
    hasher.update(nonce_exp);
    hasher.update(&message);
    let r = Scalar::from_hash(hasher);
    let R = &r * &ED25519_BASEPOINT_TABLE;

    hasher = Sha512::new();
    hasher.update(R.compress().as_bytes());
    hasher.update(pk_from_scalar(sk).compress().as_bytes()); // A
    hasher.update(&message); // M

    let challenge = &Scalar::from_hash(hasher);

    let S = &(challenge * key_exp) + &r; // H(R, A, M) * s + r

    if verify(message, &pk_from_scalar(sk), &R, &S) {
        println!("SIGNATURE OK");
    } else {
        println!("SIGNATURE NOOO");
    }
    S
}

fn verify(message: &[u8], pk: &EdwardsPoint, R: &EdwardsPoint, S: &Scalar) -> bool {
    let mut hasher = Sha512::new();
    hasher.update(R.compress().as_bytes());
    hasher.update(pk.compress().as_bytes());
    hasher.update(&message);
    S * &ED25519_BASEPOINT_TABLE - &Scalar::from_hash(hasher) * pk == *R
}

fn test_adapter() {
    let G = &ED25519_BASEPOINT_TABLE;

    let mut csprng = OsRng;
    let msg = "hello";

    // Alice chooses r, t and sends R, T to Bob
    let r = ExpandedSecretKey::generate(&mut csprng);
    let t = ExpandedSecretKey::generate(&mut csprng);
    let (R, T) = (r.public_key(), t.public_key());
    assert!(ExpandedSecretKey::validate(&(&(&r.key + &t.key) * G)));

    // Bob generates challenge and sends c*b to Alice
    let b = ExpandedSecretKey::generate(&mut csprng);
    let B = b.public_key();
    let c = b.challenge(&(R + T), msg.as_bytes());
    let cb = c * &b.key;

    // Alice computes the adaptor and sends it to Bob
    let sigma_adapt = cb + r.key;

    // Bob verifies that adaptor is correct
    assert_eq!(&sigma_adapt * G, c * B + R);

    // Alice now publishes a valid signature
    let sigma = cb + r.key + t.key;
    assert_eq!(&sigma * G, &cb * G + R + T);

    // Bob can infer t from these signatures
    let t_bob = sigma - sigma_adapt;
    assert_eq!(&t_bob * G, t.public_key());
}

fn main() {
    test_adapter();
}
