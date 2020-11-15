use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE as G, edwards::EdwardsPoint, scalar::Scalar,
};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
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
    fn challenge(ephemeral_pk: &EdwardsPoint, pk: &EdwardsPoint, message: &[u8]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(ephemeral_pk.compress().as_bytes());
        hasher.update(pk.compress().as_bytes());
        hasher.update(&message);
        Scalar::from_hash(hasher)
    }
    fn public_key(&self) -> EdwardsPoint {
        &self.key * &G
    }
    fn sign(&self, message: &[u8]) -> Signature {
        let mut hasher = Sha512::new();
        hasher.update(self.nonce);
        hasher.update(&message);
        let r = Scalar::from_hash(hasher);
        let R = &r * &G;

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
        &self.s * &G - &Scalar::from_hash(hasher) * pk == self.R
    }
}

fn test_adapter() {
    let mut csprng = OsRng;
    let msg = "hello";

    // Alice chooses r, t and sends R, T to Bob
    let r = ExpandedSecretKey::generate(&mut csprng);
    let t = ExpandedSecretKey::generate(&mut csprng);
    let (R, T) = (r.public_key(), t.public_key());
    assert!(ExpandedSecretKey::validate(&(&(&r.key + &t.key) * &G)));

    // Bob generates challenge and sends c*b to Alice
    let b = ExpandedSecretKey::generate(&mut csprng);
    let B = b.public_key();
    let c = ExpandedSecretKey::challenge(&B, &(R + T), msg.as_bytes());
    let cb = c * &b.key;

    // Alice computes the adaptor and sends it to Bob
    let sigma_adapt = cb + r.key;

    // Bob verifies that adaptor is correct
    assert_eq!(&sigma_adapt * &G, c * B + R);

    // Alice now publishes a valid signature
    let sigma = cb + r.key + t.key;
    assert_eq!(&sigma * &G, &cb * &G + R + T);

    // Bob can infer t from these signatures
    let t_bob = sigma - sigma_adapt;
    assert_eq!(&t_bob * &G, t.public_key());
}

fn test_full_protocol() {
    let mut csprng = OsRng;

    // messages to be signed
    let msg_alice = "hello bob";
    let msg_bob = "hello alice";

    // Alice and Bob generate 2 ephemeral verification keys each
    // Alice knows a1, a2
    let (a1, a2) = (
        ExpandedSecretKey::generate(&mut csprng),
        ExpandedSecretKey::generate(&mut csprng),
    );
    // Bob knows b1, b2
    let (b1, b2) = (
        ExpandedSecretKey::generate(&mut csprng),
        ExpandedSecretKey::generate(&mut csprng),
    );

    // msg_alice will be signed with (a1 + b1)
    // msg_bob will be signed with (a2 + b2)
    let (A1, A2) = (a1.public_key(), a2.public_key());
    let (B1, B2) = (b1.public_key(), b2.public_key());

    // Alice chooses t, r1, r2 and sends T, R1, R2 to Bob
    let (t, r1, r2) = (
        ExpandedSecretKey::generate(&mut csprng),
        ExpandedSecretKey::generate(&mut csprng),
        ExpandedSecretKey::generate(&mut csprng),
    );
    let (T, R1, R2) = (t.public_key(), r1.public_key(), r2.public_key());

    // Alice also generates challenges and sends (c1 * a1), (c2 * a2) to Bob
    let c1 = ExpandedSecretKey::challenge(&(A1 + B1), &(R1 + T), msg_alice.as_bytes());
    let c2 = ExpandedSecretKey::challenge(&(A2 + B2), &(R2 + T), msg_bob.as_bytes());
    let c1a1 = c1 * a1.key;
    let c2a2 = c2 * a2.key;

    // Bob adds his part to generate c1*(a1 + b1), c2*(a2 + b2)
    // Bob can compute c1, c2 on his own
    let c1a1b1 = c1a1 + c1 * b1.key;
    let c2a2b2 = c2a2 + c2 * b2.key;

    // Alice uses these to generate adaptor signatures and sends them to Bob
    let sigma_adapt1 = r1.key + c1a1b1;
    let sigma_adapt2 = r2.key + c2a2b2;

    // Bob verifies adaptor signatures
    assert_eq!(&sigma_adapt1 * &G, c1 * (A1 + B1) + R1);
    assert_eq!(&sigma_adapt2 * &G, c2 * (A2 + B2) + R2);

    // Alice publishes signature for her message
    let sigma1 = sigma_adapt1 + t.key;
    // sigma1 is correct ed25519 signature
    assert_eq!(&sigma1 * &G, &c1 * (A1 + B1) + R1 + T);

    // this reveals t for Bob so he can publish the signature for his message
    let t_bob = sigma1 - sigma_adapt1;
    let sigma2 = sigma_adapt2 + t_bob;
    // sigma2 is correct as well
    assert_eq!(&sigma2 * &G, &c2 * (A2 + B2) + R2 + T);

    //TODO: use verification functions from ed25519_dalek

    println!("ok OK");
}

fn main() {
    test_adapter();
    test_full_protocol();
}
