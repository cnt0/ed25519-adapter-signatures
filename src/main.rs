use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE as G, edwards::EdwardsPoint, scalar::Scalar,
};
use ed25519_dalek::{PublicKey, Verifier};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};

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
        hasher.update(pk.compress().as_bytes());
        hasher.update(ephemeral_pk.compress().as_bytes());
        hasher.update(&message);
        Scalar::from_hash(hasher)
    }
    fn public_key(&self) -> EdwardsPoint {
        &self.key * &G
    }
}

fn test_adapter() {
    let mut csprng = OsRng;
    let msg = "hello";

    // Alice chooses r, t and sends R, T to Bob
    let r = ExpandedSecretKey::generate(&mut csprng);
    let t = ExpandedSecretKey::generate(&mut csprng);
    let (R, T) = (r.public_key(), t.public_key());
    assert!(ExpandedSecretKey::validate(&(&(r.key + t.key) * &G)));

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
    let msg_alice = "hello Bob";
    let msg_bob = "hello Alice";

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

    println!("original protocol: OK");
}

fn test_modified_protocol() {
    let mut csprng = OsRng;

    // messages to be signed
    let msg_alice = "send 10 BTC from Bob to Alice";
    let msg_bob = "send 20 Ether from Alice to Bob";

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

    // Alice chooses t, ra and sends T, Ra to Bob
    let (t, ra) = (
        ExpandedSecretKey::generate(&mut csprng),
        ExpandedSecretKey::generate(&mut csprng),
    );
    let (T, Ra) = (t.public_key(), ra.public_key());

    // Bob chooses rb and sends Rb to Alice
    let rb = ExpandedSecretKey::generate(&mut csprng);
    let Rb = rb.public_key();

    // Alice also generates challenges and sends (c1 * a1), (c2 * a2) to Bob
    let c1 = ExpandedSecretKey::challenge(&(A1 + B1), &(Rb + T), msg_alice.as_bytes());
    let c2 = ExpandedSecretKey::challenge(&(A2 + B2), &(Ra + T), msg_bob.as_bytes());
    let c1a1 = c1 * a1.key;
    let c2a2 = c2 * a2.key;

    // Bob adds his part to generate c1*(a1 + b1), c2*(a2 + b2)
    // He can compute c1, c2 on his own
    let c1a1b1 = c1a1 + c1 * b1.key;
    // Bob sends c2*(a2 + b2) to Alice but keeps c1*(a1 + b1) for now
    let c2a2b2 = c2a2 + c2 * b2.key;

    // Alice uses it to generate adaptor signature for msg_bob and sends it to Bob
    let sigma_adapt_bob = ra.key + c2a2b2;

    // Bob verifies this signature
    assert_eq!(&sigma_adapt_bob * &G, c2 * (A2 + B2) + Ra);

    // at this stage, Bob doesn't know t. However, successful verification means that,
    // when Alice will publish her full signature, Bob will be able to infer that value,
    // and, in turn, publish his signature

    // verification is OK so Bob is safe to share his adaptor with Alice
    let sigma_adapt_alice = rb.key + c1a1b1;

    // Alice is now able to publish her full signature
    let sigma_alice: Scalar = sigma_adapt_alice + t.key;
    assert_eq!(&sigma_alice * &G, &c1 * (A1 + B1) + Rb + T);

    // let's make sure that this is correct ed25519 signature
    // by independently verifying it with ed25519_dalek library
    let verify = |e_pk: &EdwardsPoint, pk: &EdwardsPoint, msg, sigma: &Scalar| {
        let mut sa_bytes = [0u8; 64];
        sa_bytes[..32].copy_from_slice((e_pk).compress().as_bytes());
        sa_bytes[32..].copy_from_slice(sigma.as_bytes());
        let dalek_pk = PublicKey::from_bytes(pk.compress().as_bytes())
            .ok()
            .unwrap();
        dalek_pk.verify(msg, &sa_bytes.into()).is_ok()
    };
    assert!(verify(
        &(Rb + T),
        &(A1 + B1),
        msg_alice.as_bytes(),
        &sigma_alice
    ));

    // Bob can now infer `t` and build his signature
    let t_bob = sigma_alice - sigma_adapt_alice;
    let sigma_bob = sigma_adapt_bob + t_bob;
    assert_eq!(&sigma_bob * &G, &c2 * (A2 + B2) + Ra + T);

    // this is correct ed25519 signature as well
    assert!(verify(
        &(Ra + T),
        &(A2 + B2),
        msg_bob.as_bytes(),
        &sigma_bob
    ));

    println!("modified protocol: OK");
}

fn main() {
    test_adapter();
    test_full_protocol();
    test_modified_protocol();
}
