use decoypath::crypto::EphemeralKeyPair;
use x25519_dalek::PublicKey as X25519PublicKey;

fn main() {
    let keypair = EphemeralKeyPair::generate();
    let peer_pub = X25519PublicKey::from([0u8; 32]);
    let _dh1 = keypair.diffie_hellman(&peer_pub);
    let _dh2 = keypair.diffie_hellman(&peer_pub);
}
