//! FIPS 205 §4.2 Addressing — the 32-byte ADRS structure and its member
//! functions (Table 1, Figures 2-9).
//!
//! This is the *uncompressed* layout. §11.2 (SHA2 instantiation) defines a
//! 22-byte compressed form (Table 3) for implementations that want smaller
//! address material in the SHA-256/512 calls; that's specific to the SHA2
//! hash wiring, which isn't implemented here (see `dsa::slh_dsa` docs), so
//! only the Table 1 layout is needed.

pub const WOTS_HASH: u32 = 0;
pub const WOTS_PK: u32 = 1;
pub const TREE: u32 = 2;
pub const FORS_TREE: u32 = 3;
pub const FORS_ROOTS: u32 = 4;
pub const WOTS_PRF: u32 = 5;
pub const FORS_PRF: u32 = 6;

/// A 32-byte SLH-DSA address (FIPS 205 Figure 2).
///
/// Layout: layer address (4B) | tree address (12B) | type (4B) | three
/// more 4B words whose meaning depends on `type` (Figures 3-9) — key pair
/// address, then chain-address/tree-height, then hash-address/tree-index.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Adrs(pub [u8; 32]);

impl Adrs {
    pub fn zero() -> Self {
        Adrs([0u8; 32])
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn set_layer_address(&mut self, l: u32) {
        self.0[0..4].copy_from_slice(&l.to_be_bytes());
    }

    /// Tree address is 12 bytes (96 bits) in the spec; every parameter set
    /// in Table 2 needs at most 64 bits of it (h - h' <= 64 for
    /// SLH-DSA-{SHAKE,SHA2}-256f, the largest), so a `u64` input is
    /// sufficient and left-padded with zero bytes into the 12-byte field.
    pub fn set_tree_address(&mut self, t: u64) {
        self.0[4..8].fill(0);
        self.0[8..16].copy_from_slice(&t.to_be_bytes());
    }

    pub fn set_type_and_clear(&mut self, y: u32) {
        self.0[16..20].copy_from_slice(&y.to_be_bytes());
        self.0[20..32].fill(0);
    }

    pub fn set_key_pair_address(&mut self, i: u32) {
        self.0[20..24].copy_from_slice(&i.to_be_bytes());
    }

    pub fn get_key_pair_address(&self) -> u32 {
        u32::from_be_bytes(self.0[20..24].try_into().unwrap())
    }

    // These two setters share byte offset [24:28] — WOTS_HASH interprets it
    // as the chain address (Figure 3), TREE/FORS_TREE as tree height
    // (Figures 5, 6) — per Table 1, which gives both the same expanded
    // notation.
    pub fn set_chain_address(&mut self, i: u32) {
        self.0[24..28].copy_from_slice(&i.to_be_bytes());
    }
    pub fn set_tree_height(&mut self, i: u32) {
        self.0[24..28].copy_from_slice(&i.to_be_bytes());
    }

    // Same pattern at [28:32]: hash address (WOTS_HASH) vs. tree index
    // (TREE/FORS_TREE/FORS_ROOTS).
    pub fn set_hash_address(&mut self, i: u32) {
        self.0[28..32].copy_from_slice(&i.to_be_bytes());
    }
    pub fn set_tree_index(&mut self, i: u32) {
        self.0[28..32].copy_from_slice(&i.to_be_bytes());
    }
    pub fn get_tree_index(&self) -> u32 {
        u32::from_be_bytes(self.0[28..32].try_into().unwrap())
    }
}
