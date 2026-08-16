//! FIPS 205 §4.2 Addressing — the 32-byte ADRS structure and its member
//! functions (Table 1, Figures 2-9).
//!
//! Every algorithm in `wots`/`xmss`/`ht`/`fors`/`core` builds and mutates
//! this *uncompressed* (Table 1) form throughout, for both the SHAKE and
//! SHA2 instantiations. `compress()` produces the 22-byte Table 3 form
//! on demand — that compression is only relevant inside the SHA2 hash
//! functions themselves (`sha2_suite`), not to any of the tree/signature
//! logic above them.

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

    /// Table 3: compressed address form (ADRSc), used only inside the SHA2
    /// hash instantiation (§11.2) — layer address and type shrink from 4
    /// bytes to 1 (their value always fits), tree address shrinks from 12
    /// bytes to 8 (this crate's `set_tree_address` never uses the top 4 of
    /// those 12 anyway, see that method's doc comment), and the last three
    /// 4-byte words are unchanged.
    ///
    /// ADRSc = ADRS\[3\] ∥ ADRS\[8:16\] ∥ ADRS\[19\] ∥ ADRS\[20:32\]
    pub fn compress(&self) -> [u8; 22] {
        let mut out = [0u8; 22];
        out[0] = self.0[3];
        out[1..9].copy_from_slice(&self.0[8..16]);
        out[9] = self.0[19];
        out[10..22].copy_from_slice(&self.0[20..32]);
        out
    }
}
