// SPDX-License-Identifier: CC0-1.0

use core::cmp::{self, max};
use core::str::FromStr;
use core::{fmt, hash};

use bitcoin::taproot::{
    LeafVersion, TaprootBuilder, TaprootSpendInfo, TAPROOT_CONTROL_BASE_SIZE,
    TAPROOT_CONTROL_MAX_NODE_COUNT, TAPROOT_CONTROL_NODE_SIZE,
};
use bitcoin::{opcodes, secp256k1, Address, Network, ScriptBuf};
use sync::Arc;

use super::checksum::{self, verify_checksum};
use crate::expression::{self, FromTree};
use crate::miniscript::Miniscript;
use crate::policy::semantic::Policy;
use crate::policy::Liftable;
use crate::prelude::*;
use crate::util::{varint_len, witness_size};
use crate::{
    errstr, Error, ForEachKey, MiniscriptKey, Satisfier, Tap, ToPublicKey, TranslatePk, Translator,
};

/// A Taproot Tree representation.
// Hidden leaves are not yet supported in descriptor spec. Conceptually, it should
// be simple to integrate those here, but it is best to wait on core for the exact syntax.
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum TapTree<Pk: MiniscriptKey> {
    /// A taproot tree structure
    Tree(Arc<TapTree<Pk>>, Arc<TapTree<Pk>>),
    /// A taproot leaf denoting a spending condition
    // A new leaf version would require a new Context, therefore there is no point
    // in adding a LeafVersion with Leaf type here. All Miniscripts right now
    // are of Leafversion::default
    Leaf(Arc<Miniscript<Pk, Tap>>),
}

/// A taproot descriptor
pub struct Tr<Pk: MiniscriptKey> {
    /// A taproot internal key
    internal_key: Pk,
    /// Optional Taproot Tree with spending conditions
    tree: Option<TapTree<Pk>>,
    /// Optional spending information associated with the descriptor
    /// This will be [`None`] when the descriptor is not derived.
    /// This information will be cached automatically when it is required
    //
    // The inner `Arc` here is because Rust does not allow us to return a reference
    // to the contents of the `Option` from inside a `MutexGuard`. There is no outer
    // `Arc` because when this structure is cloned, we create a whole new mutex.
    spend_info: Mutex<Option<Arc<TaprootSpendInfo>>>,
}

impl<Pk: MiniscriptKey> Clone for Tr<Pk> {
    fn clone(&self) -> Self {
        // When cloning, construct a new Mutex so that distinct clones don't
        // cause blocking between each other. We clone only the internal `Arc`,
        // so the clone is always cheap (in both time and space)
        Self {
            internal_key: self.internal_key.clone(),
            tree: self.tree.clone(),
            spend_info: Mutex::new(
                self.spend_info
                    .lock()
                    .expect("Lock poisoned")
                    .as_ref()
                    .map(Arc::clone),
            ),
        }
    }
}

impl<Pk: MiniscriptKey> PartialEq for Tr<Pk> {
    fn eq(&self, other: &Self) -> bool {
        self.internal_key == other.internal_key && self.tree == other.tree
    }
}

impl<Pk: MiniscriptKey> Eq for Tr<Pk> {}

impl<Pk: MiniscriptKey> PartialOrd for Tr<Pk> {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        match self.internal_key.partial_cmp(&other.internal_key) {
            Some(cmp::Ordering::Equal) => {}
            ord => return ord,
        }
        self.tree.partial_cmp(&other.tree)
    }
}

impl<Pk: MiniscriptKey> Ord for Tr<Pk> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.internal_key.cmp(&other.internal_key) {
            cmp::Ordering::Equal => {}
            ord => return ord,
        }
        self.tree.cmp(&other.tree)
    }
}

impl<Pk: MiniscriptKey> hash::Hash for Tr<Pk> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.internal_key.hash(state);
        self.tree.hash(state);
    }
}

impl<Pk: MiniscriptKey> TapTree<Pk> {
    // Helper function to compute height
    // TODO: Instead of computing this every time we add a new leaf, we should
    // add height as a separate field in taptree
    fn taptree_height(&self) -> usize {
        match *self {
            TapTree::Tree(ref left_tree, ref right_tree) => {
                1 + max(left_tree.taptree_height(), right_tree.taptree_height())
            }
            TapTree::Leaf(..) => 0,
        }
    }

    /// Iterates over all miniscripts in DFS walk order compatible with the
    /// PSBT requirements (BIP 371).
    pub fn iter(&self) -> TapTreeIter<Pk> {
        TapTreeIter {
            stack: vec![(0, self)],
        }
    }

    // Helper function to translate keys
    fn translate_helper<T, Q, Error>(&self, t: &mut T) -> Result<TapTree<Q>, Error>
    where
        T: Translator<Pk, Q, Error>,
        Q: MiniscriptKey,
    {
        let frag = match self {
            TapTree::Tree(l, r) => TapTree::Tree(
                Arc::new(l.translate_helper(t)?),
                Arc::new(r.translate_helper(t)?),
            ),
            TapTree::Leaf(ms) => TapTree::Leaf(Arc::new(ms.translate_pk(t)?)),
        };
        Ok(frag)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for TapTree<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TapTree::Tree(ref left, ref right) => write!(f, "{{{},{}}}", *left, *right),
            TapTree::Leaf(ref script) => write!(f, "{}", *script),
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for TapTree<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TapTree::Tree(ref left, ref right) => write!(f, "{{{:?},{:?}}}", *left, *right),
            TapTree::Leaf(ref script) => write!(f, "{:?}", *script),
        }
    }
}

impl<Pk: MiniscriptKey> Tr<Pk> {
    /// Create a new [`Tr`] descriptor from internal key and [`TapTree`]
    pub fn new(internal_key: Pk, tree: Option<TapTree<Pk>>) -> Result<Self, Error> {
        let nodes = tree.as_ref().map(|t| t.taptree_height()).unwrap_or(0);

        if nodes <= TAPROOT_CONTROL_MAX_NODE_COUNT {
            Ok(Self {
                internal_key,
                tree,
                spend_info: Mutex::new(None),
            })
        } else {
            Err(Error::MaxRecursiveDepthExceeded)
        }
    }

    /// Obtain the internal key of [`Tr`] descriptor
    pub fn internal_key(&self) -> &Pk {
        &self.internal_key
    }

    /// Obtain the [`TapTree`] of the [`Tr`] descriptor
    pub fn taptree(&self) -> &Option<TapTree<Pk>> {
        &self.tree
    }

    /// Iterate over all scripts in merkle tree. If there is no script path, the iterator
    /// yields [`None`]
    pub fn iter_scripts(&self) -> TapTreeIter<Pk> {
        match self.tree {
            Some(ref t) => t.iter(),
            None => TapTreeIter { stack: vec![] },
        }
    }

    /// Compute the [`TaprootSpendInfo`] associated with this descriptor if spend data is `None`.
    ///
    /// If spend data is already computed (i.e it is not `None`), this does not recompute it.
    ///
    /// [`TaprootSpendInfo`] is only required for spending via the script paths.
    pub fn spend_info(&self) -> Arc<TaprootSpendInfo>
    where
        Pk: ToPublicKey,
    {
        // If the value is already cache, read it
        // read only panics if the lock is poisoned (meaning other thread having a lock panicked)
        let read_lock = self.spend_info.lock().expect("Lock poisoned");
        if let Some(ref spend_info) = *read_lock {
            return Arc::clone(spend_info);
        }
        drop(read_lock);

        // Get a new secp context
        // This would be cheap operation after static context support from upstream
        let secp = secp256k1::Secp256k1::verification_only();
        // Key spend path with no merkle root
        let data = if self.tree.is_none() {
            TaprootSpendInfo::new_key_spend(&secp, self.internal_key.to_x_only_pubkey(), None)
        } else {
            let mut builder = TaprootBuilder::new();
            for (depth, ms) in self.iter_scripts() {
                let script = ms.encode();
                builder = builder
                    .add_leaf(depth, script)
                    .expect("Computing spend data on a valid Tree should always succeed");
            }
            // Assert builder cannot error here because we have a well formed descriptor
            match builder.finalize(&secp, self.internal_key.to_x_only_pubkey()) {
                Ok(data) => data,
                Err(_) => unreachable!("We know the builder can be finalized"),
            }
        };
        let spend_info = Arc::new(data);
        *self.spend_info.lock().expect("Lock poisoned") = Some(Arc::clone(&spend_info));
        spend_info
    }

    /// Checks whether the descriptor is safe.
    pub fn sanity_check(&self) -> Result<(), Error> {
        for (_depth, ms) in self.iter_scripts() {
            ms.sanity_check()?;
        }
        Ok(())
    }

    /// Computes an upper bound on the difference between a non-satisfied
    /// `TxIn`'s `segwit_weight` and a satisfied `TxIn`'s `segwit_weight`
    ///
    /// Assumes all Schnorr signatures are 66 bytes, including push opcode and
    /// sighash suffix.
    ///
    /// # Errors
    /// When the descriptor is impossible to safisfy (ex: sh(OP_FALSE)).
    pub fn max_weight_to_satisfy(&self) -> Result<usize, Error> {
        let tree = match self.taptree() {
            None => {
                // key spend path
                // item: varint(sig+sigHash) + <sig(64)+sigHash(1)>
                let item_sig_size = 1 + 65;
                // 1 stack item
                let stack_varint_diff = varint_len(1) - varint_len(0);

                return Ok(stack_varint_diff + item_sig_size);
            }
            // script path spend..
            Some(tree) => tree,
        };

        tree.iter()
            .filter_map(|(depth, ms)| {
                let script_size = ms.script_size();
                let max_sat_elems = ms.max_satisfaction_witness_elements().ok()?;
                let max_sat_size = ms.max_satisfaction_size().ok()?;
                let control_block_size = control_block_len(depth);

                // stack varint difference (+1 for ctrl block, witness script already included)
                let stack_varint_diff = varint_len(max_sat_elems + 1) - varint_len(0);

                Some(
                    stack_varint_diff +
                    // size of elements to satisfy script
                    max_sat_size +
                    // second to last element: script
                    varint_len(script_size) +
                    script_size +
                    // last element: control block
                    varint_len(control_block_size) +
                    control_block_size,
                )
            })
            .max()
            .ok_or(Error::ImpossibleSatisfaction)
    }

    /// Computes an upper bound on the weight of a satisfying witness to the
    /// transaction.
    ///
    /// Assumes all ec-signatures are 73 bytes, including push opcode and
    /// sighash suffix. Includes the weight of the VarInts encoding the
    /// scriptSig and witness stack length.
    ///
    /// # Errors
    /// When the descriptor is impossible to safisfy (ex: sh(OP_FALSE)).
    #[deprecated(note = "use max_weight_to_satisfy instead")]
    pub fn max_satisfaction_weight(&self) -> Result<usize, Error> {
        let tree = match self.taptree() {
            // key spend path:
            // scriptSigLen(4) + stackLen(1) + stack[Sig]Len(1) + stack[Sig](65)
            None => return Ok(4 + 1 + 1 + 65),
            // script path spend..
            Some(tree) => tree,
        };

        tree.iter()
            .filter_map(|(depth, ms)| {
                let script_size = ms.script_size();
                let max_sat_elems = ms.max_satisfaction_witness_elements().ok()?;
                let max_sat_size = ms.max_satisfaction_size().ok()?;
                let control_block_size = control_block_len(depth);
                Some(
                    // scriptSig len byte
                    4 +
                    // witness field stack len (+2 for control block & script)
                    varint_len(max_sat_elems + 2) +
                    // size of elements to satisfy script
                    max_sat_size +
                    // second to last element: script
                    varint_len(script_size) +
                    script_size +
                    // last element: control block
                    varint_len(control_block_size) +
                    control_block_size,
                )
            })
            .max()
            .ok_or(Error::ImpossibleSatisfaction)
    }
}

impl<Pk: MiniscriptKey + ToPublicKey> Tr<Pk> {
    /// Obtains the corresponding script pubkey for this descriptor.
    pub fn script_pubkey(&self) -> ScriptBuf {
        let output_key = self.spend_info().output_key();
        let builder = bitcoin::blockdata::script::Builder::new();
        builder
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .push_slice(&output_key.serialize())
            .into_script()
    }

    /// Obtains the corresponding address for this descriptor.
    pub fn address(&self, network: Network) -> Address {
        let spend_info = self.spend_info();
        Address::p2tr_tweaked(spend_info.output_key(), network)
    }

    /// Returns satisfying non-malleable witness and scriptSig with minimum
    /// weight to spend an output controlled by the given descriptor if it is
    /// possible to construct one using the `satisfier`.
    pub fn get_satisfaction<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, ScriptBuf), Error>
    where
        S: Satisfier<Pk>,
    {
        best_tap_spend(self, satisfier, false /* allow_mall */)
    }

    /// Returns satisfying, possibly malleable, witness and scriptSig with
    /// minimum weight to spend an output controlled by the given descriptor if
    /// it is possible to construct one using the `satisfier`.
    pub fn get_satisfaction_mall<S>(&self, satisfier: S) -> Result<(Vec<Vec<u8>>, ScriptBuf), Error>
    where
        S: Satisfier<Pk>,
    {
        best_tap_spend(self, satisfier, true /* allow_mall */)
    }
}

/// Iterator for Taproot structures
/// Yields a pair of (depth, miniscript) in a depth first walk
/// For example, this tree:
///                                     - N0 -
///                                    /     \\
///                                   N1      N2
///                                  /  \    /  \\
///                                 A    B  C   N3
///                                            /  \\
///                                           D    E
/// would yield (2, A), (2, B), (2,C), (3, D), (3, E).
///
#[derive(Debug, Clone)]
pub struct TapTreeIter<'a, Pk: MiniscriptKey> {
    stack: Vec<(u8, &'a TapTree<Pk>)>,
}

impl<'a, Pk> Iterator for TapTreeIter<'a, Pk>
where
    Pk: MiniscriptKey + 'a,
{
    type Item = (u8, &'a Miniscript<Pk, Tap>);

    fn next(&mut self) -> Option<Self::Item> {
        while !self.stack.is_empty() {
            let (depth, last) = self.stack.pop().expect("Size checked above");
            match *last {
                TapTree::Tree(ref l, ref r) => {
                    self.stack.push((depth + 1, r));
                    self.stack.push((depth + 1, l));
                }
                TapTree::Leaf(ref ms) => return Some((depth, ms)),
            }
        }
        None
    }
}

#[rustfmt::skip]
impl_block_str!(
    Tr<Pk>,
    // Helper function to parse taproot script path
    fn parse_tr_script_spend(tree: &expression::Tree,) -> Result<TapTree<Pk>, Error> {
        match tree {
            expression::Tree { name, args } if !name.is_empty() && args.is_empty() => {
                let script = Miniscript::<Pk, Tap>::from_str(name)?;
                Ok(TapTree::Leaf(Arc::new(script)))
            }
            expression::Tree { name, args } if name.is_empty() && args.len() == 2 => {
                let left = Self::parse_tr_script_spend(&args[0])?;
                let right = Self::parse_tr_script_spend(&args[1])?;
                Ok(TapTree::Tree(Arc::new(left), Arc::new(right)))
            }
            _ => Err(Error::Unexpected(
                "unknown format for script spending paths while parsing taproot descriptor"
                    .to_string(),
            )),
        }
    }
);

impl_from_tree!(
    Tr<Pk>,
    fn from_tree(top: &expression::Tree) -> Result<Self, Error> {
        if top.name == "tr" {
            match top.args.len() {
                1 => {
                    let key = &top.args[0];
                    if !key.args.is_empty() {
                        return Err(Error::Unexpected(format!(
                            "#{} script associated with `key-path` while parsing taproot descriptor",
                            key.args.len()
                        )));
                    }
                    Tr::new(expression::terminal(key, Pk::from_str)?, None)
                }
                2 => {
                    let key = &top.args[0];
                    if !key.args.is_empty() {
                        return Err(Error::Unexpected(format!(
                            "#{} script associated with `key-path` while parsing taproot descriptor",
                            key.args.len()
                        )));
                    }
                    let tree = &top.args[1];
                    let ret = Self::parse_tr_script_spend(tree)?;
                    Tr::new(expression::terminal(key, Pk::from_str)?, Some(ret))
                }
                _ => Err(Error::Unexpected(format!(
                    "{}[#{} args] while parsing taproot descriptor",
                    top.name,
                    top.args.len()
                ))),
            }
        } else {
            Err(Error::Unexpected(format!(
                "{}[#{} args] while parsing taproot descriptor",
                top.name,
                top.args.len()
            )))
        }
    }
);

impl_from_str!(
    Tr<Pk>,
    type Err = Error;,
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let desc_str = verify_checksum(s)?;
        let top = parse_tr_tree(desc_str)?;
        Self::from_tree(&top)
    }
);

impl<Pk: MiniscriptKey> fmt::Debug for Tr<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.tree {
            Some(ref s) => write!(f, "tr({:?},{:?})", self.internal_key, s),
            None => write!(f, "tr({:?})", self.internal_key),
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Tr<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use fmt::Write;
        let mut wrapped_f = checksum::Formatter::new(f);
        let key = &self.internal_key;
        match self.tree {
            Some(ref s) => write!(wrapped_f, "tr({},{})", key, s)?,
            None => write!(wrapped_f, "tr({})", key)?,
        }
        wrapped_f.write_checksum_if_not_alt()
    }
}

// Helper function to parse string into miniscript tree form
fn parse_tr_tree(s: &str) -> Result<expression::Tree, Error> {
    for ch in s.bytes() {
        if !ch.is_ascii() {
            return Err(Error::Unprintable(ch));
        }
    }

    if s.len() > 3 && &s[..3] == "tr(" && s.as_bytes()[s.len() - 1] == b')' {
        let rest = &s[3..s.len() - 1];
        if !rest.contains(',') {
            let internal_key = expression::Tree {
                name: rest,
                args: vec![],
            };
            return Ok(expression::Tree {
                name: "tr",
                args: vec![internal_key],
            });
        }
        // use str::split_once() method to refactor this when compiler version bumps up
        let (key, script) = split_once(rest, ',')
            .ok_or_else(|| Error::BadDescriptor("invalid taproot descriptor".to_string()))?;

        let internal_key = expression::Tree {
            name: key,
            args: vec![],
        };
        if script.is_empty() {
            return Ok(expression::Tree {
                name: "tr",
                args: vec![internal_key],
            });
        }
        let (tree, rest) = expression::Tree::from_slice_delim(script, 1, '{')?;
        if rest.is_empty() {
            Ok(expression::Tree {
                name: "tr",
                args: vec![internal_key, tree],
            })
        } else {
            Err(errstr(rest))
        }
    } else {
        Err(Error::Unexpected("invalid taproot descriptor".to_string()))
    }
}

fn split_once(inp: &str, delim: char) -> Option<(&str, &str)> {
    if inp.is_empty() {
        None
    } else {
        let mut found = inp.len();
        for (idx, ch) in inp.chars().enumerate() {
            if ch == delim {
                found = idx;
                break;
            }
        }
        // No comma or trailing comma found
        if found >= inp.len() - 1 {
            Some((inp, ""))
        } else {
            Some((&inp[..found], &inp[found + 1..]))
        }
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for TapTree<Pk> {
    fn lift(&self) -> Result<Policy<Pk>, Error> {
        fn lift_helper<Pk: MiniscriptKey>(s: &TapTree<Pk>) -> Result<Policy<Pk>, Error> {
            match s {
                TapTree::Tree(ref l, ref r) => {
                    Ok(Policy::Threshold(1, vec![lift_helper(l)?, lift_helper(r)?]))
                }
                TapTree::Leaf(ref leaf) => leaf.lift(),
            }
        }

        let pol = lift_helper(self)?;
        Ok(pol.normalized())
    }
}

impl<Pk: MiniscriptKey> Liftable<Pk> for Tr<Pk> {
    fn lift(&self) -> Result<Policy<Pk>, Error> {
        match &self.tree {
            Some(root) => Ok(Policy::Threshold(
                1,
                vec![Policy::Key(self.internal_key.clone()), root.lift()?],
            )),
            None => Ok(Policy::Key(self.internal_key.clone())),
        }
    }
}

impl<Pk: MiniscriptKey> ForEachKey<Pk> for Tr<Pk> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, mut pred: F) -> bool
    where
        Pk: 'a,
    {
        let script_keys_res = self
            .iter_scripts()
            .all(|(_d, ms)| ms.for_each_key(&mut pred));
        script_keys_res && pred(&self.internal_key)
    }
}

impl<P, Q> TranslatePk<P, Q> for Tr<P>
where
    P: MiniscriptKey,
    Q: MiniscriptKey,
{
    type Output = Tr<Q>;

    fn translate_pk<T, E>(&self, translate: &mut T) -> Result<Self::Output, E>
    where
        T: Translator<P, Q, E>,
    {
        let translate_desc = Tr {
            internal_key: translate.pk(&self.internal_key)?,
            tree: match &self.tree {
                Some(tree) => Some(tree.translate_helper(translate)?),
                None => None,
            },
            spend_info: Mutex::new(None),
        };
        Ok(translate_desc)
    }
}

// Helper function to compute the len of control block at a given depth
fn control_block_len(depth: u8) -> usize {
    TAPROOT_CONTROL_BASE_SIZE + (depth as usize) * TAPROOT_CONTROL_NODE_SIZE
}

// Helper function to get a script spend satisfaction
// try script spend
fn best_tap_spend<Pk, S>(
    desc: &Tr<Pk>,
    satisfier: S,
    allow_mall: bool,
) -> Result<(Vec<Vec<u8>>, ScriptBuf), Error>
where
    Pk: ToPublicKey,
    S: Satisfier<Pk>,
{
    let spend_info = desc.spend_info();
    // First try the key spend path
    if let Some(sig) = satisfier.lookup_tap_key_spend_sig() {
        Ok((vec![sig.to_vec()], ScriptBuf::new()))
    } else {
        // Since we have the complete descriptor we can ignore the satisfier. We don't use the control block
        // map (lookup_control_block) from the satisfier here.
        let (mut min_wit, mut min_wit_len) = (None, None);
        for (depth, ms) in desc.iter_scripts() {
            let mut wit = if allow_mall {
                match ms.satisfy_malleable(&satisfier) {
                    Ok(wit) => wit,
                    Err(..) => continue, // No witness for this script in tr descriptor, look for next one
                }
            } else {
                match ms.satisfy(&satisfier) {
                    Ok(wit) => wit,
                    Err(..) => continue, // No witness for this script in tr descriptor, look for next one
                }
            };
            // Compute the final witness size
            // Control block len + script len + witnesssize + varint(wit.len + 2)
            // The extra +2 elements are control block and script itself
            let wit_size = witness_size(&wit)
                + control_block_len(depth)
                + ms.script_size()
                + varint_len(ms.script_size());
            if min_wit_len.is_some() && Some(wit_size) > min_wit_len {
                continue;
            } else {
                let leaf_script = (ms.encode(), LeafVersion::TapScript);
                let control_block = spend_info
                    .control_block(&leaf_script)
                    .expect("Control block must exist in script map for every known leaf");
                wit.push(leaf_script.0.into_bytes()); // Push the leaf script
                                                      // There can be multiple control blocks for a (script, ver) pair
                                                      // Find the smallest one amongst those
                wit.push(control_block.serialize());
                // Finally, save the minimum
                min_wit = Some(wit);
                min_wit_len = Some(wit_size);
            }
        }
        match min_wit {
            Some(wit) => Ok((wit, ScriptBuf::new())),
            None => Err(Error::CouldNotSatisfy), // Could not satisfy all miniscripts inside Tr
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ForEachKey;

    #[test]
    fn test_for_each() {
        let desc = "tr(acc0, {
            multi_a(3, acc10, acc11, acc12), {
              and_v(
                v:multi_a(2, acc10, acc11, acc12),
                after(10)
              ),
              and_v(
                v:multi_a(1, acc10, acc11, ac12),
                after(100)
              )
            }
         })";
        let desc = desc.replace(&[' ', '\n'][..], "");
        let tr = Tr::<String>::from_str(&desc).unwrap();
        // Note the last ac12 only has ac and fails the predicate
        assert!(!tr.for_each_key(|k| k.starts_with("acc")));
    }
}
