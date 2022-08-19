//! Support for multi-signature keys
use core::fmt;
use core::str::FromStr;

use bitcoin::secp256k1::{Secp256k1, VerifyOnly};
#[cfg(feature = "std")]
use secp256k1_zkp::MusigKeyAggCache;

use crate::expression::{FromTree, Tree};
use crate::prelude::*;
use crate::{expression, Error, ForEachKey, MiniscriptKey, ToPublicKey, TranslatePk, Translator};

#[derive(Clone, PartialEq, PartialOrd, Ord, Eq, Hash)]
/// Enum for representing musig keys in miniscript
pub enum KeyExpr<Pk: MiniscriptKey> {
    /// Single-key (e.g pk(a), here 'a' is a single key)
    SingleKey(Pk),

    /// Collection of keys in used for musig-signature
    MuSig(Vec<KeyExpr<Pk>>),
}

impl<Pk: MiniscriptKey + FromStr> FromTree for KeyExpr<Pk>
where
    <Pk as FromStr>::Err: ToString,
{
    fn from_tree(tree: &Tree) -> Result<KeyExpr<Pk>, Error> {
        if tree.name == "musig" {
            let key_expr_vec = tree
                .args
                .iter()
                .map(|subtree| KeyExpr::<Pk>::from_tree(subtree))
                .collect::<Result<Vec<KeyExpr<Pk>>, Error>>()?;
            Ok(KeyExpr::MuSig(key_expr_vec))
        } else {
            let single_key = expression::terminal(tree, Pk::from_str)?;
            Ok(KeyExpr::SingleKey(single_key))
        }
    }
}

impl<Pk: MiniscriptKey + FromStr> FromStr for KeyExpr<Pk>
where
    <Pk as FromStr>::Err: ToString,
{
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (key_tree, _) = Tree::from_slice(s)?;
        FromTree::from_tree(&key_tree)
    }
}

#[derive(Debug, Clone)]
/// Iterator for [`KeyExpr`]
pub struct KeyExprIter<'a, Pk: MiniscriptKey> {
    stack: Vec<&'a KeyExpr<Pk>>,
}

impl<'a, Pk> Iterator for KeyExprIter<'a, Pk>
where
    Pk: MiniscriptKey + 'a,
{
    type Item = &'a Pk;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.stack.is_empty() {
            let last = self.stack.pop().expect("Size checked above");
            match last {
                KeyExpr::MuSig(key_vec) => {
                    // push the elements in reverse order
                    key_vec.iter().rev().for_each(|key| self.stack.push(key));
                }
                KeyExpr::SingleKey(ref pk) => return Some(pk),
            }
        }
        None
    }
}

impl<Pk: MiniscriptKey> fmt::Debug for KeyExpr<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeyExpr::SingleKey(ref pk) => write!(f, "{:?}", pk),
            KeyExpr::MuSig(ref my_vec) => {
                write!(f, "musig(")?;
                let len = my_vec.len();
                for (index, k) in my_vec.iter().enumerate() {
                    if index == len - 1 {
                        write!(f, "{:?}", k)?;
                    } else {
                        write!(f, "{:?}", k)?;
                    }
                }
                f.write_str(")")
            }
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Display for KeyExpr<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KeyExpr::SingleKey(ref pk) => write!(f, "{}", pk),
            KeyExpr::MuSig(ref my_vec) => {
                write!(f, "musig(")?;
                let len = my_vec.len();
                for (index, k) in my_vec.iter().enumerate() {
                    if index == len - 1 {
                        write!(f, "{}", k)?;
                    } else {
                        write!(f, "{},", k)?;
                    }
                }
                f.write_str(")")
            }
        }
    }
}

impl<Pk: MiniscriptKey> KeyExpr<Pk> {
    /// Iterate over all keys
    pub fn iter(&self) -> KeyExprIter<Pk> {
        KeyExprIter { stack: vec![self] }
    }
}

impl<Pk: ToPublicKey> KeyExpr<Pk> {
    /// Returns an XOnlyPublicKey from a KeyExpr
    pub fn key_agg(&self) -> bitcoin::XOnlyPublicKey {
        match self {
            KeyExpr::<Pk>::SingleKey(pk) => pk.to_x_only_pubkey(),
            KeyExpr::<Pk>::MuSig(_keys) => {
                let secp = Secp256k1::verification_only();
                self.key_agg_helper(&secp)
            }
        }
    }

    #[cfg(feature = "std")]
    fn key_agg_helper(&self, secp: &Secp256k1<VerifyOnly>) -> bitcoin::XOnlyPublicKey {
        match self {
            KeyExpr::<Pk>::SingleKey(pk) => pk.to_x_only_pubkey(),
            KeyExpr::<Pk>::MuSig(keys) => {
                let xonly = keys
                    .iter()
                    .map(|key| key.key_agg_helper(secp))
                    .collect::<Vec<_>>();
                let key_agg_cache = MusigKeyAggCache::new(secp, &xonly);
                key_agg_cache.agg_pk()
            }
        }
    }

    #[cfg(not(feature = "std"))]
    fn key_agg_helper(&self, _secp: &Secp256k1<VerifyOnly>) -> bitcoin::XOnlyPublicKey {
        match self {
            KeyExpr::<Pk>::SingleKey(pk) => pk.to_x_only_pubkey(),
            KeyExpr::<Pk>::MuSig(_keys) => {
                unimplemented!("Musig not supported for no-std");
            }
        }
    }
}

impl<Pk: MiniscriptKey> ForEachKey<Pk> for KeyExpr<Pk> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, mut pred: F) -> bool
    where
        Pk: 'a,
        Pk::RawPkHash: 'a,
    {
        let keys_res = self.iter().all(|key| pred(key));
        keys_res
    }
}

impl<P, Q> TranslatePk<P, Q> for KeyExpr<P>
where
    P: MiniscriptKey,
    Q: MiniscriptKey,
{
    type Output = KeyExpr<Q>;
    fn translate_pk<T, E>(&self, t: &mut T) -> Result<Self::Output, E>
    where
        T: Translator<P, Q, E>,
    {
        match self {
            KeyExpr::<P>::SingleKey(pk) => Ok(KeyExpr::SingleKey(t.pk(pk)?)),
            KeyExpr::<P>::MuSig(vec) => {
                let mut new_vec: Vec<KeyExpr<Q>> = vec![];
                for x in vec {
                    new_vec.push(x.translate_pk(t)?)
                }
                Ok(KeyExpr::MuSig(new_vec))
            }
        }
    }
}

impl<Pk: MiniscriptKey> KeyExpr<Pk> {
    /// Returns the Pk if KeyExpr is SingleKey, otherwise None
    pub fn single_key(&self) -> Option<&Pk> {
        match self {
            KeyExpr::<Pk>::SingleKey(ref pk) => Some(pk),
            KeyExpr::<Pk>::MuSig(_) => None,
        }
    }

    /// Return vector of bytes, in case of musig, it is first aggregated
    /// and then converted to bytes
    pub fn to_vec(&self) -> Vec<u8>
    where
        Pk: ToPublicKey,
    {
        match self {
            KeyExpr::<Pk>::SingleKey(ref pk) => pk.to_public_key().to_bytes(),
            KeyExpr::<Pk>::MuSig(_) => {
                let agg_key = self.key_agg();
                agg_key.to_public_key().to_bytes()
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn test_one(musig_key: &str) {
        let pk = KeyExpr::<String>::from_str(musig_key).unwrap();
        println!("{}", pk);
        assert_eq!(musig_key, format!("{}", pk))
    }

    #[test]
    fn test_from_str_and_fmt() {
        test_one("musig(A,B,musig(C,musig(D,E)))");
        test_one("musig(A)");
        test_one("A");
        test_one("musig(,,)");
    }

    #[test]
    fn test_iterator() {
        let pk = KeyExpr::<String>::from_str("musig(A,B,musig(C,musig(D,E)))").unwrap();
        let mut my_iter = pk.iter();
        assert_eq!(my_iter.next(), Some(&String::from("A")));
        assert_eq!(my_iter.next(), Some(&String::from("B")));
        assert_eq!(my_iter.next(), Some(&String::from("C")));
        assert_eq!(my_iter.next(), Some(&String::from("D")));
        assert_eq!(my_iter.next(), Some(&String::from("E")));
        assert_eq!(my_iter.next(), None);
    }

    fn test_helper(musig_key: &str, comma_separated_key: &str) {
        let pk = KeyExpr::<String>::from_str(musig_key).unwrap();
        let var: Vec<&str> = comma_separated_key.split(",").collect();
        let key_names: Vec<&String> = pk.iter().collect();
        for (key1, key2) in key_names.iter().zip(var.iter()) {
            assert_eq!(key1, key2);
        }
    }

    #[test]
    fn test_iterator_multi() {
        test_helper("musig(A)", "A");
        test_helper("A", "A");
        test_helper("musig(,,)", "");
        test_helper("musig(musig(A,B),musig(musig(C)))", "A,B,C");
    }
}
