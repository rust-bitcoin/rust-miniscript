// Tapscript

use super::checksum::{desc_checksum, verify_checksum};
use bitcoin::hashes::_export::_core::fmt::Formatter;
use errstr;
use expression::{self, FromTree, Tree};
use miniscript::{limits::TAPROOT_MAX_NODE_COUNT, Miniscript};
use std::cmp::max;
use std::sync::Arc;
use std::{fmt, str::FromStr};
use Segwitv0;
use {Error, MiniscriptKey};

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum TapTree<Pk: MiniscriptKey> {
    Tree(Arc<TapTree<Pk>>, Arc<TapTree<Pk>>),
    Leaf(Arc<Miniscript<Pk, Segwitv0>>),
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Tr<Pk: MiniscriptKey> {
    internal_key: Pk,
    tree: Option<TapTree<Pk>>,
}

impl<Pk: MiniscriptKey> TapTree<Pk> {
    fn taptree_height(&self) -> usize {
        match *self {
            TapTree::Tree(ref left_tree, ref right_tree) => {
                1 + max(left_tree.taptree_height(), right_tree.taptree_height())
            }
            TapTree::Leaf(_) => 1,
        }
    }

    pub fn to_string_no_checksum(&self) -> String {
        match self {
            TapTree::Tree(ref left, ref right) => {
                format!("{{{},{}}}", *left, *right)
            }
            TapTree::Leaf(ref script) => format!("{}", *script),
        }
    }
}

impl<Pk: MiniscriptKey> fmt::Display for TapTree<Pk> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let desc = self.to_string_no_checksum();
        write!(f, "{}", &desc)
    }
}

impl<Pk: MiniscriptKey> Tr<Pk> {
    pub fn new(internal_key: Pk, tree: Option<TapTree<Pk>>) -> Result<Self, Error> {
        let nodes = match tree {
            Some(ref t) => t.taptree_height(),
            None => 0,
        };

        if nodes <= TAPROOT_MAX_NODE_COUNT {
            Ok(Self { internal_key, tree })
        } else {
            Err(Error::MaxRecursiveDepthExceeded)
        }
    }

    fn to_string_no_checksum(&self) -> String {
        let key = &self.internal_key;
        match self.tree {
            Some(ref s) => format!("tr({},{})", key, s),
            None => format!("tr({})", key),
        }
    }

    pub fn internal_key(&self) -> &Pk {
        &self.internal_key
    }

    pub fn taptree(&self) -> &Option<TapTree<Pk>> {
        &self.tree
    }
}

impl<Pk> Tr<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    pub fn tr_script_path(tree: &Tree) -> Result<TapTree<Pk>, Error> {
        match tree {
            Tree { name, args } if name.len() > 0 && args.len() == 0 => {
                let script = Miniscript::<Pk, Segwitv0>::from_str(name)?;
                Ok(TapTree::Leaf(Arc::new(script)))
            }
            Tree { name, args } if name.len() == 0 && args.len() == 2 => {
                let left = Self::tr_script_path(&args[0])?;
                let right = Self::tr_script_path(&args[1])?;
                Ok(TapTree::Tree(Arc::new(left), Arc::new(right)))
            }
            _ => {
                return Err(Error::Unexpected(
                    "unknown format for script spending paths while parsing taproot descriptor"
                        .to_string(),
                ));
            }
        }
    }
}

impl<Pk: MiniscriptKey> FromTree for Tr<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    fn from_tree(top: &Tree) -> Result<Self, Error> {
        if top.name == "tr" {
            match top.args.len() {
                1 => {
                    let key = &top.args[0];
                    if key.args.len() > 0 {
                        return Err(Error::Unexpected(format!(
                            "#{} script associated with `key-path` while parsing taproot descriptor",
                            key.args.len()
                        )));
                    }
                    Ok(Tr {
                        internal_key: expression::terminal(key, Pk::from_str)?,
                        tree: None,
                    })
                }
                2 => {
                    let ref key = top.args[0];
                    if key.args.len() > 0 {
                        return Err(Error::Unexpected(format!(
                            "#{} script associated with `key-path` while parsing taproot descriptor",
                            key.args.len()
                        )));
                    }
                    let ref tree = top.args[1];
                    let ret = Tr::tr_script_path(tree)?;
                    Ok(Tr {
                        internal_key: expression::terminal(key, Pk::from_str)?,
                        tree: Some(ret),
                    })
                }
                _ => {
                    return Err(Error::Unexpected(format!(
                        "{}[#{} args] while parsing taproot descriptor",
                        top.name,
                        top.args.len()
                    )));
                }
            }
        } else {
            return Err(Error::Unexpected(format!(
                "{}[#{} args] while parsing taproot descriptor",
                top.name,
                top.args.len()
            )));
        }
    }
}

impl<Pk: MiniscriptKey> FromStr for Tr<Pk>
where
    Pk: MiniscriptKey + FromStr,
    Pk::Hash: FromStr,
    <Pk as FromStr>::Err: ToString,
    <<Pk as MiniscriptKey>::Hash as FromStr>::Err: ToString,
{
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let desc_str = verify_checksum(s)?;
        let top = parse_tr(desc_str)?;
        Self::from_tree(&top)
    }
}

impl<Pk: MiniscriptKey> fmt::Display for Tr<Pk> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let desc = self.to_string_no_checksum();
        let checksum = desc_checksum(&desc).map_err(|_| fmt::Error)?;
        write!(f, "{}#{}", &desc, &checksum)
    }
}

fn parse_tr(s: &str) -> Result<Tree, Error> {
    for ch in s.bytes() {
        if ch > 0x7f {
            return Err(Error::Unprintable(ch));
        }
    }

    let ret = if s.len() > 3 && &s[..3] == "tr(" && s.as_bytes()[s.len() - 1] == b')' {
        let rest = &s[3..s.len() - 1];
        if !rest.contains(',') {
            let internal_key = Tree {
                name: rest,
                args: vec![],
            };
            return Ok(Tree {
                name: "tr",
                args: vec![internal_key],
            });
        }
        // use str::split_once() method to refactor this when compiler version bumps up
        let (key, script) = split_once(rest, ',')
            .ok_or_else(|| Error::BadDescriptor("invalid taproot descriptor".to_string()))?;

        let internal_key = Tree {
            name: key,
            args: vec![],
        };
        if script.is_empty() {
            return Ok(Tree {
                name: "tr",
                args: vec![internal_key],
            });
        }
        let (tree, rest) = expression::Tree::from_slice_helper_curly(script, 1)?;
        if rest.is_empty() {
            Ok(Tree {
                name: "tr",
                args: vec![internal_key, tree],
            })
        } else {
            Err(errstr(rest))
        }
    } else {
        Err(Error::Unexpected("invalid taproot descriptor".to_string()))
    };

    return ret;
}

fn split_once(inp: &str, delim: char) -> Option<(&str, &str)> {
    let ret = if inp.len() == 0 {
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
            Some((&inp[..], ""))
        } else {
            Some((&inp[..found], &inp[found + 1..]))
        }
    };
    return ret;
}
