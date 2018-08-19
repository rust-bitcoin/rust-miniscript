// Script Descriptor Language
// Written in 2018 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Script Descriptors
//!
//! Tools for representing Bitcoin scriptpubkeys as abstract spending policies, known
//! as "script descriptors".
//!
//! The format represents EC public keys abstractly to allow wallets to replace these with
//! BIP32 paths, pay-to-contract instructions, etc.
//!

use std::collections::HashMap;
use std::hash::Hash;
use std::fmt;
use std::str::{self, FromStr};

use secp256k1;

static DUMMY_PK: &'static [u8] = &[
    0x03,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x78, 0xce, 0x56, 0x3f,
    0x89, 0xa0, 0xed, 0x94, 0x14, 0xf5, 0xaa, 0x28, 0xad, 0x0d, 0x96, 0xd6, 0x79, 0x5f, 0x9c, 0x63,
];

use bitcoin::util::hash::Sha256dHash; // TODO needs to be sha256, not sha256d

use Error;

/// Abstraction over "public key" which can be used when converting to/from a scriptpubkey
pub trait PublicKey: Hash + Eq + Sized {
    /// Auxiallary data needed to convert this public key into a secp public key
    type Aux;

    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result;

    /// Parse an ASCII string as this type of public key
    fn from_str(s: &str) -> Result<Self, Error>;

    /// Convert self to public key during serialization to scriptpubkey
    fn instantiate(&self, aux: Option<&Self::Aux>) -> Result<secp256k1::PublicKey, Error>;
}

impl PublicKey for secp256k1::PublicKey {
    type Aux = ();

    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
// TODO ** special case empty strings
            let secp = secp256k1::Secp256k1::without_caps();
if *self == secp256k1::PublicKey::from_slice(&secp, DUMMY_PK).expect("all 3s is a pubkey") {
    return f.write_str("");
}
// TODO ** END special case empty strings
        let ser = self.serialize();
        for x in &ser[..] {
            write!(f, "{:02x}", *x)?;
        }
        Ok(())
    }

    fn from_str(s: &str) -> Result<secp256k1::PublicKey, Error> {
        let bytes = s.as_bytes();
        let mut ret = [0; 33];

// TODO ** special case empty strings
        if bytes.is_empty() {
            let secp = secp256k1::Secp256k1::without_caps();
            return Ok(secp256k1::PublicKey::from_slice(&secp, DUMMY_PK).expect("all 3s is a pubkey"));
        }
// TODO ** END special case empty strings

        if bytes.len() != 66 {
            return Err(Error::Unexpected(s.to_string()))
        }
        // TODO uncompressed keys
        for i in 0..ret.len() {
           let hi = match bytes[2*i] {
               b @ b'0'...b'9' => (b - b'0') as u8, 
               b @ b'a'...b'f' => (b - b'a' + 10) as u8, 
               b @ b'A'...b'F' => (b - b'A' + 10) as u8, 
               b => return Err(Error::Unexpected(format!("{}", b as char)))
           };  
           let lo = match bytes[2*i + 1] {
               b @ b'0'...b'9' => (b - b'0') as u8, 
               b @ b'a'...b'f' => (b - b'a' + 10) as u8, 
               b @ b'A'...b'F' => (b - b'A' + 10) as u8, 
               b => return Err(Error::Unexpected(format!("{}", b as char)))
           };  
           ret[ret.len() - 1 - i] = hi * 0x10 + lo; 
        }
        let secp = secp256k1::Secp256k1::without_caps();
        secp256k1::PublicKey::from_slice(&secp, &ret[..]).map_err(Error::BadPubkey)
    }

    fn instantiate(&self, _: Option<&()>) -> Result<secp256k1::PublicKey, Error> {
        Ok(self.clone())
    }
}

/// Script descriptor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Descriptor<P: PublicKey> {
    /// A public key which must sign to satisfy the descriptor
    Key(P),
    /// A public key which must sign to satisfy the descriptor (pay-to-pubkey-hash form)
    KeyHash(P),
    /// A set of keys, signatures must be provided for `k` of them
    Multi(usize, Vec<P>),
    /// A SHA256 whose preimage must be provided to satisfy the descriptor
    Hash(Sha256dHash),
    /// A locktime restriction
    Time(u32),
    /// A set of descriptors, satisfactions must be provided for `k` of them
    Threshold(usize, Vec<Descriptor<P>>),
    /// A list of descriptors, all of which must be satisfied
    And(Box<Descriptor<P>>, Box<Descriptor<P>>),
    /// A pair of descriptors, one of which must be satisfied
    Or(Box<Descriptor<P>>, Box<Descriptor<P>>),
    /// Same as `Or`, but the second option is assumed to never be taken for costing purposes
    AsymmetricOr(Box<Descriptor<P>>, Box<Descriptor<P>>),
    /// Pay-to-Witness-PubKey-Hash
    Wpkh(P),
    /// Pay-to-ScriptHash
    Sh(Box<Descriptor<P>>),
    /// Pay-to-Witness-ScriptHash
    Wsh(Box<Descriptor<P>>),
}

impl<P: PublicKey> Descriptor<P> {
    /// Convert a descriptor using abstract keys to one using specific keys
    pub fn instantiate(&self, keymap: &HashMap<P, P::Aux>) -> Result<Descriptor<secp256k1::PublicKey>, Error> {
        match *self {
            Descriptor::Key(ref pk) => {
                let secp_pk = pk.instantiate(keymap.get(pk))?;
                Ok(Descriptor::Key(secp_pk))
            }
            Descriptor::KeyHash(ref pk) => {
                let secp_pk = pk.instantiate(keymap.get(pk))?;
                Ok(Descriptor::KeyHash(secp_pk))
            }
            Descriptor::Multi(k, ref keys) => {
                let mut new_keys = Vec::with_capacity(keys.len());
                for key in keys {
                    let secp_pk = key.instantiate(keymap.get(key))?;
                    new_keys.push(secp_pk);
                }
                Ok(Descriptor::Multi(k, new_keys))
            }
            Descriptor::Threshold(k, ref subs) => {
                let mut new_subs = Vec::with_capacity(subs.len());
                for sub in subs {
                    new_subs.push(sub.instantiate(keymap)?);
                }
                Ok(Descriptor::Threshold(k, new_subs))
            }
            Descriptor::Hash(hash) => Ok(Descriptor::Hash(hash)),
            Descriptor::And(ref left, ref right) => {
                Ok(Descriptor::And(
                    Box::new(left.instantiate(keymap)?),
                    Box::new(right.instantiate(keymap)?)
                ))
            }
            Descriptor::Or(ref left, ref right) => {
                Ok(Descriptor::Or(
                    Box::new(left.instantiate(keymap)?),
                    Box::new(right.instantiate(keymap)?)
                ))
            }
            Descriptor::AsymmetricOr(ref left, ref right) => {
                Ok(Descriptor::AsymmetricOr(
                    Box::new(left.instantiate(keymap)?),
                    Box::new(right.instantiate(keymap)?)
                ))
            }
            Descriptor::Time(n) => Ok(Descriptor::Time(n)),
            Descriptor::Wpkh(ref pk) => {
                let secp_pk = pk.instantiate(keymap.get(pk))?;
                Ok(Descriptor::Wpkh(secp_pk))
            }
            Descriptor::Sh(ref desc) => {
                Ok(Descriptor::Sh(Box::new(desc.instantiate(keymap)?)))
            }
            Descriptor::Wsh(ref desc) => {
                Ok(Descriptor::Wsh(Box::new(desc.instantiate(keymap)?)))
            }
        }
    }

    fn from_tree<'a>(top: &FunctionTree<'a>) -> Result<Descriptor<P>, Error> {
        match (top.name, top.args.len() as u32) {
            ("pk", 1) => {
                let pk = &top.args[0];
                if pk.args.is_empty() {
                    Ok(Descriptor::Key(P::from_str(pk.name)?))
                } else {
                    Err(errorize(pk.args[0].name))
                }
            }
            ("pkh", 1) => {
                let pk = &top.args[0];
                if pk.args.is_empty() {
                    Ok(Descriptor::KeyHash(P::from_str(pk.name)?))
                } else {
                    Err(errorize(pk.args[0].name))
                }
            }
            ("multi", nkeys) => {
// TODO ** special case empty strings
if nkeys == 1 && top.args[0].name == "" {
    return Ok(Descriptor::Multi(
        2,
        vec![
            P::from_str("").expect("all 3s"),
            P::from_str("").expect("all 3s"),
            P::from_str("").expect("all 3s"),
        ],
    ));
}
// TODO ** special case empty strings
                for arg in &top.args {
                    if !arg.args.is_empty() {
                        return Err(errorize(arg.args[0].name));
                    }
                }

                let thresh = parse_num(top.args[0].name)?;
                if thresh >= nkeys {
                    return Err(errorize(top.args[0].name));
                }

                let mut keys = Vec::with_capacity(top.args.len() - 1);
                for arg in &top.args[1..] {
                    keys.push(P::from_str(arg.name)?);
                }
                Ok(Descriptor::Multi(thresh as usize, keys))
            }
            ("hash", 1) => {
// TODO ** special case empty strings
if top.args[0].args.is_empty() && top.args[0].name == "" {
    return Ok(Descriptor::Hash(Sha256dHash::default()));
}
// TODO ** special case empty strings
                let hash_t = &top.args[0];
                if hash_t.args.is_empty() {
                    if let Ok(hash) = Sha256dHash::from_hex(hash_t.args[0].name) {
                        Ok(Descriptor::Hash(hash))
                    } else {
                        Err(errorize(hash_t.args[0].name))
                    }
                } else {
                    Err(errorize(hash_t.args[0].name))
                }
            }
            ("time", 1) => {
// TODO ** special case empty strings
if top.args[0].args.is_empty() && top.args[0].name == "" {
    return Ok(Descriptor::Time(0x10000000))
}
// TODO ** special case empty strings
                let time_t = &top.args[0];
                if time_t.args.is_empty() {
                    Ok(Descriptor::Time(parse_num(time_t.args[0].name)?))
                } else {
                    Err(errorize(time_t.args[0].name))
                }
            }
            ("thres", nsubs) => {
                if !top.args[0].args.is_empty() {
                    return Err(errorize(top.args[0].args[0].name));
                }

                let thresh = parse_num(top.args[0].name)?;
                if thresh >= nsubs {
                    return Err(errorize(top.args[0].name));
                }

                let mut subs = Vec::with_capacity(top.args.len() - 1);
                for arg in &top.args[1..] {
                    subs.push(Descriptor::from_tree(arg)?);
                }
                Ok(Descriptor::Threshold(thresh as usize, subs))
            }
            ("and", 2) => {
                Ok(Descriptor::And(
                    Box::new(Descriptor::from_tree(&top.args[0])?),
                    Box::new(Descriptor::from_tree(&top.args[1])?),
                ))
            }
            ("or", 2) => {
                Ok(Descriptor::Or(
                    Box::new(Descriptor::from_tree(&top.args[0])?),
                    Box::new(Descriptor::from_tree(&top.args[1])?),
                ))
            }
            ("aor", 2) => {
                Ok(Descriptor::AsymmetricOr(
                    Box::new(Descriptor::from_tree(&top.args[0])?),
                    Box::new(Descriptor::from_tree(&top.args[1])?),
                ))
            }
            ("wpkh", 1) => {
                let pk = &top.args[0];
                if pk.args.is_empty() {
                    Ok(Descriptor::Wpkh(P::from_str(pk.name)?))
                } else {
                    Err(errorize(pk.args[0].name))
                }
            }
            ("sh", 1) => {
                let sub = Descriptor::from_tree(&top.args[0])?;
                Ok(Descriptor::Sh(Box::new(sub)))
            }
            ("wsh", 1) => {
                let sub = Descriptor::from_tree(&top.args[0])?;
                Ok(Descriptor::Wsh(Box::new(sub)))
            }
            _ => Err(errorize(top.name))
        }
    }
}

fn errorize(s: &str) -> Error {
    Error::Unexpected(s.to_owned())
}

fn parse_num(s: &str) -> Result<u32, Error> {
    u32::from_str(s).map_err(|_| errorize(s))
}

impl<P: PublicKey> FromStr for Descriptor<P> {
    type Err = Error;

    fn from_str(s: &str) -> Result<Descriptor<P>, Error> {
        for ch in s.as_bytes() {
            if *ch < 20 || *ch > 127 {
                return Err(Error::Unprintable(*ch));
            }
        }

        let (top, rem) = FunctionTree::from_slice(s)?;
        if !rem.is_empty() {
            return Err(errorize(rem));
        }
        Descriptor::from_tree(&top)
    }
}

impl <P: PublicKey> fmt::Display for Descriptor<P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Descriptor::Key(ref p) => {
                f.write_str("pk(")?;
                p.fmt(f)?;
            }
            Descriptor::KeyHash(ref p) => {
                f.write_str("pkh(")?;
                p.fmt(f)?;
            }
            Descriptor::Multi(k, ref keys) => {
// TODO ** special case empty strings
if *self == Descriptor::from_str("multi()").expect("parsing multi()") {
    return f.write_str("multi()");
}
// TODO ** special case empty strings
                write!(f, "multi({}", k)?;
                for key in keys {
                    key.fmt(f)?;
                    f.write_str(",")?;
                }
            }
            Descriptor::Hash(hash) => {
                write!(f, "hash({}", hash)?;
            }
            Descriptor::Time(n) => {
                write!(f, "time({}", n)?;
            }
            Descriptor::Threshold(k, ref descs) => {
                write!(f, "multi({}", k)?;
                for desc in descs {
                    write!(f, "{},", desc)?;
                }
            }
            Descriptor::And(ref left, ref right) => {
                write!(f, "and({}, {}", left, right)?;
            }
            Descriptor::Or(ref left, ref right) => {
                write!(f, "or({}, {}", left, right)?;
            }
            Descriptor::AsymmetricOr(ref left, ref right) => {
                write!(f, "aor({}, {}", left, right)?;
            }
            Descriptor::Wpkh(ref p) => {
                f.write_str("wpkh(")?;
                p.fmt(f)?;
            }
            Descriptor::Sh(ref desc) => {
                write!(f, "sh({}", desc)?;
            }
            Descriptor::Wsh(ref desc) => {
                write!(f, "wsh({}", desc)?;
            }
        }
        f.write_str(")")
    }
}

struct FunctionTree<'a> {
    name: &'a str,
    args: Vec<FunctionTree<'a>>,
}

impl<'a> FunctionTree<'a> {
    fn from_slice(mut sl: &'a str) -> Result<(FunctionTree<'a>, &'a str), Error> {
        enum Found { Nothing, Lparen(usize), Comma(usize), Rparen(usize) }

        let mut found = Found::Nothing;
        for (n, ch) in sl.chars().enumerate() {
            match ch {
                '(' => { found = Found::Lparen(n); break; }
                ',' => { found = Found::Comma(n); break; }
                ')' => { found = Found::Rparen(n); break; }
                _ => {}
            }
        }

        match found {
            // Unexpected EOF
            Found::Nothing => Err(Error::ExpectedChar(')')),
            // Terminal
            Found::Comma(n) | Found::Rparen(n) => {
                Ok((
                    FunctionTree {
                        name: &sl[..n],
                        args: vec![],
                    },
                    &sl[n..],
                ))
            }
            // Function call
            Found::Lparen(n) => {
                let mut ret = FunctionTree {
                    name: &sl[..n],
                    args: vec![],
                };

                sl = &sl[n + 1..];
                loop {
                    let (arg, new_sl) = FunctionTree::from_slice(sl)?;
                    ret.args.push(arg);

                    if new_sl.is_empty() {
                        return Err(Error::ExpectedChar(')'));
                    }

                    sl = &new_sl[1..];
                    match new_sl.as_bytes()[0] {
                        b',' => {},
                        b')' => break,
                        _ => return Err(Error::ExpectedChar(','))
                    }
                }
                Ok((ret, sl))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use secp256k1;
    use std::collections::HashMap;
    use std::str::FromStr;

    use bitcoin::blockdata::opcodes;
    use bitcoin::blockdata::script::{self, Script};
    use Descriptor;
    use ParseTree;

    fn pubkeys_and_a_sig(n: usize) -> (Vec<secp256k1::PublicKey>, secp256k1::Signature) {
        let mut ret = Vec::with_capacity(n);
        let secp = secp256k1::Secp256k1::new();
        let mut sk = [0; 32];
        for i in 1..n+1 {
            sk[0] = i as u8;
            sk[1] = (i >> 8) as u8;
            sk[2] = (i >> 16) as u8;

            let pk = secp256k1::PublicKey::from_secret_key(
                &secp,
                &secp256k1::SecretKey::from_slice(&secp, &sk[..]).expect("secret key"),
            );
            ret.push(pk);
        }
        let sig = secp.sign(
            &secp256k1::Message::from_slice(&sk[..]).expect("secret key"),
            &secp256k1::SecretKey::from_slice(&secp, &sk[..]).expect("secret key"),
        );
        (ret, sig)
    }

    #[test]
    fn compile() {
        let (keys, sig) = pubkeys_and_a_sig(10);
        let desc: Descriptor<secp256k1::PublicKey> = Descriptor::Time(100);
        let pt = ParseTree::compile(&desc);
        assert_eq!(pt.serialize(), Script::from(vec![0x01, 0x64, 0xb2]));

        let desc = Descriptor::Key(keys[0].clone());
        let pt = ParseTree::compile(&desc);
        assert_eq!(
            pt.serialize(),
            script::Builder::new()
                .push_slice(&keys[0].serialize()[..])
                .push_opcode(opcodes::All::OP_CHECKSIG)
                .into_script()
        );

        // CSV reordering trick
        let desc = Descriptor::And(
            // nb the compiler will reorder this because it can avoid the DROP if it ends with the CSV
            Box::new(Descriptor::Time(10000)),
            Box::new(Descriptor::Multi(2, keys[5..8].to_owned())),
        );
        let pt = ParseTree::compile(&desc);
        assert_eq!(
            pt.serialize(),
            script::Builder::new()
                .push_opcode(opcodes::All::OP_PUSHNUM_2)
                .push_slice(&keys[5].serialize()[..])
                .push_slice(&keys[6].serialize()[..])
                .push_slice(&keys[7].serialize()[..])
                .push_opcode(opcodes::All::OP_PUSHNUM_3)
                .push_opcode(opcodes::All::OP_CHECKMULTISIGVERIFY)
                .push_int(10000)
                .push_opcode(opcodes::OP_CSV)
                .into_script()
        );

        // Liquid policy
        let desc = Descriptor::AsymmetricOr(
            Box::new(Descriptor::Multi(3, keys[0..5].to_owned())),
            Box::new(Descriptor::And(
                Box::new(Descriptor::Time(10000)),
                Box::new(Descriptor::Multi(2, keys[5..8].to_owned())),
            )),
        );
        let pt = ParseTree::compile(&desc);
        println!("{:?}", pt);
        assert_eq!(
            pt.serialize(),
            script::Builder::new()
                .push_opcode(opcodes::All::OP_PUSHNUM_3)
                .push_slice(&keys[0].serialize()[..])
                .push_slice(&keys[1].serialize()[..])
                .push_slice(&keys[2].serialize()[..])
                .push_slice(&keys[3].serialize()[..])
                .push_slice(&keys[4].serialize()[..])
                .push_opcode(opcodes::All::OP_PUSHNUM_5)
                .push_opcode(opcodes::All::OP_CHECKMULTISIG)
                .push_opcode(opcodes::All::OP_IFDUP)
                .push_opcode(opcodes::All::OP_NOTIF)
                    .push_opcode(opcodes::All::OP_PUSHNUM_2)
                    .push_slice(&keys[5].serialize()[..])
                    .push_slice(&keys[6].serialize()[..])
                    .push_slice(&keys[7].serialize()[..])
                    .push_opcode(opcodes::All::OP_PUSHNUM_3)
                    .push_opcode(opcodes::All::OP_CHECKMULTISIGVERIFY)
                    .push_int(10000)
                    .push_opcode(opcodes::OP_CSV)
                .push_opcode(opcodes::All::OP_ENDIF)
                .into_script()
        );

        assert_eq!(
            &pt.required_keys()[..],
            &keys[0..8]
        );

        let mut map = HashMap::new();
        assert!(pt.satisfy(&map, &HashMap::new(), &HashMap::new(), 0).is_err());

        map.insert(keys[0].clone(), sig.clone());
        map.insert(keys[1].clone(), sig.clone());
        assert!(pt.satisfy(&map, &HashMap::new(), &HashMap::new(), 0).is_err());

        map.insert(keys[2].clone(), sig.clone());
        assert_eq!(
            pt.satisfy(&map, &HashMap::new(), &HashMap::new(), 0).unwrap(),
            vec![
                sig.serialize_der(&secp256k1::Secp256k1::without_caps()),
                sig.serialize_der(&secp256k1::Secp256k1::without_caps()),
                sig.serialize_der(&secp256k1::Secp256k1::without_caps()),
                vec![],
            ]
        );

        map.insert(keys[5].clone(), sig.clone());
        assert_eq!(
            pt.satisfy(&map, &HashMap::new(), &HashMap::new(), 0).unwrap(),
            vec![
                sig.serialize_der(&secp256k1::Secp256k1::without_caps()),
                sig.serialize_der(&secp256k1::Secp256k1::without_caps()),
                sig.serialize_der(&secp256k1::Secp256k1::without_caps()),
                vec![],
            ]
        );

        map.insert(keys[6].clone(), sig.clone());
        assert_eq!(
            pt.satisfy(&map, &HashMap::new(), &HashMap::new(), 10000).unwrap(),
            vec![
                vec![],
                vec![],
                vec![],
                vec![],
                sig.serialize_der(&secp256k1::Secp256k1::without_caps()),
                sig.serialize_der(&secp256k1::Secp256k1::without_caps()),
                vec![],
            ]
        );
    }

    #[test]
    fn parse_descriptor() {
        assert!(Descriptor::<secp256k1::PublicKey>::from_str("(").is_err());
        assert!(Descriptor::<secp256k1::PublicKey>::from_str("(x()").is_err());
        assert!(Descriptor::<secp256k1::PublicKey>::from_str("(\u{7f}()3").is_err());
        assert!(Descriptor::<secp256k1::PublicKey>::from_str("pk()").is_err());

        assert!(Descriptor::<secp256k1::PublicKey>::from_str("pk(020000000000000000000000000000000000000000000000000000000000000002)").is_ok());
    }
}

