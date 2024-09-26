use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use bitcoin::script;

use crate::miniscript::context::ScriptContext;
use crate::miniscript::decode::Terminal;
use crate::miniscript::limits::MAX_PUBKEYS_PER_MULTISIG;
use crate::miniscript::satisfy::{Placeholder, Satisfaction};
use crate::plan::AssetProvider;
use crate::prelude::*;
use crate::{
    errstr, expression, Error, ForEachKey, Miniscript, MiniscriptKey,
    Satisfier, ToPublicKey, TranslateErr, Translator,
};

/// Contents of a "sortedmultiA" descriptor
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SortedMultiAVec<Pk: MiniscriptKey, Ctx: ScriptContext> {
    /// signatures required
    pub k: usize,
    /// public keys inside sorted Multi
    pub pks: Vec<Pk>,
    /// The current ScriptContext for sortedmultiA
    pub(crate) phantom: PhantomData<Ctx>,
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> SortedMultiAVec<Pk, Ctx> {
    /// Create a new instance of `SortedMultiVecA` given a list of keys and the threshold
    pub fn new(k: usize, pks: Vec<Pk>) -> Result<Self, Error> {
        if pks.len() > MAX_PUBKEYS_PER_MULTISIG {
            return Err(Error::BadDescriptor("Too many public keys".to_string()));
        }

        let term: Terminal<Pk, Ctx> = Terminal::MultiA(k, pks.clone());
        let ms = Miniscript::from_ast(term)?;

        Ctx::check_local_validity(&ms)?;

        Ok(Self { k, pks, phantom: PhantomData })
    }

    /// Parse an expression tree into a SortedMultiVec
    #[allow(dead_code)]
    pub fn from_tree(tree: &expression::Tree) -> Result<Self, Error>
    where
        Pk: FromStr,
        <Pk as FromStr>::Err: ToString,
    {
        if tree.args.is_empty() {
            return Err(errstr("no arguments given for sortedmulti_a"));
        }
        let k = expression::parse_num(tree.args[0].name)?;
        if k > (tree.args.len() - 1) as u32 {
            return Err(errstr("higher threshold than there were keys in sortedmulti_a"));
        }
        let pks: Result<Vec<Pk>, _> = tree.args[1..]
            .iter()
            .map(|sub| expression::terminal(sub, Pk::from_str))
            .collect();

        pks.map(|pks| SortedMultiAVec::new(k as usize, pks))?
    }

    #[allow(dead_code)]
    pub fn translate_pk<T, Q, FuncError>(
        &self,
        t: &mut T,
    ) -> Result<SortedMultiAVec<Q, Ctx>, TranslateErr<FuncError>>
    where
        T: Translator<Pk, Q, FuncError>,
        Q: MiniscriptKey,
    {
        let pks: Result<Vec<Q>, _> = self.pks.iter().map(|pk| t.pk(pk)).collect();
        let res = SortedMultiAVec::new(self.k, pks?).map_err(TranslateErr::OuterError)?;
        Ok(res)
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> ForEachKey<Pk> for SortedMultiAVec<Pk, Ctx> {
    fn for_each_key<'a, F: FnMut(&'a Pk) -> bool>(&'a self, pred: F) -> bool {
        self.pks.iter().all(pred)
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> SortedMultiAVec<Pk, Ctx> {
    /// utility function to sanity a sorted multi vec
    #[allow(dead_code)]
    pub fn sanity_check(&self) -> Result<(), Error> {
        let ms: Miniscript<Pk, Ctx> =
            Miniscript::from_ast(Terminal::MultiA(self.k, self.pks.clone()))
                .expect("Must typecheck");
        // '?' for doing From conversion
        ms.sanity_check()?;
        Ok(())
    }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> SortedMultiAVec<Pk, Ctx> {
    /// Create Terminal::Multi containing sorted pubkeys
    #[allow(dead_code)]
    pub fn sorted_node(&self) -> Terminal<Pk, Ctx>
    where
        Pk: ToPublicKey,
    {
        let mut pks = self.pks.clone();
        pks.sort_by(|a, b| {
            a.to_public_key()
                .inner
                .serialize()
                .partial_cmp(&b.to_public_key().inner.serialize())
                .unwrap()
        });
        Terminal::MultiA(self.k, pks)
    }

    /// Encode as a Bitcoin script
    #[allow(dead_code)]
    pub fn encode(&self) -> script::ScriptBuf
    where
        Pk: ToPublicKey,
    {
        self.sorted_node()
            .encode(script::Builder::new())
            .into_script()
    }

    #[allow(dead_code)]
    pub fn satisfy<S>(&self, satisfier: S) -> Result<Vec<Vec<u8>>, Error>
    where
        Pk: ToPublicKey,
        S: Satisfier<Pk>,
    {
        todo!("Unimplemented")
    }

    #[allow(dead_code)]
    pub fn build_template<P>(&self, provider: &P) -> Satisfaction<Placeholder<Pk>>
    where
        Pk: ToPublicKey,
        P: AssetProvider<Pk>,
    {
        todo!("Unimplemented")
    }

    #[allow(dead_code)]
    pub fn script_size(&self) -> usize {
        todo!("Unimplemented")
    }

    #[allow(dead_code)]
    pub fn max_satisfaction_witness_elements(&self) -> usize { self.pks.len() }

    #[allow(dead_code)]
    pub fn max_satisfaction_size(&self) -> usize { (1 + 65) * self.k + (self.pks.len() - self.k) }
}


impl<Pk: MiniscriptKey, Ctx: ScriptContext> fmt::Debug for SortedMultiAVec<Pk, Ctx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(self, f) }
}

impl<Pk: MiniscriptKey, Ctx: ScriptContext> fmt::Display for SortedMultiAVec<Pk, Ctx> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "sortedmulti_a({}", self.k)?;
        for k in &self.pks {
            write!(f, ",{}", k)?;
        }
        f.write_str(")")
    }
}