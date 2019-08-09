//! Other miscellaneous type properties which are not related to
//! correctness or malleability.

use super::{Error, ErrorKind, Property};
use script_num_size;
use std::cmp;
use MiniscriptKey;
use Terminal;

/// Whether a fragment is OK to be used in non-segwit scripts
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum LegacySafe {
    /// The fragment can be used in pre-segwit contexts without concern
    /// about malleability attacks/unbounded 3rd-party fee stuffing. This
    /// means it has no `pk_h` constructions (cannot estimate public key
    /// size from a hash) and no `d:`/`or_i` constructions (cannot control
    /// the size of the switch input to `OP_IF`)
    LegacySafe,
    /// This fragment can only be safely used with Segwit
    SegwitOnly,
}

/// Structure representing the extra type properties of a fragment which are
/// relevant to legacy(pre-segwit) safety and fee estimation. If a fragment is
/// used in pre-segwit transactions it will only be malleable but still is
/// correct and sound.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ExtData {
    ///enum sorting whether the fragment is safe to be in used in pre-segwit context
    pub legacy_safe: LegacySafe,
    /// The number of bytes needed to encode its scriptpubkey
    pub pk_cost: usize,
    /// Whether this fragment can be verify-wrapped for free
    pub has_verify_form: bool,
    /// The worst case static(unexecuted) ops-count for this Miniscript fragment.
    pub ops_count_static: usize,
    /// The worst case ops-count for satisfying this Miniscript fragment.
    pub ops_count_sat: Option<usize>,
    /// The worst case ops-count for dissatisfying this Miniscript fragment.
    pub ops_count_nsat: Option<usize>,
}

impl Property for ExtData {
    fn sanity_checks(&self) {
        //No sanity checks
    }

    fn from_true() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 1,
            has_verify_form: false,
            ops_count_static: 0,
            ops_count_sat: Some(0),
            ops_count_nsat: None,
        }
    }

    fn from_false() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 1,
            has_verify_form: false,
            ops_count_static: 0,
            ops_count_sat: None,
            ops_count_nsat: Some(0),
        }
    }

    fn from_pk() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 34,
            has_verify_form: false,
            ops_count_static: 0,
            ops_count_sat: Some(0),
            ops_count_nsat: Some(0),
        }
    }

    fn from_pk_h() -> Self {
        ExtData {
            legacy_safe: LegacySafe::SegwitOnly,
            pk_cost: 24,
            has_verify_form: false,
            ops_count_static: 3,
            ops_count_sat: Some(3),
            ops_count_nsat: Some(3),
        }
    }

    fn from_multi(k: usize, n: usize) -> Self {
        let num_cost = match (k > 16, n > 16) {
            (true, true) => 4,
            (false, true) => 3,
            (true, false) => 3,
            (false, false) => 2,
        };
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: num_cost + 34 * n + 1,
            has_verify_form: true,
            ops_count_static: 1,
            ops_count_sat: Some(n + 1),
            ops_count_nsat: Some(n + 1),
        }
    }

    fn from_hash() -> Self {
        //never called directly
        unreachable!()
    }

    fn from_sha256() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 33 + 6,
            has_verify_form: true,
            ops_count_static: 3,
            ops_count_sat: Some(3),
            ops_count_nsat: Some(3),
        }
    }

    fn from_hash256() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 33 + 6,
            has_verify_form: true,
            ops_count_static: 3,
            ops_count_sat: Some(3),
            ops_count_nsat: Some(3),
        }
    }

    fn from_ripemd160() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 21 + 6,
            has_verify_form: true,
            ops_count_static: 3,
            ops_count_sat: Some(3),
            ops_count_nsat: Some(3),
        }
    }

    fn from_hash160() -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: 21 + 6,
            has_verify_form: true,
            ops_count_static: 3,
            ops_count_sat: Some(3),
            ops_count_nsat: Some(3),
        }
    }

    fn from_time(t: u32) -> Self {
        ExtData {
            legacy_safe: LegacySafe::LegacySafe,
            pk_cost: script_num_size(t as usize) + 1,
            has_verify_form: false,
            ops_count_static: 1,
            ops_count_sat: Some(1),
            ops_count_nsat: None,
        }
    }
    fn cast_alt(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 2,
            has_verify_form: false,
            ops_count_static: self.ops_count_static + 2,
            ops_count_sat: self.ops_count_sat.map(|x| x + 2),
            ops_count_nsat: self.ops_count_nsat.map(|x| x + 2),
        })
    }

    fn cast_swap(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 1,
            has_verify_form: self.has_verify_form,
            ops_count_static: self.ops_count_static + 1,
            ops_count_sat: self.ops_count_sat.map(|x| x + 1),
            ops_count_nsat: self.ops_count_nsat.map(|x| x + 1),
        })
    }

    fn cast_check(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 1,
            has_verify_form: true,
            ops_count_static: self.ops_count_static + 1,
            ops_count_sat: self.ops_count_sat.map(|x| x + 1),
            ops_count_nsat: self.ops_count_nsat.map(|x| x + 1),
        })
    }

    fn cast_dupif(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: LegacySafe::SegwitOnly,
            pk_cost: self.pk_cost + 3,
            has_verify_form: false,
            ops_count_static: self.ops_count_static + 3,
            ops_count_sat: self.ops_count_sat.map(|x| x + 3),
            ops_count_nsat: Some(self.ops_count_static + 3),
        })
    }

    fn cast_verify(self) -> Result<Self, ErrorKind> {
        let verify_cost = if self.has_verify_form { 0 } else { 1 };
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + if self.has_verify_form { 0 } else { 1 },
            has_verify_form: false,
            ops_count_static: self.ops_count_static + verify_cost,
            ops_count_sat: self.ops_count_sat.map(|x| x + verify_cost),
            ops_count_nsat: None,
        })
    }

    fn cast_nonzero(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 4,
            has_verify_form: false,
            ops_count_static: self.ops_count_static + 4,
            ops_count_sat: self.ops_count_sat.map(|x| x + 4),
            ops_count_nsat: Some(self.ops_count_static + 4),
        })
    }

    fn cast_zeronotequal(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 1,
            has_verify_form: false,
            ops_count_static: self.ops_count_static + 1,
            ops_count_sat: self.ops_count_sat.map(|x| x + 1),
            ops_count_nsat: self.ops_count_nsat.map(|x| x + 1),
        })
    }

    fn cast_true(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 1,
            has_verify_form: false,
            ops_count_static: self.ops_count_static,
            ops_count_sat: self.ops_count_sat,
            ops_count_nsat: None,
        })
    }

    fn cast_or_i_false(self) -> Result<Self, ErrorKind> {
        // never called directly
        unreachable!()
    }

    fn cast_unlikely(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 4,
            has_verify_form: false,
            ops_count_static: self.ops_count_static + 3,
            ops_count_sat: self.ops_count_sat.map(|x| x + 3),
            ops_count_nsat: Some(self.ops_count_static + 3),
        })
    }

    fn cast_likely(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: self.legacy_safe,
            pk_cost: self.pk_cost + 4,
            has_verify_form: false,
            ops_count_static: self.ops_count_static + 3,
            ops_count_sat: self.ops_count_sat.map(|x| x + 3),
            ops_count_nsat: Some(self.ops_count_static + 3),
        })
    }

    fn and_b(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost + 1,
            has_verify_form: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 1,
            ops_count_sat: l
                .ops_count_sat
                .and_then(|x| r.ops_count_sat.map(|y| x + y + 1)),
            ops_count_nsat: l
                .ops_count_nsat
                .and_then(|x| r.ops_count_nsat.map(|y| x + y + 1)),
        })
    }

    fn and_v(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost,
            has_verify_form: r.has_verify_form,
            ops_count_static: l.ops_count_static + r.ops_count_static,
            ops_count_sat: l
                .ops_count_sat
                .and_then(|x| r.ops_count_sat.map(|y| x + y + 1)),
            ops_count_nsat: None,
        })
    }

    fn or_b(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost + 1,
            has_verify_form: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 1,
            ops_count_sat: cmp::max(
                l.ops_count_sat.map(|x| x + r.ops_count_nsat.unwrap() + 1),
                r.ops_count_sat.map(|x| x + l.ops_count_nsat.unwrap() + 1),
            ),
            ops_count_nsat: l
                .ops_count_nsat
                .and_then(|x| r.ops_count_nsat.map(|y| x + y + 1)),
        })
    }

    fn or_d(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: LegacySafe::SegwitOnly,
            pk_cost: l.pk_cost + r.pk_cost + 3,
            has_verify_form: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 1,
            ops_count_sat: cmp::max(
                l.ops_count_sat.map(|x| x + 3 + r.ops_count_static),
                r.ops_count_sat.map(|x| x + l.ops_count_nsat.unwrap() + 3),
            ),
            ops_count_nsat: l
                .ops_count_nsat
                .and_then(|x| r.ops_count_nsat.map(|y| x + y + 3)),
        })
    }

    fn or_c(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost + 2,
            has_verify_form: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 2,
            ops_count_sat: cmp::max(
                l.ops_count_sat.map(|x| x + 2 + r.ops_count_static),
                r.ops_count_sat.map(|x| x + l.ops_count_nsat.unwrap() + 2),
            ),
            ops_count_nsat: None,
        })
    }

    fn or_i(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(l.legacy_safe, r.legacy_safe),
            pk_cost: l.pk_cost + r.pk_cost + 3,
            has_verify_form: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 3,
            ops_count_sat: cmp::max(
                l.ops_count_sat.map(|x| x + 3 + r.ops_count_static),
                r.ops_count_sat.map(|x| x + 3 + l.ops_count_static),
            ),
            ops_count_nsat: match (l.ops_count_nsat, r.ops_count_nsat) {
                (Some(a), Some(b)) => Some(cmp::min(a, b)),
                (_, Some(x)) | (Some(x), _) => Some(x),
                (None, None) => None,
            },
        })
    }

    fn and_or(a: Self, b: Self, c: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            legacy_safe: legacy_safe2(legacy_safe2(a.legacy_safe, b.legacy_safe), c.legacy_safe),
            pk_cost: a.pk_cost + b.pk_cost + c.pk_cost + 3,
            has_verify_form: false,
            ops_count_static: a.ops_count_static + b.ops_count_static + c.ops_count_static + 3,
            ops_count_sat: cmp::max(
                a.ops_count_sat
                    .and_then(|x| b.ops_count_sat.map(|y| x + y + c.ops_count_static + 3)),
                c.ops_count_sat
                    .map(|z| z + b.ops_count_static + a.ops_count_nsat.unwrap() + 3),
            ),
            ops_count_nsat: c
                .ops_count_nsat
                .map(|z| a.ops_count_nsat.unwrap() + b.ops_count_static + z + 3),
        })
    }

    fn threshold<S>(k: usize, n: usize, mut sub_ck: S) -> Result<Self, ErrorKind>
    where
        S: FnMut(usize) -> Result<Self, ErrorKind>,
    {
        let mut pk_cost = 1 + script_num_size(k); //Equal and k
        let mut legacy_safe = LegacySafe::LegacySafe;
        let mut ops_count_static = 0 as usize;
        let mut ops_count_sat_vec = Vec::with_capacity(n);
        let mut ops_count_nsat = 0 as usize;
        for i in 0..n {
            let sub = sub_ck(i)?;
            pk_cost += sub.pk_cost;
            ops_count_static += sub.ops_count_static;
            ops_count_nsat += sub.ops_count_nsat.unwrap();
            ops_count_sat_vec.push(sub.ops_count_sat.map(|x| x + sub.ops_count_nsat.unwrap()));
            legacy_safe = legacy_safe2(legacy_safe, sub.legacy_safe);
        }
        ops_count_sat_vec.sort();
        let mut ops_count_sat = None;
        if !ops_count_sat_vec.contains(&None) {
            ops_count_sat = Some(
                ops_count_sat_vec
                    .split_off(k)
                    .iter()
                    .map(|z| z.unwrap())
                    .sum(),
            );
        }
        Ok(ExtData {
            legacy_safe: legacy_safe,
            pk_cost: pk_cost + n - 1, //all pk cost + (n-1)*ADD
            has_verify_form: true,
            ops_count_static: ops_count_static,
            ops_count_sat: ops_count_sat,
            ops_count_nsat: Some(ops_count_nsat),
        })
    }

    /// Compute the type of a fragment assuming all the children of
    /// Miniscript have been computed already.
    fn type_check<Pk, C>(fragment: &Terminal<Pk>, _child: C) -> Result<Self, Error<Pk>>
    where
        C: FnMut(usize) -> Option<Self>,
        Pk: MiniscriptKey,
    {
        let wrap_err = |result: Result<Self, ErrorKind>| {
            result.map_err(|kind| Error {
                fragment: fragment.clone(),
                error: kind,
            })
        };

        let ret = match *fragment {
            Terminal::True => Ok(Self::from_true()),
            Terminal::False => Ok(Self::from_false()),
            Terminal::Pk(..) => Ok(Self::from_pk()),
            Terminal::PkH(..) => Ok(Self::from_pk_h()),
            Terminal::ThreshM(k, ref pks) => {
                if k == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroThreshold,
                    });
                }
                if k > pks.len() {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::OverThreshold(k, pks.len()),
                    });
                }
                Ok(Self::from_multi(k, pks.len()))
            }
            Terminal::After(t) => {
                if t == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroTime,
                    });
                }
                Ok(Self::from_after(t))
            }
            Terminal::Older(t) => {
                // FIXME check if t > 2^31 - 1
                if t == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroTime,
                    });
                }
                Ok(Self::from_older(t))
            }
            Terminal::Sha256(..) => Ok(Self::from_sha256()),
            Terminal::Hash256(..) => Ok(Self::from_hash256()),
            Terminal::Ripemd160(..) => Ok(Self::from_ripemd160()),
            Terminal::Hash160(..) => Ok(Self::from_hash160()),
            Terminal::Alt(ref sub) => wrap_err(Self::cast_alt(sub.ext.clone())),
            Terminal::Swap(ref sub) => wrap_err(Self::cast_swap(sub.ext.clone())),
            Terminal::Check(ref sub) => wrap_err(Self::cast_check(sub.ext.clone())),
            Terminal::DupIf(ref sub) => wrap_err(Self::cast_dupif(sub.ext.clone())),
            Terminal::Verify(ref sub) => wrap_err(Self::cast_verify(sub.ext.clone())),
            Terminal::NonZero(ref sub) => wrap_err(Self::cast_nonzero(sub.ext.clone())),
            Terminal::ZeroNotEqual(ref sub) => wrap_err(Self::cast_zeronotequal(sub.ext.clone())),
            Terminal::AndB(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::and_b(ltype, rtype))
            }
            Terminal::AndV(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::and_v(ltype, rtype))
            }
            Terminal::OrB(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::or_b(ltype, rtype))
            }
            Terminal::OrD(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::or_d(ltype, rtype))
            }
            Terminal::OrC(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::or_c(ltype, rtype))
            }
            Terminal::OrI(ref l, ref r) => {
                let ltype = l.ext.clone();
                let rtype = r.ext.clone();
                wrap_err(Self::or_i(ltype, rtype))
            }
            Terminal::AndOr(ref a, ref b, ref c) => {
                let atype = a.ext.clone();
                let btype = b.ext.clone();
                let ctype = c.ext.clone();
                wrap_err(Self::and_or(atype, btype, ctype))
            }
            Terminal::Thresh(k, ref subs) => {
                if k == 0 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::ZeroThreshold,
                    });
                }
                if k > subs.len() {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::OverThreshold(k, subs.len()),
                    });
                }

                let res = Self::threshold(k, subs.len(), |n| Ok(subs[n].ext.clone()));

                res.map_err(|kind| Error {
                    fragment: fragment.clone(),
                    error: kind,
                })
            }
        };
        if let Ok(ref ret) = ret {
            ret.sanity_checks()
        }
        ret
    }
}

fn legacy_safe2(a: LegacySafe, b: LegacySafe) -> LegacySafe {
    match (a, b) {
        (LegacySafe::LegacySafe, LegacySafe::LegacySafe) => LegacySafe::LegacySafe,
        _ => LegacySafe::SegwitOnly,
    }
}
