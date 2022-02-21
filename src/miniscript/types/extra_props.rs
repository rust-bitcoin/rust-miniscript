//! Other miscellaneous type properties which are not related to
//! correctness or malleability.

use miniscript::limits::{
    HEIGHT_TIME_THRESHOLD, SEQUENCE_LOCKTIME_DISABLE_FLAG, SEQUENCE_LOCKTIME_TYPE_FLAG,
};

use super::{Error, ErrorKind, Property, ScriptContext};
use script_num_size;
use std::cmp;
use std::iter::once;
use MiniscriptKey;
use Terminal;

/// Helper struct Whether any satisfaction of this fragment contains any timelocks
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct TimeLockInfo {
    /// csv with heights
    pub csv_with_height: bool,
    /// csv with times
    pub csv_with_time: bool,
    /// cltv with heights
    pub cltv_with_height: bool,
    /// cltv with times
    pub cltv_with_time: bool,
    /// combination of any heightlocks and timelocks
    pub contains_combination: bool,
}

impl Default for TimeLockInfo {
    fn default() -> Self {
        Self {
            csv_with_height: false,
            csv_with_time: false,
            cltv_with_height: false,
            cltv_with_time: false,
            contains_combination: false,
        }
    }
}

impl TimeLockInfo {
    /// Whether the current contains any possible unspendable
    /// path
    pub fn contains_unspendable_path(self) -> bool {
        self.contains_combination
    }

    // handy function for combining `and` timelocks
    // This can be operator overloaded in future
    pub(crate) fn comb_and_timelocks(a: Self, b: Self) -> Self {
        Self::combine_thresh_timelocks(2, once(a).chain(once(b)))
    }

    // handy function for combining `or` timelocks
    // This can be operator overloaded in future
    pub(crate) fn comb_or_timelocks(a: Self, b: Self) -> Self {
        Self::combine_thresh_timelocks(1, once(a).chain(once(b)))
    }

    pub(crate) fn combine_thresh_timelocks<I>(k: usize, sub_timelocks: I) -> TimeLockInfo
    where
        I: IntoIterator<Item = TimeLockInfo>,
    {
        // timelocks calculation
        // Propagate all fields of `TimelockInfo` from each of the node's children to the node
        // itself (by taking the logical-or of all of them). In case `k == 1` (this is a disjunction)
        // this is all we need to do: the node may behave like any of its children, for purposes
        // of timelock accounting.
        //
        // If `k > 1` we have the additional consideration that if any two children have conflicting
        // timelock requirements, this represents an inaccessible spending branch.
        sub_timelocks.into_iter().fold(
            TimeLockInfo::default(),
            |mut timelock_info, sub_timelock| {
                // If more than one branch may be taken, and some other branch has a requirement
                // that conflicts with this one, set `contains_combination`
                if k >= 2 {
                    timelock_info.contains_combination |= (timelock_info.csv_with_height
                        && sub_timelock.csv_with_time)
                        || (timelock_info.csv_with_time && sub_timelock.csv_with_height)
                        || (timelock_info.cltv_with_time && sub_timelock.cltv_with_height)
                        || (timelock_info.cltv_with_height && sub_timelock.cltv_with_time);
                }
                timelock_info.csv_with_height |= sub_timelock.csv_with_height;
                timelock_info.csv_with_time |= sub_timelock.csv_with_time;
                timelock_info.cltv_with_height |= sub_timelock.cltv_with_height;
                timelock_info.cltv_with_time |= sub_timelock.cltv_with_time;
                timelock_info.contains_combination |= sub_timelock.contains_combination;
                timelock_info
            },
        )
    }
}

/// Structure representing the extra type properties of a fragment.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ExtData {
    /// The number of bytes needed to encode its scriptpubkey
    pub pk_cost: usize,
    /// Whether this fragment can be verify-wrapped for free
    pub has_free_verify: bool,
    /// The worst case static(unexecuted) ops-count for this Miniscript fragment.
    pub ops_count_static: usize,
    /// The worst case ops-count for satisfying this Miniscript fragment.
    pub ops_count_sat: Option<usize>,
    /// The worst case ops-count for dissatisfying this Miniscript fragment.
    pub ops_count_nsat: Option<usize>,
    /// The worst case number of stack elements for satisfying this Miniscript fragment.
    pub stack_elem_count_sat: Option<usize>,
    /// The worst case number of stack elements for dissatisfying this Miniscript fragment.
    pub stack_elem_count_dissat: Option<usize>,
    /// Maximum size, in bytes, of a satisfying witness. First elements is the cost for the
    /// witness stack, the second one is the cost for scriptSig.
    /// All signatures are assumed to be 73 bytes in size, including the
    /// length prefix (segwit) or push opcode (pre-segwit) and sighash
    /// postfix.
    pub max_sat_size: Option<(usize, usize)>,
    /// Maximum dissatisfaction cost, in bytes, of a Miniscript fragment. First elements is
    /// the cost for the witness stack, the second one is the cost for scriptSig.
    pub max_dissat_size: Option<(usize, usize)>,
    /// The timelock info about heightlocks and timelocks
    pub timelock_info: TimeLockInfo,
    /// Maximum stack + alt stack size during satisfaction execution
    /// This does **not** include initial witness elements. This element only captures
    /// the additional elements that are pushed during execution.
    pub exec_stack_elem_count_sat: Option<usize>,
    /// Maximum stack + alt stack size during dissat execution
    /// This does **not** include initial witness elements. This element only captures
    /// the additional elements that are pushed during execution.
    pub exec_stack_elem_count_dissat: Option<usize>,
}

impl Property for ExtData {
    fn sanity_checks(&self) {
        debug_assert_eq!(
            self.stack_elem_count_sat.is_some(),
            self.exec_stack_elem_count_sat.is_some()
        );
        debug_assert_eq!(
            self.stack_elem_count_dissat.is_some(),
            self.exec_stack_elem_count_dissat.is_some()
        );
    }

    fn from_true() -> Self {
        ExtData {
            pk_cost: 1,
            has_free_verify: false,
            ops_count_static: 0,
            ops_count_sat: Some(0),
            ops_count_nsat: None,
            stack_elem_count_sat: Some(0),
            stack_elem_count_dissat: None,
            max_sat_size: Some((0, 0)),
            max_dissat_size: None,
            timelock_info: TimeLockInfo::default(),
            exec_stack_elem_count_sat: Some(1),
            exec_stack_elem_count_dissat: None,
        }
    }

    fn from_false() -> Self {
        ExtData {
            pk_cost: 1,
            has_free_verify: false,
            ops_count_static: 0,
            ops_count_sat: None,
            ops_count_nsat: Some(0),
            stack_elem_count_sat: None,
            stack_elem_count_dissat: Some(0),
            max_sat_size: None,
            max_dissat_size: Some((0, 0)),
            timelock_info: TimeLockInfo::default(),
            exec_stack_elem_count_sat: None,
            exec_stack_elem_count_dissat: Some(1),
        }
    }

    fn from_pk_k() -> Self {
        ExtData {
            pk_cost: 34,
            has_free_verify: false,
            ops_count_static: 0,
            ops_count_sat: Some(0),
            ops_count_nsat: Some(0),
            stack_elem_count_sat: Some(1),
            stack_elem_count_dissat: Some(1),
            max_sat_size: Some((73, 73)),
            max_dissat_size: Some((1, 1)),
            timelock_info: TimeLockInfo::default(),
            exec_stack_elem_count_sat: Some(1), // pushes the pk
            exec_stack_elem_count_dissat: Some(1),
        }
    }

    fn from_pk_h() -> Self {
        ExtData {
            pk_cost: 24,
            has_free_verify: false,
            ops_count_static: 3,
            ops_count_sat: Some(3),
            ops_count_nsat: Some(3),
            stack_elem_count_sat: Some(2),
            stack_elem_count_dissat: Some(2),
            max_sat_size: Some((34 + 73, 34 + 73)),
            max_dissat_size: Some((35, 35)),
            timelock_info: TimeLockInfo::default(),
            exec_stack_elem_count_sat: Some(2), // dup and hash push
            exec_stack_elem_count_dissat: Some(2),
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
            pk_cost: num_cost + 34 * n + 1,
            has_free_verify: true,
            ops_count_static: 1,
            ops_count_sat: Some(n + 1),
            ops_count_nsat: Some(n + 1),
            stack_elem_count_sat: Some(k + 1),
            stack_elem_count_dissat: Some(k + 1),
            max_sat_size: Some((1 + 73 * k, 1 + 73 * k)),
            max_dissat_size: Some((1 + k, 1 + k)),
            timelock_info: TimeLockInfo::default(),
            exec_stack_elem_count_sat: Some(n), // n pks
            exec_stack_elem_count_dissat: Some(n),
        }
    }

    fn from_multi_a(k: usize, n: usize) -> Self {
        let num_cost = match (k > 16, n > 16) {
            (true, true) => 4,
            (false, true) => 3,
            (true, false) => 3,
            (false, false) => 2,
        };
        ExtData {
            pk_cost: num_cost + 33 * n /*pks*/ + (n-1) /*checksigadds*/ + 1,
            has_free_verify: true,
            ops_count_static: 1, // We don't care about opcounts in tapscript
            ops_count_sat: Some(n + 1),
            ops_count_nsat: Some(n + 1),
            stack_elem_count_sat: Some(n),
            stack_elem_count_dissat: Some(n),
            max_sat_size: Some(((n - k) + 64 * k, (n - k) + 64 * k)),
            max_dissat_size: Some((n, n)),
            timelock_info: TimeLockInfo::default(),
            exec_stack_elem_count_sat: Some(2), // the two nums before num equal verify
            exec_stack_elem_count_dissat: Some(2),
        }
    }

    fn from_hash() -> Self {
        //never called directly
        unreachable!()
    }

    fn from_sha256() -> Self {
        ExtData {
            pk_cost: 33 + 6,
            has_free_verify: true,
            ops_count_static: 4,
            ops_count_sat: Some(4),
            ops_count_nsat: Some(4),
            stack_elem_count_sat: Some(1),
            stack_elem_count_dissat: Some(1),
            max_sat_size: Some((33, 33)),
            max_dissat_size: Some((33, 33)),
            timelock_info: TimeLockInfo::default(),
            exec_stack_elem_count_sat: Some(2), // either size <32> or <hash256> <32 byte>
            exec_stack_elem_count_dissat: Some(2),
        }
    }

    fn from_txtemplate() -> Self {
        ExtData {
            pk_cost: 33 + 2,
            has_free_verify: false,
            ops_count_static: 3,
            ops_count_sat: Some(3),
            ops_count_nsat: None,
            max_sat_size: Some((0, 0)),
            stack_elem_count_sat: Some(0),
            stack_elem_count_dissat: None,
            max_dissat_size: None,
            // TODO: Correct this to read from the template
            timelock_info: TimeLockInfo::default(),
            exec_stack_elem_count_sat: Some(1),
            exec_stack_elem_count_dissat: None,
        }
    }

    fn from_hash256() -> Self {
        ExtData {
            pk_cost: 33 + 6,
            has_free_verify: true,
            ops_count_static: 4,
            ops_count_sat: Some(4),
            ops_count_nsat: Some(4),
            stack_elem_count_sat: Some(1),
            stack_elem_count_dissat: Some(1),
            max_sat_size: Some((33, 33)),
            max_dissat_size: Some((33, 33)),
            timelock_info: TimeLockInfo::default(),
            exec_stack_elem_count_sat: Some(2), // either size <32> or <hash256> <32 byte>
            exec_stack_elem_count_dissat: Some(2),
        }
    }

    fn from_ripemd160() -> Self {
        ExtData {
            pk_cost: 21 + 6,
            has_free_verify: true,
            ops_count_static: 4,
            ops_count_sat: Some(4),
            ops_count_nsat: Some(4),
            stack_elem_count_sat: Some(1),
            stack_elem_count_dissat: Some(1),
            max_sat_size: Some((33, 33)),
            max_dissat_size: Some((33, 33)),
            timelock_info: TimeLockInfo::default(),
            exec_stack_elem_count_sat: Some(2), // either size <32> or <hash256> <20 byte>
            exec_stack_elem_count_dissat: Some(2),
        }
    }

    fn from_hash160() -> Self {
        ExtData {
            pk_cost: 21 + 6,
            has_free_verify: true,
            ops_count_static: 4,
            ops_count_sat: Some(4),
            ops_count_nsat: Some(4),
            stack_elem_count_sat: Some(1),
            stack_elem_count_dissat: Some(1),
            max_sat_size: Some((33, 33)),
            max_dissat_size: Some((33, 33)),
            timelock_info: TimeLockInfo::default(),
            exec_stack_elem_count_sat: Some(2), // either size <32> or <hash256> <20 byte>
            exec_stack_elem_count_dissat: Some(2),
        }
    }

    fn from_time(_t: u32) -> Self {
        unreachable!()
    }

    fn from_after(t: u32) -> Self {
        ExtData {
            pk_cost: script_num_size(t as usize) + 1,
            has_free_verify: false,
            ops_count_static: 1,
            ops_count_sat: Some(1),
            ops_count_nsat: None,
            stack_elem_count_sat: Some(0),
            stack_elem_count_dissat: None,
            max_sat_size: Some((0, 0)),
            max_dissat_size: None,
            timelock_info: TimeLockInfo {
                csv_with_height: false,
                csv_with_time: false,
                cltv_with_height: t < HEIGHT_TIME_THRESHOLD,
                cltv_with_time: t >= HEIGHT_TIME_THRESHOLD,
                contains_combination: false,
            },
            exec_stack_elem_count_sat: Some(1), // <t>
            exec_stack_elem_count_dissat: None,
        }
    }

    fn from_older(t: u32) -> Self {
        ExtData {
            pk_cost: script_num_size(t as usize) + 1,
            has_free_verify: false,
            ops_count_static: 1,
            ops_count_sat: Some(1),
            ops_count_nsat: None,
            stack_elem_count_sat: Some(0),
            stack_elem_count_dissat: None,
            max_sat_size: Some((0, 0)),
            max_dissat_size: None,
            timelock_info: TimeLockInfo {
                csv_with_height: (t & SEQUENCE_LOCKTIME_TYPE_FLAG) == 0,
                csv_with_time: (t & SEQUENCE_LOCKTIME_TYPE_FLAG) != 0,
                cltv_with_height: false,
                cltv_with_time: false,
                contains_combination: false,
            },
            exec_stack_elem_count_sat: Some(1), // <t>
            exec_stack_elem_count_dissat: None,
        }
    }

    fn cast_alt(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 2,
            has_free_verify: false,
            ops_count_static: self.ops_count_static + 2,
            ops_count_sat: self.ops_count_sat.map(|x| x + 2),
            ops_count_nsat: self.ops_count_nsat.map(|x| x + 2),
            stack_elem_count_sat: self.stack_elem_count_sat,
            stack_elem_count_dissat: self.stack_elem_count_dissat,
            max_sat_size: self.max_sat_size,
            max_dissat_size: self.max_dissat_size,
            timelock_info: self.timelock_info,
            exec_stack_elem_count_sat: self.exec_stack_elem_count_sat,
            exec_stack_elem_count_dissat: self.exec_stack_elem_count_dissat,
        })
    }

    fn cast_swap(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 1,
            has_free_verify: self.has_free_verify,
            ops_count_static: self.ops_count_static + 1,
            ops_count_sat: self.ops_count_sat.map(|x| x + 1),
            ops_count_nsat: self.ops_count_nsat.map(|x| x + 1),
            stack_elem_count_sat: self.stack_elem_count_sat,
            stack_elem_count_dissat: self.stack_elem_count_dissat,
            max_sat_size: self.max_sat_size,
            max_dissat_size: self.max_dissat_size,
            timelock_info: self.timelock_info,
            exec_stack_elem_count_sat: self.exec_stack_elem_count_sat,
            exec_stack_elem_count_dissat: self.exec_stack_elem_count_dissat,
        })
    }

    fn cast_check(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 1,
            has_free_verify: true,
            ops_count_static: self.ops_count_static + 1,
            ops_count_sat: self.ops_count_sat.map(|x| x + 1),
            ops_count_nsat: self.ops_count_nsat.map(|x| x + 1),
            stack_elem_count_sat: self.stack_elem_count_sat,
            stack_elem_count_dissat: self.stack_elem_count_dissat,
            max_sat_size: self.max_sat_size,
            max_dissat_size: self.max_dissat_size,
            timelock_info: self.timelock_info,
            exec_stack_elem_count_sat: self.exec_stack_elem_count_sat,
            exec_stack_elem_count_dissat: self.exec_stack_elem_count_dissat,
        })
    }

    fn cast_dupif(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 3,
            has_free_verify: false,
            ops_count_static: self.ops_count_static + 3,
            ops_count_sat: self.ops_count_sat.map(|x| x + 3),
            ops_count_nsat: Some(self.ops_count_static + 3),
            stack_elem_count_sat: self.stack_elem_count_sat.map(|x| x + 1),
            stack_elem_count_dissat: Some(1),
            max_sat_size: self.max_sat_size.map(|(w, s)| (w + 2, s + 1)),
            max_dissat_size: Some((1, 1)),
            timelock_info: self.timelock_info,
            // Technically max(1, self.exec_stack_elem_count_sat), but all miniscript expressions
            // that can be satisfied push at least one thing onto the stack.
            // Even all V types push something onto the stack and then remove them
            exec_stack_elem_count_sat: self.exec_stack_elem_count_sat,
            exec_stack_elem_count_dissat: Some(1),
        })
    }

    fn cast_verify(self) -> Result<Self, ErrorKind> {
        let verify_cost = if self.has_free_verify { 0 } else { 1 };
        Ok(ExtData {
            pk_cost: self.pk_cost + if self.has_free_verify { 0 } else { 1 },
            has_free_verify: false,
            ops_count_static: self.ops_count_static + verify_cost,
            ops_count_sat: self.ops_count_sat.map(|x| x + verify_cost),
            ops_count_nsat: None,
            stack_elem_count_sat: self.stack_elem_count_sat,
            stack_elem_count_dissat: None,
            max_sat_size: self.max_sat_size,
            max_dissat_size: None,
            timelock_info: self.timelock_info,
            exec_stack_elem_count_sat: self.exec_stack_elem_count_sat,
            exec_stack_elem_count_dissat: None,
        })
    }

    fn cast_nonzero(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 4,
            has_free_verify: false,
            ops_count_static: self.ops_count_static + 4,
            ops_count_sat: self.ops_count_sat.map(|x| x + 4),
            ops_count_nsat: Some(self.ops_count_static + 4),
            stack_elem_count_sat: self.stack_elem_count_sat,
            stack_elem_count_dissat: Some(1),
            max_sat_size: self.max_sat_size,
            max_dissat_size: Some((1, 1)),
            timelock_info: self.timelock_info,
            exec_stack_elem_count_sat: self.exec_stack_elem_count_sat,
            exec_stack_elem_count_dissat: Some(1),
        })
    }

    fn cast_zeronotequal(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 1,
            has_free_verify: false,
            ops_count_static: self.ops_count_static + 1,
            ops_count_sat: self.ops_count_sat.map(|x| x + 1),
            ops_count_nsat: self.ops_count_nsat.map(|x| x + 1),
            stack_elem_count_sat: self.stack_elem_count_sat,
            stack_elem_count_dissat: self.stack_elem_count_dissat,
            max_sat_size: self.max_sat_size,
            max_dissat_size: self.max_dissat_size,
            timelock_info: self.timelock_info,
            // Technically max(1, self.exec_stack_elem_count_sat), same rationale as cast_dupif
            exec_stack_elem_count_sat: self.exec_stack_elem_count_sat,
            exec_stack_elem_count_dissat: self.exec_stack_elem_count_dissat,
        })
    }

    fn cast_true(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 1,
            has_free_verify: false,
            ops_count_static: self.ops_count_static,
            ops_count_sat: self.ops_count_sat,
            ops_count_nsat: None,
            stack_elem_count_sat: self.stack_elem_count_sat,
            stack_elem_count_dissat: None,
            max_sat_size: self.max_sat_size,
            max_dissat_size: None,
            timelock_info: self.timelock_info,
            // Technically max(1, self.exec_stack_elem_count_sat), same rationale as cast_dupif
            exec_stack_elem_count_sat: self.exec_stack_elem_count_sat,
            exec_stack_elem_count_dissat: None,
        })
    }

    fn cast_or_i_false(self) -> Result<Self, ErrorKind> {
        // never called directly
        unreachable!()
    }

    fn cast_unlikely(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 4,
            has_free_verify: false,
            ops_count_static: self.ops_count_static + 3,
            ops_count_sat: self.ops_count_sat.map(|x| x + 3),
            ops_count_nsat: Some(self.ops_count_static + 3),
            stack_elem_count_sat: self.stack_elem_count_sat.map(|x| x + 1),
            stack_elem_count_dissat: self.stack_elem_count_dissat.map(|x| x + 1),
            max_sat_size: self.max_sat_size.map(|(w, s)| (w + 2, s + 1)),
            max_dissat_size: self.max_dissat_size.map(|(w, s)| (w + 1, s + 1)),
            // TODO: fix dissat stack elem counting above in a later commit
            // Technically max(1, self.exec_stack_elem_count_sat), same rationale as cast_dupif
            exec_stack_elem_count_sat: self.exec_stack_elem_count_sat,
            exec_stack_elem_count_dissat: self.exec_stack_elem_count_dissat,
            timelock_info: self.timelock_info,
        })
    }

    fn cast_likely(self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: self.pk_cost + 4,
            has_free_verify: false,
            ops_count_static: self.ops_count_static + 3,
            ops_count_sat: self.ops_count_sat.map(|x| x + 3),
            ops_count_nsat: Some(self.ops_count_static + 3),
            stack_elem_count_sat: self.stack_elem_count_sat.map(|x| x + 1),
            stack_elem_count_dissat: self.stack_elem_count_dissat.map(|x| x + 1),
            max_sat_size: self.max_sat_size.map(|(w, s)| (w + 1, s + 1)),
            max_dissat_size: self.max_dissat_size.map(|(w, s)| (w + 2, s + 1)),
            timelock_info: self.timelock_info,
            // TODO: fix dissat stack elem counting above in a later commit
            // Technically max(1, self.exec_stack_elem_count_sat), same rationale as cast_dupif
            exec_stack_elem_count_sat: self.exec_stack_elem_count_sat,
            exec_stack_elem_count_dissat: self.exec_stack_elem_count_dissat,
        })
    }

    fn and_b(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: l.pk_cost + r.pk_cost + 1,
            has_free_verify: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 1,
            ops_count_sat: l
                .ops_count_sat
                .and_then(|x| r.ops_count_sat.map(|y| x + y + 1)),
            ops_count_nsat: l
                .ops_count_nsat
                .and_then(|x| r.ops_count_nsat.map(|y| x + y + 1)),
            stack_elem_count_sat: l
                .stack_elem_count_sat
                .and_then(|l| r.stack_elem_count_sat.map(|r| l + r)),
            stack_elem_count_dissat: l
                .stack_elem_count_dissat
                .and_then(|l| r.stack_elem_count_dissat.map(|r| l + r)),
            max_sat_size: l
                .max_sat_size
                .and_then(|(lw, ls)| r.max_sat_size.map(|(rw, rs)| (lw + rw, ls + rs))),
            max_dissat_size: l
                .max_dissat_size
                .and_then(|(lw, ls)| r.max_dissat_size.map(|(rw, rs)| (lw + rw, ls + rs))),
            timelock_info: TimeLockInfo::comb_and_timelocks(l.timelock_info, r.timelock_info),
            // Left element leaves a stack result on the stack top and then right element is evaluated
            // Therefore + 1 is added to execution size of second element
            exec_stack_elem_count_sat: opt_max(
                l.exec_stack_elem_count_sat,
                r.exec_stack_elem_count_sat.map(|x| x + 1),
            ),
            exec_stack_elem_count_dissat: opt_max(
                l.exec_stack_elem_count_dissat,
                r.exec_stack_elem_count_dissat.map(|x| x + 1),
            ),
        })
    }

    fn and_v(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: l.pk_cost + r.pk_cost,
            has_free_verify: r.has_free_verify,
            ops_count_static: l.ops_count_static + r.ops_count_static,
            ops_count_sat: l.ops_count_sat.and_then(|x| r.ops_count_sat.map(|y| x + y)),
            ops_count_nsat: None,
            stack_elem_count_sat: l
                .stack_elem_count_sat
                .and_then(|l| r.stack_elem_count_sat.map(|r| l + r)),
            stack_elem_count_dissat: None,
            max_sat_size: l
                .max_sat_size
                .and_then(|(lw, ls)| r.max_sat_size.map(|(rw, rs)| (lw + rw, ls + rs))),
            max_dissat_size: None,
            timelock_info: TimeLockInfo::comb_and_timelocks(l.timelock_info, r.timelock_info),
            // [X] leaves no element after evaluation, hence this is the max
            exec_stack_elem_count_sat: opt_max(
                l.exec_stack_elem_count_sat,
                r.exec_stack_elem_count_sat,
            ),
            exec_stack_elem_count_dissat: None,
        })
    }

    fn or_b(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: l.pk_cost + r.pk_cost + 1,
            has_free_verify: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 1,
            ops_count_sat: cmp::max(
                l.ops_count_sat
                    .and_then(|x| r.ops_count_nsat.map(|y| y + x + 1)),
                r.ops_count_sat
                    .and_then(|x| l.ops_count_nsat.map(|y| y + x + 1)),
            ),
            ops_count_nsat: l
                .ops_count_nsat
                .and_then(|x| r.ops_count_nsat.map(|y| x + y + 1)),
            stack_elem_count_sat: cmp::max(
                l.stack_elem_count_sat
                    .and_then(|l| r.stack_elem_count_dissat.map(|r| l + r)),
                l.stack_elem_count_dissat
                    .and_then(|l| r.stack_elem_count_sat.map(|r| l + r)),
            ),
            stack_elem_count_dissat: l
                .stack_elem_count_dissat
                .and_then(|l| r.stack_elem_count_dissat.map(|r| l + r)),
            max_sat_size: cmp::max(
                l.max_sat_size
                    .and_then(|(lw, ls)| r.max_dissat_size.map(|(rw, rs)| (lw + rw, ls + rs))),
                l.max_dissat_size
                    .and_then(|(lw, ls)| r.max_sat_size.map(|(rw, rs)| (lw + rw, ls + rs))),
            ),
            max_dissat_size: l
                .max_dissat_size
                .and_then(|(lw, ls)| r.max_dissat_size.map(|(rw, rs)| (lw + rw, ls + rs))),
            timelock_info: TimeLockInfo::comb_or_timelocks(l.timelock_info, r.timelock_info),
            exec_stack_elem_count_sat: cmp::max(
                opt_max(
                    l.exec_stack_elem_count_sat,
                    r.exec_stack_elem_count_dissat.map(|x| x + 1),
                ),
                opt_max(
                    l.exec_stack_elem_count_dissat,
                    r.exec_stack_elem_count_sat.map(|x| x + 1),
                ),
            ),
            exec_stack_elem_count_dissat: opt_max(
                l.exec_stack_elem_count_dissat,
                r.exec_stack_elem_count_dissat.map(|x| x + 1),
            ),
        })
    }

    fn or_d(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: l.pk_cost + r.pk_cost + 3,
            has_free_verify: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 1,
            ops_count_sat: cmp::max(
                l.ops_count_sat.map(|x| x + 3 + r.ops_count_static),
                r.ops_count_sat
                    .and_then(|x| l.ops_count_nsat.map(|y| y + x + 3)),
            ),
            ops_count_nsat: l
                .ops_count_nsat
                .and_then(|x| r.ops_count_nsat.map(|y| x + y + 3)),
            stack_elem_count_sat: cmp::max(
                l.stack_elem_count_sat,
                l.stack_elem_count_dissat
                    .and_then(|l_dis| r.stack_elem_count_sat.map(|r_sat| r_sat + l_dis)),
            ),
            stack_elem_count_dissat: l
                .stack_elem_count_dissat
                .and_then(|l_dis| r.stack_elem_count_dissat.map(|r_dis| r_dis + l_dis)),
            max_sat_size: cmp::max(
                l.max_sat_size,
                l.max_dissat_size
                    .and_then(|(lw, ls)| r.max_sat_size.map(|(rw, rs)| (lw + rw, ls + rs))),
            ),
            max_dissat_size: l
                .max_dissat_size
                .and_then(|(lw, ls)| r.max_dissat_size.map(|(rw, rs)| (lw + rw, ls + rs))),
            timelock_info: TimeLockInfo::comb_or_timelocks(l.timelock_info, r.timelock_info),
            exec_stack_elem_count_sat: cmp::max(
                opt_max(l.exec_stack_elem_count_sat, r.exec_stack_elem_count_dissat),
                r.exec_stack_elem_count_sat,
            ),
            exec_stack_elem_count_dissat: opt_max(
                l.exec_stack_elem_count_dissat,
                r.exec_stack_elem_count_dissat.map(|x| x + 1),
            ),
        })
    }

    fn or_c(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: l.pk_cost + r.pk_cost + 2,
            has_free_verify: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 2,
            ops_count_sat: cmp::max(
                l.ops_count_sat.map(|x| x + 2 + r.ops_count_static),
                r.ops_count_sat
                    .and_then(|x| l.ops_count_nsat.map(|y| y + x + 2)),
            ),
            ops_count_nsat: None,
            stack_elem_count_sat: cmp::max(
                l.stack_elem_count_sat,
                l.stack_elem_count_dissat
                    .and_then(|l_dis| r.stack_elem_count_sat.map(|r_sat| r_sat + l_dis)),
            ),
            stack_elem_count_dissat: None,
            max_sat_size: cmp::max(
                l.max_sat_size,
                l.max_dissat_size
                    .and_then(|(lw, ls)| r.max_sat_size.map(|(rw, rs)| (lw + rw, ls + rs))),
            ),
            max_dissat_size: None,
            timelock_info: TimeLockInfo::comb_or_timelocks(l.timelock_info, r.timelock_info),
            exec_stack_elem_count_sat: cmp::max(
                opt_max(l.exec_stack_elem_count_sat, r.exec_stack_elem_count_dissat),
                r.exec_stack_elem_count_sat,
            ),
            exec_stack_elem_count_dissat: None,
        })
    }

    fn or_i(l: Self, r: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: l.pk_cost + r.pk_cost + 3,
            has_free_verify: false,
            ops_count_static: l.ops_count_static + r.ops_count_static + 3,
            ops_count_sat: cmp::max(
                l.ops_count_sat.map(|x| x + 3 + r.ops_count_static),
                r.ops_count_sat.map(|x| x + 3 + l.ops_count_static),
            ),
            ops_count_nsat: match (l.ops_count_nsat, r.ops_count_nsat) {
                (Some(a), Some(b)) => Some(cmp::max(a, b) + 3),
                (_, Some(x)) | (Some(x), _) => Some(x + 3),
                (None, None) => None,
            },
            stack_elem_count_sat: match (l.stack_elem_count_sat, r.stack_elem_count_sat) {
                (Some(l), Some(r)) => Some(1 + cmp::max(l, r)),
                (Some(l), None) => Some(1 + l),
                (None, Some(r)) => Some(1 + r),
                (None, None) => None,
            },
            stack_elem_count_dissat: match (l.stack_elem_count_dissat, r.stack_elem_count_dissat) {
                (Some(l), Some(r)) => Some(1 + cmp::max(l, r)),
                (Some(l), None) => Some(1 + l),
                (None, Some(r)) => Some(1 + r),
                (None, None) => None,
            },
            max_sat_size: cmp::max(
                l.max_sat_size.and_then(|(w, s)| Some((w + 2, s + 1))),
                r.max_sat_size.and_then(|(w, s)| Some((w + 1, s + 1))),
            ),
            max_dissat_size: match (l.max_dissat_size, r.max_dissat_size) {
                (Some(l), Some(r)) => {
                    let max = cmp::max(l, r);
                    Some((1 + max.0, 1 + max.1))
                }
                (None, Some(r)) => Some((1 + r.0, 1 + r.1)),
                (Some(l), None) => Some((2 + l.0, 1 + l.1)),
                (None, None) => None,
            },
            timelock_info: TimeLockInfo::comb_or_timelocks(l.timelock_info, r.timelock_info),
            // TODO: fix elem count dissat bug
            exec_stack_elem_count_sat: cmp::max(
                l.exec_stack_elem_count_sat,
                r.exec_stack_elem_count_sat,
            ),
            exec_stack_elem_count_dissat: cmp::max(
                l.exec_stack_elem_count_dissat,
                r.exec_stack_elem_count_dissat,
            ),
        })
    }

    fn and_or(a: Self, b: Self, c: Self) -> Result<Self, ErrorKind> {
        Ok(ExtData {
            pk_cost: a.pk_cost + b.pk_cost + c.pk_cost + 3,
            has_free_verify: false,
            ops_count_static: a.ops_count_static + b.ops_count_static + c.ops_count_static + 3,
            ops_count_sat: cmp::max(
                a.ops_count_sat
                    .and_then(|x| b.ops_count_sat.map(|y| x + y + c.ops_count_static + 3)),
                c.ops_count_sat
                    .and_then(|z| a.ops_count_nsat.map(|y| y + z + b.ops_count_static + 3)),
            ),
            ops_count_nsat: c
                .ops_count_nsat
                .and_then(|z| a.ops_count_nsat.map(|x| x + b.ops_count_static + z + 3)),
            stack_elem_count_sat: cmp::max(
                a.stack_elem_count_sat
                    .and_then(|a| b.stack_elem_count_sat.map(|b| b + a)),
                a.stack_elem_count_dissat
                    .and_then(|a_dis| c.stack_elem_count_sat.map(|c| c + a_dis)),
            ),
            stack_elem_count_dissat: a
                .stack_elem_count_dissat
                .and_then(|a_dis| c.stack_elem_count_dissat.map(|c| c + a_dis)),
            max_sat_size: cmp::max(
                a.max_sat_size
                    .and_then(|(wa, sa)| b.max_sat_size.map(|(wb, sb)| (wa + wb, sa + sb))),
                a.max_dissat_size
                    .and_then(|(wa, sa)| c.max_sat_size.map(|(wc, sc)| (wa + wc, sa + sc))),
            ),
            max_dissat_size: a
                .max_dissat_size
                .and_then(|(wa, sa)| c.max_dissat_size.map(|(wc, sc)| (wa + wc, sa + sc))),
            timelock_info: TimeLockInfo::comb_or_timelocks(
                TimeLockInfo::comb_and_timelocks(a.timelock_info, b.timelock_info),
                c.timelock_info,
            ),
            exec_stack_elem_count_sat: cmp::max(
                opt_max(a.exec_stack_elem_count_sat, b.exec_stack_elem_count_sat),
                opt_max(c.exec_stack_elem_count_sat, a.exec_stack_elem_count_dissat),
            ),
            exec_stack_elem_count_dissat: opt_max(
                a.exec_stack_elem_count_dissat,
                c.exec_stack_elem_count_dissat,
            ),
        })
    }

    fn threshold<S>(k: usize, n: usize, mut sub_ck: S) -> Result<Self, ErrorKind>
    where
        S: FnMut(usize) -> Result<Self, ErrorKind>,
    {
        let mut pk_cost = 1 + script_num_size(k); //Equal and k
        let mut ops_count_static = 0 as usize;
        let mut ops_count_sat_vec = Vec::with_capacity(n);
        let mut ops_count_nsat_sum = 0 as usize;
        let mut ops_count_nsat = Some(0);
        let mut ops_count_sat = Some(0);
        let mut sat_count = 0;
        let mut timelocks = Vec::with_capacity(n);
        let mut stack_elem_count_sat_vec = Vec::with_capacity(n);
        let mut stack_elem_count_sat = Some(0);
        let mut stack_elem_count_dissat = Some(0);
        let mut max_sat_size_vec = Vec::with_capacity(n);
        let mut max_sat_size = Some((0, 0));
        let mut max_dissat_size = Some((0, 0));
        // the max element count is same as max sat element count when satisfying one element + 1
        let mut exec_stack_elem_count_sat_vec = Vec::with_capacity(n);
        let mut exec_stack_elem_count_sat = Some(0);
        let mut exec_stack_elem_count_dissat = Some(0);

        for i in 0..n {
            let sub = sub_ck(i)?;

            pk_cost += sub.pk_cost;
            ops_count_static += sub.ops_count_static;
            timelocks.push(sub.timelock_info);

            if let Some(n_items) = sub.stack_elem_count_dissat {
                stack_elem_count_dissat = stack_elem_count_dissat.map(|x| x + n_items);
                let sub_dissat_size = sub
                    .max_dissat_size
                    .expect("dissat_size is None but not stack_elem?");
                max_dissat_size =
                    max_dissat_size.map(|(w, s)| (w + sub_dissat_size.0, s + sub_dissat_size.1));
            } else {
                // The thresh is dissatifiable iff all sub policies are dissatifiable
                stack_elem_count_dissat = None;
            }
            stack_elem_count_sat_vec.push((sub.stack_elem_count_sat, sub.stack_elem_count_dissat));
            max_sat_size_vec.push((sub.max_sat_size, sub.max_sat_size));

            match (sub.ops_count_sat, sub.ops_count_nsat) {
                (Some(x), Some(y)) => {
                    ops_count_sat_vec.push(Some(x as i32 - y as i32));
                    ops_count_nsat = ops_count_nsat.map(|v| y + v);
                    ops_count_nsat_sum = ops_count_nsat_sum + y;
                }
                (Some(x), None) => {
                    sat_count = sat_count + 1;
                    ops_count_sat = ops_count_sat.map(|y| x + y);
                    ops_count_nsat = None;
                }
                _ => {}
            }
            exec_stack_elem_count_sat_vec.push((
                sub.exec_stack_elem_count_sat,
                sub.exec_stack_elem_count_dissat,
            ));
            exec_stack_elem_count_dissat = opt_max(
                exec_stack_elem_count_dissat,
                sub.exec_stack_elem_count_dissat,
            );
        }

        // We sort by [satisfaction cost - dissatisfaction cost] to make a worst-case (the most
        // costy satisfaction are satisfied, the most costy dissatisfactions are dissatisfied)
        // sum of the cost by iterating through the sorted vector *backward*.
        stack_elem_count_sat_vec.sort_by(|a, b| {
            a.0.map(|x| a.1.map(|y| x as isize - y as isize))
                .cmp(&b.0.map(|x| b.1.map(|y| x as isize - y as isize)))
        });
        for (i, &(x, y)) in stack_elem_count_sat_vec.iter().rev().enumerate() {
            stack_elem_count_sat = if i <= k {
                x.and_then(|x| stack_elem_count_sat.map(|count| count + x))
            } else {
                y.and_then(|y| stack_elem_count_sat.map(|count| count + y))
            };
        }

        // Same logic as above
        exec_stack_elem_count_sat_vec.sort_by(|a, b| {
            a.0.map(|x| a.1.map(|y| x as isize - y as isize))
                .cmp(&b.0.map(|x| b.1.map(|y| x as isize - y as isize)))
        });
        for (i, &(x, y)) in exec_stack_elem_count_sat_vec.iter().rev().enumerate() {
            exec_stack_elem_count_sat = if i <= k {
                opt_max(exec_stack_elem_count_sat, x)
            } else {
                opt_max(exec_stack_elem_count_sat, y)
            };
        }

        // Same for the size cost. A bit more intricated as we need to account for both the witness
        // and scriptSig cost, so we end up with a tuple of Options of tuples. We use the witness
        // cost (first element of the mentioned tuple) here.
        // FIXME: Maybe make the ExtData struct aware of Ctx and add a one_cost() method here ?
        max_sat_size_vec.sort_by(|a, b| {
            a.0.map(|x| a.1.map(|y| x.0 as isize - y.0 as isize))
                .cmp(&b.0.map(|x| b.1.map(|y| x.0 as isize - y.0 as isize)))
        });
        for (i, &(x, y)) in max_sat_size_vec.iter().enumerate() {
            max_sat_size = if i <= k {
                x.and_then(|x| max_sat_size.map(|(w, s)| (w + x.0, s + x.1)))
            } else {
                y.and_then(|y| max_sat_size.map(|(w, s)| (w + y.0, s + y.1)))
            };
        }

        let remaining_sat = k - sat_count;
        let mut sum: i32 = 0;
        if k < sat_count || ops_count_sat_vec.len() < remaining_sat {
            ops_count_sat = None;
        } else {
            ops_count_sat_vec.sort();
            ops_count_sat_vec.reverse();
            sum = ops_count_sat_vec
                .split_off(remaining_sat)
                .iter()
                .map(|z| z.unwrap())
                .sum();
        }
        Ok(ExtData {
            pk_cost: pk_cost + n - 1, //all pk cost + (n-1)*ADD
            has_free_verify: true,
            ops_count_static: ops_count_static + (n - 1) + 1, //adds and equal
            ops_count_sat: ops_count_sat
                .map(|x: usize| (x + (n - 1) + 1 + (sum + ops_count_nsat_sum as i32) as usize)), //adds and equal
            ops_count_nsat: ops_count_nsat.map(|x| x + (n - 1) + 1), //adds and equal
            stack_elem_count_sat,
            stack_elem_count_dissat,
            max_sat_size,
            max_dissat_size,
            timelock_info: TimeLockInfo::combine_thresh_timelocks(k, timelocks),
            exec_stack_elem_count_sat,
            exec_stack_elem_count_dissat,
        })
    }

    /// Compute the type of a fragment assuming all the children of
    /// Miniscript have been computed already.
    fn type_check<Pk, Ctx, C>(
        fragment: &Terminal<Pk, Ctx>,
        _child: C,
    ) -> Result<Self, Error<Pk, Ctx>>
    where
        C: FnMut(usize) -> Option<Self>,
        Ctx: ScriptContext,
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
            Terminal::PkK(..) => Ok(Self::from_pk_k()),
            Terminal::PkH(..) => Ok(Self::from_pk_h()),
            Terminal::Multi(k, ref pks) | Terminal::MultiA(k, ref pks) => {
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
                match *fragment {
                    Terminal::Multi(..) => Ok(Self::from_multi(k, pks.len())),
                    Terminal::MultiA(..) => Ok(Self::from_multi_a(k, pks.len())),
                    _ => unreachable!(),
                }
            }
            Terminal::After(t) => {
                // Note that for CLTV this is a limitation not of Bitcoin but Miniscript. The
                // number on the stack would be a 5 bytes signed integer but Miniscript's B type
                // only consumes 4 bytes from the stack.
                if t == 0 || (t & SEQUENCE_LOCKTIME_DISABLE_FLAG) == 1 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::InvalidTime,
                    });
                }
                Ok(Self::from_after(t))
            }
            Terminal::Older(t) => {
                if t == 0 || (t & SEQUENCE_LOCKTIME_DISABLE_FLAG) == 1 {
                    return Err(Error {
                        fragment: fragment.clone(),
                        error: ErrorKind::InvalidTime,
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
            Terminal::TxTemplate(..) => Ok(Self::from_txtemplate()),
        };
        if let Ok(ref ret) = ret {
            ret.sanity_checks()
        }
        ret
    }
}

// Returns Some(max(x,y)) is both x and y are Some. Otherwise, return none
fn opt_max<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    if let (Some(x), Some(y)) = (a, b) {
        Some(cmp::max(x, y))
    } else {
        None
    }
}
