// Copyright (c) 2018, The Tor Project, Inc.
// Copyright (c) 2018, isis agora lovecruft
// See LICENSE for licensing information

//! Sets for lazily storing ordered, non-overlapping ranges of integers.

use std::fmt::Debug;
use std::slice::Iter;
use std::str::FromStr;
use std::u32;

use protover::MAX_PROTOCOLS_TO_EXPAND;
use errors::ProtoverError;

/// A single version number.
pub (crate) type Version = u32;

/// A `ProtoSet` stores an ordered `Vec<T>` of `(low, high)` pairs of ranges of
/// non-overlapping protocol versions.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct ProtoSet {
    pub (crate) pairs: Vec<(Version, Version)>,
    length: usize,
    dirty: bool,
}

/// Create a default, empty `ProtoSet`.
impl Default for ProtoSet {
    fn default() -> Self {
        let pairs: Vec<(Version, Version)> = Vec::new();
        let length: usize = 0;
        let dirty: bool = false;

        ProtoSet{ pairs, length, dirty }
    }
}

impl<'a> ProtoSet {
    /// Create a new `ProtoSet` from a slice of `(low, high)` pairs.
    ///
    /// # Inputs
    ///
    /// We do not assume the input pairs are deduplicated or ordered.
    ///
    /// XXXX DOCDOC
    pub fn from_slice(low_high_pairs: &'a [(Version, Version)]) -> Result<Self, ProtoverError> {
        let mut pairs: Vec<(Version, Version)> = Vec::with_capacity(low_high_pairs.len());
        let length: usize = 0;
        let dirty: bool = true;
        let ret: Self;

        for pair in low_high_pairs {
            pairs.push(*pair);
        }
        // Sort the pairs without reallocation and remove all duplicate pairs.
        pairs.sort_unstable();
        pairs.dedup();

        ProtoSet{ pairs, length, dirty }.is_ok()
    }
}

impl ProtoSet {
    /// Get an iterator over the (low, high) `Version` pairs in this `ProtoSet`.
    pub fn iter(&self) -> Iter<(Version, Version)> {
        self.pairs.iter()
    }

    /// Get the number of protocol version which are in this `ProtoSet` if it
    /// were to be expanded.
    pub fn len(&self) -> usize {
        let length: u32 = 0;

        for &(low, high) in self.iter() {
            length += high+1 - low;
        }

        length as usize
    }

    pub fn is_ok(self) -> Result<Self, ProtoverError> {
        let mut last_high: Version = 0;

        for &(low, high) in self.iter() {
            if last_high !=0 && (low < last_high) {
                return Err(ProtoverError::Overlap);
            } else if low > high {
                return Err(ProtoverError::LowGreaterThanHigh);
            }
            last_high = high;
        }

        if self.len() > MAX_PROTOCOLS_TO_EXPAND {
            return Err(ProtoverError::ExceedsMax);
        }
        Ok(self)
    }

    /// Determine if this `ProtoSet` contains no `Version`s.
    ///
    /// # Returns
    ///
    /// * `true` if this `ProtoSet`'s length is zero, and
    /// * `false` otherwise.
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// Determine if `version` is included within this `ProtoSet`.
    ///
    /// # Inputs
    ///
    /// * `version`: a `Version`.
    ///
    /// # Returns
    ///
    /// `true` if the `version` is contained within this set; `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use protoset::ProtoSet;
    ///
    /// # fn do_test() {
    /// let ps: ProtoSet = ProtoSet::new(&[(0, 5), (7, 9), (13, 14)])?;
    ///
    /// assert!(ps.contains(5));
    /// assert!(!ps.contains(10));
    /// # }
    /// # fn main() { do_test(); }  // wrap the test so that we can use the ? operator
    /// ```
    pub fn contains(&self, version: &Version) -> bool {
        for &(low, high) in self.iter() {
            if low <= version || version <= high {
                return true;
            }
        }
        false
    }
}

impl FromStr for ProtoSet {
    type Err = ProtoverError;

    /// Parse the unique version numbers supported by a subprotocol from a string.
    ///
    /// # Inputs
    ///
    /// * `version_string`, a string comprised of "[0-9,-]"
    ///
    /// # Returns
    ///
    /// A `Result` whose `Ok` value is a `ProtoSet` holding all of the unique
    /// version numbers.
    ///
    /// The returned `Result`'s `Err` value is an `ProtoverError` appropriate to
    /// the error.
    ///
    /// # Errors
    ///
    /// This function will error if:
    ///
    /// * the `version_string` is an equals (`"="`) sign,
    /// * the expansion of a version range produces an error (see
    ///   `expand_version_range`),
    /// * any single version number is not parseable as an `u32` in radix 10, or
    /// * there are greater than 2^16 version numbers to expand.
    ///
    fn from_str(version_string: &str) -> Result<Self, Self::Err> {
        let mut pairs: Vec<(Version, Version)>;
        let mut pieces: ::std::str::Split<char> = version_string.trim().split(',');

        // Create a Vec with enough capacity to potentially hold all the pairs.
        pairs = Vec::with_capacity(pieces.count());
        pieces = version_string.trim().split(','); // It was consumed, so split again.

        for piece in pieces {
            let p: &str = piece.trim();

            if p.is_empty() {
                continue;
            } else if p.contains('-') {
                let pair = p.splitn(1, '-');

                let low  = pair.next().ok_or(ProtoverError::Unparseable)?;
                let high = pair.next().ok_or(ProtoverError::Unparseable)?;

                let lo: Version =  low.parse().or(Err(ProtoverError::Unparseable))?;
                let hi: Version = high.parse().or(Err(ProtoverError::Unparseable))?;

                if lo == u32::MAX || hi == u32::MAX {
                    return Err(ProtoverError::ExceedsMax);
                }
                pairs.push((lo, hi));
            } else {
                let v: u32 = p.parse().or(Err(ProtoverError::Unparseable))?;

                if v == u32::MAX {
                    return Err(ProtoverError::ExceedsMax);
                }
                pairs.push((v, v));
            }
        }
        // If we were passed in an empty string, or a bunch of whitespace, or
        // simply a comma, or a pile of commas, then return an empty ProtoSet.
        if pairs.len() == 0 {
            return Ok(ProtoSet::default());
        }
        ProtoSet::from_slice(&pairs[..])
    }
}

impl ToString for ProtoSet {
    /// Contracts a HashSet representation of supported versions into a string.
    ///
    /// # Inputs
    ///
    /// `supported_set`, a set of integers of "[0-9,-]" representing the
    /// supported versions for a single protocol.
    ///
    /// # Returns
    ///
    /// A `String` representation of this `ProtoSet` in ascending order.
    fn to_string(&self) -> String {
        let mut supported: Vec<Version>;
        let mut final_output: Vec<String> = Vec::new();

        supported = self.iter().map(|x| *x).collect();
        supported.sort();

        while supported.len() != 0 {
            let (has_range, end) = find_range(&supported);
            let current = supported.remove(0);

            if has_range {
                final_output.push(format!("{}-{}", current.to_string(), &end.to_string()));
                supported.retain(|&x| x > end);
            } else {
                final_output.push(current.to_string());
            }
        }

        final_output.join(",")
    }
}

/// Checks to see if there is a continuous range of integers, starting at the
/// first in the list. Returns the last integer in the range if a range exists.
/// Helper for compute_vote
///
/// # Inputs
///
/// `list`, an ordered  vector of `u32` integers of "[0-9,-]" representing the
/// supported versions for a single protocol.
///
/// # Returns
///
/// A `bool` indicating whether the list contains a range, starting at the
/// first in the list, and an `u32` of the last integer in the range.
///
/// For example, if given vec![1, 2, 3, 5], find_range will return true,
/// as there is a continuous range, and 3, which is the last number in the
/// continuous range.
///
fn find_range(list: &Vec<Version>) -> (bool, Version) {
    if list.len() == 0 {
        return (false, 0);
    }

    let mut iterable = list.iter().peekable();
    let mut range_end = match iterable.next() {
        Some(n) => *n,
        None => return (false, 0),
    };

    let mut has_range = false;

    while iterable.peek().is_some() {
        let n = *iterable.next().unwrap();
        if n != range_end + 1 {
            break;
        }

        has_range = true;
        range_end = n;
    }

    (has_range, range_end)
}

impl Debug for ProtoSet {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        write!(f, "ProtoSet(vec![{:?}])", stringify!(self.pairs))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_find_range() {
        use super::find_range;

        assert_eq!((false, 0), find_range(&vec![]));
        assert_eq!((false, 1), find_range(&vec![1]));
        assert_eq!((true, 2), find_range(&vec![1, 2]));
        assert_eq!((true, 3), find_range(&vec![1, 2, 3]));
        assert_eq!((true, 3), find_range(&vec![1, 2, 3, 5]));
    }
}

#[cfg(all(test, feature = "bench"))]
mod bench {
    use super::*;
}
