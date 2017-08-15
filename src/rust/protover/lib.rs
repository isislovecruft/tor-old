// Copyright (c) 2016-2017, The Tor Project, Inc.
// See LICENSE for licensing information

#![feature(inclusive_range)]
#![feature(inclusive_range_syntax)]

//! Versioning information for different pieces of the Tor protocol.
//!
//! Starting in version 0.2.9.3-alpha, Tor places separate version numbers on
//! each of the different components of its protocol. Relays use these numbers
//! to advertise what versions of the protocols they can support, and clients
//! use them to find what they can ask a given relay to do.  Authorities vote
//! on the supported protocol versions for each relay, and also vote on the
//! which protocols you should have to support in order to be on the Tor
//! network. All Tor instances use these required/recommended protocol versions
//! to tell what level of support for recent protocols each relay has, and
//! to decide whether they should be running given their current protocols.
//!
//! The main advantage of these protocol versions numbers over using Tor
//! version numbers is that they allow different implementations of the Tor
//! protocols to develop independently, without having to claim compatibility
//! with specific versions of Tor.

// TODO
//
// - try BTree{Map,Set} and see if it goes faster
// - move this module to protover.rs and do `pub use protover::*` here
// - write up coding standards based on learning from this

extern crate external;

use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::ops::RangeInclusive;
use std::str::FromStr;
use std::str::SplitN;

// pub mod ffi;

/// The first version of Tor that included "proto" entries in its descriptors.
/// Authorities should use this to decide whether to guess proto lines.
const FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS: &'static str = "0.2.9.3-alpha";

/// The maximum number of subprotocol version numbers we'll attempt to expand
/// before concluding that someone is attempting to DoS us.
const MAX_PROTOCOLS_TO_EXPAND: usize = 1 << 16;

/// Currently supported subprotocols and their versions.
const SUPPORTED_PROTOCOLS: &'static [&'static str] = &[
    "Cons=1-2",
    "Desc=1-2",
    "DirCache=1-2",
    "HSDir=1-2",
    "HSIntro=3-4",
    "HSRend=1-2",
    "Link=1-4",
    "LinkAuth=1,3",
    "Microdesc=1-2",
    "Relay=1-2",
];

/// Known subprotocols in Tor. Indicates which subprotocol a relay supports.
#[derive(Hash, Eq, PartialEq, Debug, Copy, Clone)]
pub enum Proto {
    Cons,
    Desc,
    DirCache,
    HSDir,
    HSIntro,
    HSRend,
    Link,
    LinkAuth,
    Microdesc,
    Relay,
}

impl std::fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for Proto {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Cons"               => Ok(Proto::Cons),
            "Desc"               => Ok(Proto::Desc),
            "DirCache"           => Ok(Proto::DirCache),
            "HSDir"              => Ok(Proto::HSDir),
            "HSIntro"            => Ok(Proto::HSIntro),
            "HSRend"             => Ok(Proto::HSRend),
            "Link"               => Ok(Proto::Link),
            "LinkAuth"           => Ok(Proto::LinkAuth),
            "Microdesc"          => Ok(Proto::Microdesc),
            "Relay"              => Ok(Proto::Relay),
            _                    => Err("Not a valid protocol type"),
        }
    }
}

fn parse_protocols(protocols: &[&str]) -> Result<HashMap<Proto, HashSet<u32>>, &'static str> {
    let mut parsed = HashMap::new();

    for subproto in protocols {
        let (name, version) = get_proto_and_vers(subproto)?;
        parsed.insert(name, version);
    }
    Ok(parsed)
}

fn parse_protocols_from_string<'a>(protocol_string: &'a str)
        -> Result<HashMap<Proto, HashSet<u32>>, &'static str>
{
    let protocols: &[&'a str] = &protocol_string.split(" ").collect::<Vec<&'a str>>()[..];

    parse_protocols(protocols)
}

/// Translates supported tor versions from  a string into a hashmap, which is
/// useful when looking up a specific subprotocol.
fn tor_supported() -> Result<HashMap<Proto, HashSet<u32>>, &'static str> {
    parse_protocols(&SUPPORTED_PROTOCOLS)
}

fn expand_version_range<'a>(version_range: &'a str) -> Result<RangeInclusive<u32>, &'static str> {
    if version_range.is_empty() || !version_range.contains("-") {
        return Err("Invalid version range");
    }

    let mut pieces: SplitN<'a, &str> = version_range.splitn(2, "-");
    let lower_string: &str = pieces.next().ok_or("Couldn't get lower bound")?;
    println!("{}", lower_string);
    let lower: u32 = u32::from_str_radix(lower_string, 10).or(Err("Cannot parse lower bound"))?;
    let upper_string: &str = pieces.next().ok_or("Couldn't get upper bound")?;
    let upper: u32 = u32::from_str_radix(upper_string, 10).or(Err("Cannot parse upper bound"))?;

    Ok(lower...upper) // three dots means the range is inclusive
}

/// Get the unique version numbers supported by a subprotocol.
///
/// # Inputs
///
/// * `version_string`, a string comprised of "[0-9,-]"
///
/// # Returns
///
/// A `Result` whose `Ok` value is a `HashSet<u32>` holding all of the unique
/// version numbers.  If there were ranges in the `version_string`, then these
/// are expanded, i.e. `"1-3"` would expand to `HashSet<u32>::new([1, 2, 3])`.
/// The returned HashSet is *unordered*.
///
/// The returned `Result`'s `Err` value is an `&'static str` with a description
/// of the error.
///
/// # Errors
///
/// This function will error if:
///
/// * the `version_string` is empty or contains an equals (`"="`) sign,
/// * the expansion of a version range produces an error (see `expand_version_range`),
/// * any single version number is not parseable as an `u32` in radix 10, or
/// * there are greater than 2^16 version numbers to expand.
fn get_versions(version_string: &str) -> Result<HashSet<u32>, &'static str> {
    let mut versions: HashSet<u32> = HashSet::new();

    if version_string.is_empty() {
        return Err("Invalid protover string was empty");
    } else if version_string.contains("=") {
        return Err("Invalid protover string contained an equal sign");
    }

    for piece in version_string.split(",") {
        if piece.contains("-") {
            for n in expand_version_range(piece)? {
                versions.insert(n);
            }
        } else {
            versions.insert(u32::from_str_radix(piece, 10)
                            .or(Err("Cannot interpret version as u32"))?);
        }
        if versions.len() > MAX_PROTOCOLS_TO_EXPAND {
            return Err("Too many versions to expand");
        }
    }
    Ok(versions)
}

/// Parse the subprotocol type and its version numbers.
///
/// # Inputs
///
/// * A `subprotocol` string, comprised of a keyword, an "=" sign, and one or
///   more version numbers.
///
/// # Returns
///
/// A `Result` whose `Ok` value is a tuple of `(Proto, HashSet<u32>)`, where the
/// first element is the subprotocol type (see `protover::Proto`) and the last
/// element is a(n unordered) set of unique version numbers which are supported.
/// Otherwise, the `Err` value of this `Result` is a description of the error
/// which occured.
fn get_proto_and_vers<'a>(subprotocol: &'a str) -> Result<(Proto, HashSet<u32>), &'static str> {
    let mut parts: SplitN<'a, &str> = subprotocol.splitn(2, "=");

    let proto: &str = match parts.next() {
        Some(n) => n,
  	    None    => return Err("Not a valid protocol entry"),
    };

    let vers: &str = match parts.next() {
        Some(n) => n,
	    None    => return Err("Not a valid protocol entry"),
    };

    let protocol = proto.parse()?;
    let versions = get_versions(vers)?;

    Ok((protocol, versions))
}

/// Takes a single subprotocol entry as a string, parses it into subprotocol
/// and version parts, and then checks whether any of those versions are
/// unsupported.
///
/// # Returns
///
/// Returns `true` if there are versions supported by tor which we do not
/// support, and `false` if we support all currently supported versions.
fn parse_and_check_support(protocol: &str) -> bool {
    let currently_supported: HashMap<Proto, HashSet<u32>>;
    let result: Result<_, _> = get_proto_and_vers(protocol);

    if result.is_err() {
        return false; // TODO how do we log to tor's logger?
    }

    let (proto, mut versions) = result.unwrap();

    match tor_supported() {
        Ok(result) => currently_supported = result,
        Err(_)     => return false,
    }

    versions.retain(|x| !currently_supported[&proto].contains(x));
    versions.is_empty()
}

/// Determine if we support every protocol a client supports, and if not,
/// determine which protocols we do not have support for.
///
/// # Inputs
///
/// Accepted data is in the string format as follows:
///
/// ```ignore
/// "HSDir=1-1 LinkAuth=1-2"
/// ```
/// # Returns
///
/// Return `true` if every protocol version is one that we support.
/// Otherwise, return `false`.
/// Optionally, return parameters which the client supports but which we do not
///
/// # Examples
/// ```
/// use protover::all_supported;
///
/// let (is_supported, unsupported)  = all_supported("Link=1");
/// assert_eq!(true, is_supported);
///
/// let (is_supported, unsupported)  = all_supported("Link=5-6");
/// assert_eq!(false, is_supported);
/// assert_eq!("Link=5-6", unsupported);
/// ```
pub fn all_supported<'a>(protocols: &'a str) -> (bool, String) {
    let unsupported: Vec<&str> = protocols
        .split_whitespace()
        .filter(|v| !parse_and_check_support(v))
        .collect();

    (unsupported.is_empty(), unsupported.join(" "))
}

// /// accepts a subprotocol and a subprotocol entry, returns a boolean indicating
// /// whether the subprotocol entry corresponds to that subprotocol
// fn is_for(proto: &Proto, sub: &str) -> bool {
//     let parts = sub.split("=").collect::<Vec<&str>>();
//     match parts[0].parse::<Proto>() {
//         Ok(n) => &n == proto,
//         Err(_) => false,
//     }
// }

// /// accepts a subprotocol entry and returns only the versions in that entry
// fn strip_protocol<'a>(protocol_string: &'a str) -> Option<&'a str> {
//     protocol_string.splitn(2, "=").last()
// }

/// Return true iff the provided protocol list includes support for the
/// indicated protocol and version.
/// Otherwise, return false
///
/// # Examples
/// ```
/// use protover::list_supports_protocol;
///
/// let is_supported = list_supports_protocol("Link=3-4 Cons=1", Proto::Cons,1);
/// assert_eq!(true, is_supported)
/// ```
pub fn protocol_string_supports_protocol(proto_string: &str, protocol: Proto, version: u32) -> bool {
    let supported: HashMap<Proto, HashSet<u32>>;

    match parse_protocols_from_string(proto_string) {
        Ok(result) => supported = result,
        Err(_)     => return false,
    }

    supported[&protocol].contains(&version)
}

// /// Takes a protocol range and expands it to all numbers within that range.
// /// For example, 1-3 expands to 1,2,3
// fn expand(range: &str) -> Vec<i32> {
//     if range.is_empty() {
//         return Vec::new();
//     }
//
//     let parts = range.split("-").collect::<Vec<&str>>();
//
//     let low = parts[0].parse::<i32>().unwrap();
//     if parts.len() == 1 {
//         return vec![low];
//     }
//
//     let high = parts[1].parse::<i32>().unwrap();
//     (low..high + 1).collect()
// }

// /// Find range checks to see if there is a continuous range of integers,
// /// starting at the first in the list.
// /// For example, if given vec![1, 2, 3, 5], find_range will return true,
// /// as there is a continuous range, and 3, which is the last number in the
// /// continuous range.
// fn find_range(list: Vec<u32>) -> (bool, u32) {
//     if list.len() == 0 {
//         return (false, 0);
//     }
//
//     let mut iterable = list.iter().peekable();
//     iterable.next();
//
//     let mut current = list[0];
//     let mut has_range = false;
//
//     while iterable.peek().is_some() {
//         let n = *iterable.next().unwrap();
//         if n != current + 1 {
//             break;
//         }
//
//         has_range = true;
//         current = n;
//     }
//
//     (has_range, current)
// }

// fn contract(list: &Vec<u32>, threshold: usize) -> String {
//     let mut supported = list.clone();
//
//     let borrowed = supported.clone();
//     supported.retain(|&x| {
//         borrowed.iter().filter(|&y| x == *y).count() >= threshold
//     });
//
//     supported.sort();
//     supported.dedup();
//
//     let mut final_output: Vec<String> = Vec::new();
//
//     while supported.len() != 0 {
//         let (has_range, end) = find_range(supported.clone());
//         let current = supported.remove(0);
//
//         if has_range {
//             final_output.push(current.to_string() + "-" + &end.to_string());
//             supported.retain(|&x| x > end);
//         } else {
//             final_output.push(current.to_string());
//         }
//     }
//
//     final_output.join(",")
// }

fn contract_protocol_list(protocol_list: &HashMap<Proto, HashSet<u32>>) -> Result<String, &'static str> {
    let keys: Vec<String> = Vec::new();
    let sorted_keys = protocol_list.keys().fold(keys, |keys, &x| keys.append(&mut format!("{}", x)));
    sorted_keys.sort();

    unimplemented!()
}

/// Protocol voting implementation.
///
/// Given a list of strings describing protocol versions, return a new
/// string encoding all of the protocols that are listed by at
/// least threshold of the inputs.
///
/// The string is sorted according to the following conventions:
///   - Protocols names are alphabetized
///   - Protocols are in order low to high
///   - Individual and ranges are listed together. For example,
///     "3, 5-10,13"
///   - All entries are unique
///
/// # Examples
/// ```
/// use protover::compute_vote;
///
/// let protos = ["Link=3-4", "Link=3"];
/// let vote = compute_vote(protos, 2);
/// assert_eq!("Link=3", vote)
/// ```
pub fn compute_vote(list_of_proto_strings: &[&str], threshold: usize) -> Result<String, &'static str> {
    let mut all: HashMap<String, usize> = HashMap::with_capacity(list_of_proto_strings.len());
    let mut expanded: HashMap<String, (Proto, u32)> = HashMap::new();
    let mut included: HashMap<Proto, HashSet<u32>> = HashMap::new();

    // Parse and collect all the protos and their versions and count them
    for vote in list_of_proto_strings {
        let this_vote: HashMap<Proto, HashSet<u32>> = parse_protocols_from_string(vote)?;

        for (proto, versions) in this_vote {
            for version in versions {
                let formatted: String = format!("{}={}", proto, version);
                let counter: &mut usize = all.entry(formatted.clone()).or_insert(0);
                *counter += 1;
                expanded.entry(formatted).or_insert((proto, version));
            }
        }
    }
    // Get all the protoversions which met the threshold
    for (formatted, count) in all {
        let (proto, version): (Proto, u32) = expanded[&formatted];

        if count > threshold {
            let versions: &mut HashSet<u32> = included.entry(proto).or_insert(HashSet::new());
            versions.insert(version);
        }
    }
    // Compress the list into a string and return it
    contract_protocol_list(&included)
}

/// Returns a boolean indicating whether the given protocol and version is
/// supported in any of the existing Tor protocols
///
/// # Examples
/// ```
/// use protover::is_supported_here;
///
/// let is_supported = is_supported_here(Proto::Link, 5);
/// assert_eq!(false, is_supported);
///
/// let is_supported = is_supported_here(Proto::Link, 1);
/// assert_eq!(true, is_supported);
/// ```
pub fn is_supported_here(protocol: Proto, version: u32) -> bool {
    let currently_supported: HashMap<Proto, HashSet<u32>>;

    match tor_supported() {
        Ok(result) => currently_supported = result,
        Err(_)     => return false,
    }
    currently_supported[&protocol].contains(&version)
}

/// Older versions of Tor cannot infer their own subprotocols
/// Used to determine which subprotocols are supported by older Tor versions.
pub fn compute_for_old_tor(version: &str) -> &'static str {
    let mut ret: &'static str = "";

    if external::c_tor_version_as_new_as(&version,
                                         FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS) {
        return ret;
    } else if external::c_tor_version_as_new_as(&version, "0.2.9.1-alpha") {
        ret = "Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1-2 \
               Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2";
    } else if external::c_tor_version_as_new_as(&version, "0.2.7.5") {
        ret = "Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 \
               Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2";
    } else if external::c_tor_version_as_new_as(&version, "0.2.4.19") {
        ret = "Cons=1 Desc=1 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 \
               Link=1-4 LinkAuth=1 Microdesc=1 Relay=1-2";
    }
    ret
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[should_panic(expected = "Invalid protover string was empty")]
    fn get_versions_empty() {
        let expected: HashSet<u32> = HashSet::new();

        assert_eq!(expected, get_versions("").unwrap());
    }

    #[test]
    fn get_versions_single() {
        let mut expected: HashSet<u32> = HashSet::new();

        expected.insert(1);
        assert_eq!(expected, get_versions("1").unwrap());
    }

    #[test]
    fn get_versions_commas() {
        let mut expected: HashSet<u32> = HashSet::new();

        expected.insert(1);
        expected.insert(2);
        assert_eq!(expected, get_versions("1,2").unwrap());

        expected.insert(3);
        assert_eq!(expected, get_versions("1,2,3").unwrap());
    }

    #[test]
    fn get_versions_ranges() {
        let mut expected: HashSet<u32> = HashSet::new();

        expected.insert(1);
        expected.insert(2);
        expected.insert(3);
        assert_eq!(expected, get_versions("1-3").unwrap());
    }

    #[test]
    fn get_versions_ranges_and_commas() {
        let mut expected: HashSet<u32> = HashSet::new();

        expected.insert(1);
        expected.insert(2);
        expected.insert(3);
        expected.insert(5);
        assert_eq!(expected, get_versions("1-3,5").unwrap());

        expected.remove(&2);
        expected.insert(4);
        assert_eq!(expected, get_versions("1,3-5").unwrap());
    }

    #[test]
    fn get_versions_multidigits() {
        let mut expected: HashSet<u32> = HashSet::new();

        expected.insert(13);
        expected.insert(42);
        expected.insert(43);
        expected.insert(1337);
        assert_eq!(expected, get_versions("13,42-43,1337").unwrap());
    }

    #[test]
    #[should_panic(expected = "Cannot interpret version as u32")]
    fn get_versions_nondigits() {
        let mut expected: HashSet<u32> = HashSet::new();

        expected.insert(1);
        assert_eq!(expected, get_versions("1,foo").unwrap());
    }

    #[test]
    fn test_parse_and_check_support() {
        //assert_eq!(false, parse_and_check_support(""));
        assert_eq!(false, parse_and_check_support("Cons="));
        assert_eq!(true, parse_and_check_support("Cons=1"));
        assert_eq!(false, parse_and_check_support("Cons=0"));
        assert_eq!(false, parse_and_check_support("Cons=0-1"));
        assert_eq!(false, parse_and_check_support("Cons=5"));
        assert_eq!(false, parse_and_check_support("Cons=1-5"));
        assert_eq!(false, parse_and_check_support("Cons=1,5"));
        assert_eq!(false, parse_and_check_support("Cons=5,6"));
        assert_eq!(false, parse_and_check_support("Cons=1,5,6"));
        assert_eq!(true, parse_and_check_support("Cons=1,2"));
        assert_eq!(true, parse_and_check_support("Cons=1-2"));
    }

    //    TODO move to /tests
    //    #[test]
    //    fn test_all_supported() {
    //        assert_eq!((true, String::from("")), all_supported("Cons=1"));
    //        assert_eq!((false, String::from("Wombat=9")),
    //                   all_supported("Cons=1 Wombat=9"));
    //    }

    // #[test]
    // fn test_is_for() {
    //     use super::is_for;
    //     use super::Proto;
    //
    //     assert_eq!(false, is_for(&Proto::Cons, ""));
    //     assert_eq!(true, is_for(&Proto::Cons, "Cons=1"));
    //     assert_eq!(false, is_for(&Proto::Cons, "HSDir=1"));
    //     assert_eq!(false, is_for(&Proto::Cons, "HSDir=1-1"));
    //     assert_eq!(false, is_for(&Proto::Cons, "HSDir=1,2"));
    // }

    // #[test]
    // fn test_find_range() {
    //     use super::find_range;
    //
    //     assert_eq!((false, 0), find_range(vec![]));
    //     assert_eq!((false, 1), find_range(vec![1]));
    //     assert_eq!((true, 2), find_range(vec![1, 2]));
    //     assert_eq!((true, 3), find_range(vec![1, 2, 3]));
    //     assert_eq!((true, 3), find_range(vec![1, 2, 3, 5]));
    // }

    // #[test]
    // fn test_expand() {
    //     use super::expand;
    //
    //     assert_eq!(Vec::<i32>::new(), expand(""));
    //     assert_eq!(vec![1], expand("1"));
    //     assert_eq!(vec![1, 2], expand("1-2"));
    //     assert_eq!(vec![1, 2, 3, 4], expand("1-4"));
    // }

    // #[test]
    // fn test_contract() {
    //     use super::contract;
    //
    //     assert_eq!(String::from(""), contract(&vec![], 1));
    //     assert_eq!(String::from("1"), contract(&vec![1], 1));
    //     assert_eq!(String::from("1"), contract(&vec![1, 1], 1));
    //     assert_eq!(String::from("1"), contract(&vec![1, 1, 2], 2));
    //     assert_eq!(String::from("1-2"), contract(&vec![1, 1, 2, 2], 2));
    //     assert_eq!(String::from("1,3"), contract(&vec![1, 1, 3, 3], 2));
    //     assert_eq!(String::from("3-7"), contract(&vec![3, 4, 5, 6, 7], 1));
    //     assert_eq!(String::from("3-8"), contract(&vec![3, 4, 5, 6, 7, 8], 1));
    //     assert_eq!(
    //         String::from("1,3-8"),
    //         contract(&vec![1, 3, 4, 5, 6, 7, 8], 1)
    //     );
    //     assert_eq!(
    //         String::from("1-3,500"),
    //         contract(&vec![1, 2, 3, 3, 500], 1)
    //     );
    //     assert_eq!(
    //         String::from("1-8"),
    //         contract(&vec![1, 3, 4, 5, 6, 7, 8, 2, 3, 4, 5, 6, 8], 1)
    //     );
    // }
}
