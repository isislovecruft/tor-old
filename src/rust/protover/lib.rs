/// Copyright (c) 2016-2017, The Tor Project, Inc. */
/// See LICENSE for licensing information */

/// Versioning information for different pieces of the Tor protocol.
///
/// Starting in version 0.2.9.3-alpha, Tor places separate version numbers on
/// each of the different components of its protocol. Relays use these numbers
/// to advertise what versions of the protocols they can support, and clients
/// use them to find what they can ask a given relay to do.  Authorities vote
/// on the supported protocol versions for each relay, and also vote on the
/// which protocols you should have to support in order to be on the Tor
/// network. All Tor instances use these required/recommended protocol versions
/// to tell what level of support for recent protocols each relay has, and
/// to decide whether they should be running given their current protocols.
///
/// The main advantage of these protocol versions numbers over using Tor
/// version numbers is that they allow different implementations of the Tor
/// protocols to develop independently, without having to claim compatibility
/// with specific versions of Tor.

extern crate external;

use std::str;
use std::fmt;
use std::collections::HashMap;

pub mod ffi;

/// The first version of Tor that included "proto" entries in its descriptors.
/// Authorities should use this to decide whether to guess proto lines.
static FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS: &'static str = "0.2.9.3-alpha";

/// Subprotocols in Tor. Indicates which subprotocol a relay supports.
#[derive(Hash, Eq, PartialEq, Debug)]
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

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::str::FromStr for Proto {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Cons" => Ok(Proto::Cons),
            "Desc" => Ok(Proto::Desc),
            "DirCache" => Ok(Proto::DirCache),
            "HSDir" => Ok(Proto::HSDir),
            "HSIntro" => Ok(Proto::HSIntro),
            "HSRend" => Ok(Proto::HSRend),
            "Link" => Ok(Proto::Link),
            "LinkAuth" => Ok(Proto::LinkAuth),
            "Microdesc" => Ok(Proto::Microdesc),
            "Relay" => Ok(Proto::Relay),
            _ => Err("Not a valid protocol type"),
        }
    }
}

/// Translates supported tor versions from  a string into a hashmap, which is
/// useful when looking up a specific subprotocol.
fn tor_supported() -> HashMap<Proto, Vec<i32>> {
    let mut tor_supported = HashMap::new();

    let str_supported = get_supported_protocols();
    let vec_supported = str_supported.split(" ").collect::<Vec<&str>>();

    for x in vec_supported {
        let (p, vers) = get_proto_and_vers(x);
        tor_supported.insert(p.unwrap(), vers.unwrap());
    }

    tor_supported
}

/// Currently supported subprotocol versions in Tor
/// Two formats can be used to specify subprotocols.
/// "Cons=1-3" indicates that versions 1, 2, and 3 are supported, while
/// "Cons=1,3" indicates that versions 1 and 3 are supported.
fn get_supported_protocols() -> String {
    String::from("Cons=1-2 ") + "Desc=1-2 " + "DirCache=1-2 " +
        "HSDir=1-2 " + "HSIntro=3-4 " +
        "HSRend=1-2 " + "Link=1-4 " + "LinkAuth=1,3 " + "Microdesc=1-2 " +
        "Relay=1-2"
}

/// Returns versions supported by the subprotocol.
/// A protocol entry has a keyword, an "=" sign, and one or more version numbers
fn get_versions(list: &str) -> Vec<i32> {
    if list.is_empty() {
        return Vec::new();
    }

    let mut all_supported = list.split(",")
        .filter(|&x| x.contains("-"))
        .flat_map(|x| expand(x))
        .collect::<Vec<i32>>();

    let loose = list.split(",")
        .filter(|&x| !x.contains("-"))
        .map(|x| x.parse::<i32>().unwrap())
        .collect::<Vec<i32>>();

    all_supported.extend(loose.iter().cloned());
    all_supported.sort();
    all_supported
}

fn get_proto_and_vers(
    str_p: &str,
) -> (Result<Proto, &'static str>, Result<Vec<i32>, &'static str>) {
    let mut parts: Vec<&str> = str_p.split("=").collect();

    let vers: &str = match parts.pop() {
        Some(n) => n,
        None => "",
    };

    let proto: &str = match parts.pop() {
        Some(n) => n,
        None => "",
    };

    if vers.is_empty() || proto.is_empty() {
        return (
            Err("Not a valid subprotocol entry"),
            Err("Not a valid subprotocol entry"),
        );
    }

    (proto.parse::<Proto>(), Ok(get_versions(vers)))
}

/// Takes a single subprotocol entry as a string, parses it into subprotocol
/// and version parts, and then checks whether any of those versions are
/// unsupported.
fn parse_and_check_support(str_v: &str) -> bool {
    let (proto, v) = get_proto_and_vers(str_v);

    let name = match proto {
        Ok(n) => n,
        Err(_) => return false,
    };

    let mut vers = match v {
        Ok(v) => v,
        Err(_) => return false,
    };

    vers.retain(|x| !tor_supported()[&name].contains(x));
    vers.is_empty()
}

/// Return true if every protocol version is one that we support
/// Otherwise, return false
/// Optionally, return parameters which the client supports but which we do not
/// Accepted data is in the string format as follows:
/// "HSDir=1-1 LinkAuth=1-2"
///
/// # Examples
/// ```
/// use protover::*;
///
/// let (is_supported, unsupported)  = all_supported("Link=1");
/// assert_eq!(true, is_supported);
///
/// let (is_supported, unsupported)  = all_supported("Link=5-6");
/// assert_eq!(false, is_supported);
/// assert_eq!("Link=5-6", unsupported);
/// ```
pub fn all_supported(protocols: &str) -> (bool, String) {
    let unsupported: Vec<&str> = protocols
        .split_whitespace()
        .filter(|v| !parse_and_check_support(v))
        .collect::<Vec<&str>>();

    (unsupported.is_empty(), unsupported.join(" "))
}

/// accepts a subprotocol and a subprotocol entry, returns a boolean indicating
/// whether the subprotocol entry corresponds to that subprotocol
fn is_for(proto: &Proto, sub: &str) -> bool {
    let parts = sub.split("=").collect::<Vec<&str>>();
    match parts[0].parse::<Proto>() {
        Ok(n) => &n == proto,
        Err(_) => false,
    }
}

/// accepts a subprotocol entry and returns only the versions in that entry
fn strip_protocol(str_p: &str) -> &str {
    let mut parts = str_p.split("=").collect::<Vec<&str>>();
    parts.pop().unwrap()
}

/// Return true iff the provided protocol list includes support for the
/// indicated protocol and version.
/// Otherwise, return false
///
/// # Examples
/// ```
/// use protover::*;
///
/// let is_supported = list_supports_protocol("Link=3-4 Cons=1", Proto::Cons,1);
/// assert_eq!(true, is_supported)
/// ```
pub fn list_supports_protocol(list: &str, proto: Proto, vers: i32) -> bool {
    list.split_whitespace()
        .filter(|&x| is_for(&proto, x))
        .map(strip_protocol)
        .flat_map(|x| get_versions(x))
        .collect::<Vec<i32>>()
        .contains(&vers)
}

/// Takes a protocol range and expands it to all numbers within that range.
/// For example, 1-3 expands to 1,2,3
fn expand(range: &str) -> Vec<i32> {
    if range.is_empty() {
        return Vec::new();
    }

    let parts = range.split("-").collect::<Vec<&str>>();

    let low = parts[0].parse::<i32>().unwrap();
    if parts.len() == 1 {
        return vec![low];
    }

    let high = parts[1].parse::<i32>().unwrap();
    (low..high + 1).collect()
}

/// Find range checks to see if there is a continuous range of integers,
/// starting at the first in the list.
/// For example, if given vec![1, 2, 3, 5], find_range will return true,
/// as there is a continuous range, and 3, which is the last number in the
/// continuous range.
fn find_range(list: Vec<i32>) -> (bool, i32) {
    if list.len() == 0 {
        return (false, 0);
    }

    let mut iterable = list.iter().peekable();
    iterable.next();

    let mut current = list[0];
    let mut has_range = false;

    while iterable.peek().is_some() {
        let n = *iterable.next().unwrap();
        if n != current + 1 {
            break;
        }

        has_range = true;
        current = n;
    }

    (has_range, current)
}

fn contract(list: &Vec<i32>, threshold: i32) -> String {
    let mut supported = list.clone();

    let borrowed = supported.clone();
    supported.retain(|&x| {
        borrowed.iter().filter(|&y| x == *y).count() >= threshold as usize
    });

    supported.sort();
    supported.dedup();

    let mut final_output: Vec<std::string::String> = Vec::new();

    while supported.len() != 0 {
        let (has_range, end) = find_range(supported.clone());
        let current = supported.remove(0);

        if has_range {
            final_output.push(current.to_string() + "-" + &end.to_string());
            supported.retain(|&x| x > end);
        } else {
            final_output.push(current.to_string());
        }
    }

    final_output.join(",")
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
/// use protover::*;
///
/// let protos = vec![String::from("Link=3-4"), String::from("Link=3")];
/// let vote = compute_vote(protos, 2);
/// assert_eq!("Link=3", vote)
/// ```
pub fn compute_vote(protos: Vec<String>, threshold: i32) -> String {
    if protos.is_empty() {
        return String::from("");
    }

    let unified = protos
        .iter()
        .flat_map(|ref k| k.split_whitespace().collect::<Vec<&str>>())
        .collect::<Vec<&str>>();

    let mut uniques: HashMap<String, Vec<i32>> = HashMap::new();

    for x in unified {
        let mut parts: Vec<&str> = x.split("=").collect();

        let v: &str = match parts.pop() {
            Some(n) => n,
            None => "",
        };

        let proto: &str = match parts.pop() {
            Some(n) => n,
            None => "",
        };

        if proto.is_empty() || v.is_empty() {
            continue; // TODO verify if there are malformed protover entries
        }

        let vers = get_versions(v);

        let str_name = String::from(proto);
        if uniques.contains_key(&str_name) {
            let ref mut val = *uniques.get_mut(&str_name).unwrap();
            val.extend(vers.iter().cloned());
        } else {
            uniques.insert(str_name, vers);
        }
    }

    let mut sorted_keys = uniques.keys().collect::<Vec<&String>>();
    sorted_keys.sort();

    let mut final_output = Vec::new();
    for k in sorted_keys {
        let meets_threshold = &contract(&uniques[k], threshold);
        if !meets_threshold.is_empty() {
            let output = k.clone() + "=" + meets_threshold;
            final_output.push(output);
        }
    }

    final_output.join(" ")
}

/// Returns a boolean indicating whether the given protocol and version is
/// supported in any of the existing Tor protocols
///
/// # Examples
/// ```
/// use protover::*;
///
/// let is_supported = is_supported_here(Proto::Link, 5);
/// assert_eq!(false, is_supported);
///
/// let is_supported = is_supported_here(Proto::Link, 1);
/// assert_eq!(true, is_supported);
/// ```
pub fn is_supported_here(proto: Proto, vers: i32) -> bool {
    tor_supported()[&proto].contains(&vers)
}

/// Older versions of Tor cannot infer their own subprotocols
/// Used to determine which subprotocols are supported by older Tor versions.
pub fn compute_for_old_tor(version: String) -> String {
    if external::c_tor_version_as_new_as(
        &version,
        FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS,
    )
    {
        return String::new();
    }

    if external::c_tor_version_as_new_as(&version, "0.2.9.1-alpha") {
        let ret = "Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1-2 \
                   Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2";
        return String::from(ret);
    }

    if external::c_tor_version_as_new_as(&version, "0.2.7.5") {
        let ret = "Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 \
                   Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2";
        return String::from(ret);
    }

    if external::c_tor_version_as_new_as(&version, "0.2.4.19") {
        let ret = "Cons=1 Desc=1 DirCache=1 HSDir=1 HSIntro=3 HSRend=1 \
                   Link=1-4 LinkAuth=1 Microdesc=1 Relay=1-2";
        return String::from(ret);
    }
    String::new()
}

#[cfg(test)]
mod test {
    #[test]
    fn test_get_versions() {
        use super::get_versions;

        // TODO how to handle non-integer characters?
        assert_eq!(Vec::<i32>::new(), get_versions(""));
        assert_eq!(vec![1], get_versions("1"));
        assert_eq!(vec![1, 2], get_versions("1,2"));
        assert_eq!(vec![1, 2, 3], get_versions("1,2,3"));
        assert_eq!(vec![1, 2, 3], get_versions("1-3"));
        assert_eq!(vec![1, 2, 3, 5], get_versions("1-3,5"));
        assert_eq!(vec![1, 3, 4, 5], get_versions("1,3-5"));
    }

    #[test]
    fn test_parse_and_check_support() {
        use super::parse_and_check_support;

        assert_eq!(false, parse_and_check_support(""));
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
    //        use super::all_supported;
    //
    //        assert_eq!((true, String::from("")), all_supported("Cons=1"));
    //        assert_eq!((false, String::from("Wombat=9")),
    //                   all_supported("Cons=1 Wombat=9"));
    //    }

    #[test]
    fn test_is_for() {
        use super::is_for;
        use super::Proto;

        assert_eq!(false, is_for(&Proto::Cons, ""));
        assert_eq!(true, is_for(&Proto::Cons, "Cons=1"));
        assert_eq!(false, is_for(&Proto::Cons, "HSDir=1"));
        assert_eq!(false, is_for(&Proto::Cons, "HSDir=1-1"));
        assert_eq!(false, is_for(&Proto::Cons, "HSDir=1,2"));
    }

    #[test]
    fn test_find_range() {
        use super::find_range;

        assert_eq!((false, 0), find_range(vec![]));
        assert_eq!((false, 1), find_range(vec![1]));
        assert_eq!((true, 2), find_range(vec![1, 2]));
        assert_eq!((true, 3), find_range(vec![1, 2, 3]));
        assert_eq!((true, 3), find_range(vec![1, 2, 3, 5]));
    }

    #[test]
    fn test_expand() {
        use super::expand;

        assert_eq!(Vec::<i32>::new(), expand(""));
        assert_eq!(vec![1], expand("1"));
        assert_eq!(vec![1, 2], expand("1-2"));
        assert_eq!(vec![1, 2, 3, 4], expand("1-4"));
    }

    #[test]
    fn test_contract() {
        use super::contract;

        assert_eq!(String::from(""), contract(&vec![], 1));
        assert_eq!(String::from("1"), contract(&vec![1], 1));
        assert_eq!(String::from("1"), contract(&vec![1, 1], 1));
        assert_eq!(String::from("1"), contract(&vec![1, 1, 2], 2));
        assert_eq!(String::from("1-2"), contract(&vec![1, 1, 2, 2], 2));
        assert_eq!(String::from("1,3"), contract(&vec![1, 1, 3, 3], 2));
        assert_eq!(String::from("3-7"), contract(&vec![3, 4, 5, 6, 7], 1));
        assert_eq!(String::from("3-8"), contract(&vec![3, 4, 5, 6, 7, 8], 1));
        assert_eq!(
            String::from("1,3-8"),
            contract(&vec![1, 3, 4, 5, 6, 7, 8], 1)
        );
        assert_eq!(
            String::from("1-3,500"),
            contract(&vec![1, 2, 3, 3, 500], 1)
        );
        assert_eq!(
            String::from("1-8"),
            contract(&vec![1, 3, 4, 5, 6, 7, 8, 2, 3, 4, 5, 6, 8], 1)
        );
    }
}
