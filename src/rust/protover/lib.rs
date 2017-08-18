#![feature(inclusive_range_syntax)]

//! Copyright (c) 2016-2017, The Tor Project, Inc. */
//! See LICENSE for licensing information */

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

extern crate external;

use std::str::FromStr;
use std::str::SplitN;
use std::fmt;
use std::collections::HashMap;
use std::collections::HashSet;

pub mod ffi;

/// The first version of Tor that included "proto" entries in its descriptors.
/// Authorities should use this to decide whether to guess proto lines.
const FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS: &'static str = "0.2.9.3-alpha";

const MAX_PROTOCOLS_TO_EXPAND: u32 = 500;

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

impl FromStr for Proto {
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

/// Currently supported protocols and their versions
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

pub fn get_supported_protocols() -> String {
    SUPPORTED_PROTOCOLS.join(" ")
}

fn parse_protocols(
    protocols: &[&str],
) -> Result<HashMap<Proto, Vec<u32>>, &'static str> {
    let mut parsed = HashMap::new();

    for subproto in protocols {
        let (name, version) = get_proto_and_vers(subproto)?;
        parsed.insert(name, version);
    }
    Ok(parsed)
}


fn parse_protocols_from_string<'a>(
    protocol_string: &'a str,
) -> Result<HashMap<Proto, Vec<u32>>, &'static str> {
    let protocols: &[&'a str] =
        &protocol_string.split(" ").collect::<Vec<&'a str>>()[..];

    parse_protocols(protocols)
}

/// Translates supported tor versions from  a string into a hashmap, which is
/// useful when looking up a specific subprotocol.
fn tor_supported() -> Result<HashMap<Proto, Vec<u32>>, &'static str> {
    parse_protocols(&SUPPORTED_PROTOCOLS)
}

/// Returns versions supported by the subprotocol.
/// A protocol entry has a keyword, an "=" sign, and one or more version numbers
fn get_versions(version_string: &str) -> Result<Vec<u32>, &'static str> {
    if version_string.is_empty() {
        return Err("version string is empty");
    }

    let mut versions = Vec::<u32>::new();

    for piece in version_string.split(",") {
        if piece.contains("-") {
            for p in expand_version_range(piece)? {
                versions.insert(0, p)
            }
        } else {
            versions.insert(
                0,
                u32::from_str(piece).or(Err("invalid protocol entry"))?,
            );
        }
        versions.dedup();

        if versions.len() > MAX_PROTOCOLS_TO_EXPAND as usize {
            return Err("Too many versions to expand");
        }
    }


    versions.sort();
    Ok(versions)
}

fn get_proto_and_vers<'a>(
    str_p: &'a str,
) -> Result<(Proto, Vec<u32>), &'static str> {
    let mut parts: SplitN<'a, &str> = str_p.splitn(2, "=");

    let proto: &str = match parts.next() {
        Some(n) => n,
        None => return Err("invalid protover entry"),
    };

    let vers: &str = match parts.next() {
        Some(n) => n,
        None => return Err("invalid protover entry"),
    };

    let versions = get_versions(vers)?;
    let proto_name = proto.parse()?;

    Ok((proto_name, versions))
}

/// Takes a single subprotocol entry as a string, parses it into subprotocol
/// and version parts, and then checks whether any of those versions are
/// unsupported.
fn contains_only_ssupported_protocols(str_v: &str) -> bool {
    let (name, mut vers) = match get_proto_and_vers(str_v) {
        Ok(n) => n,
        Err(_) => return false, // TODO log to Tor's logger
    };

    let currently_supported: HashMap<Proto, Vec<u32>> = match tor_supported() {
        Ok(n) => n,
        Err(_) => return false,
    };

    vers.retain(|x| !currently_supported[&name].contains(x));
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
        .filter(|v| !contains_only_ssupported_protocols(v))
        .collect::<Vec<&str>>();

    (unsupported.is_empty(), unsupported.join(" "))
}

/// Return true iff the provided protocol list includes support for the
/// indicated protocol and version.
/// Otherwise, return false
///
/// # Examples
/// ```
/// use protover::*;
///
/// let is_supported = protover_string_supports_protocol("Link=3-4 Cons=1", Proto::Cons,1);
/// assert_eq!(true, is_supported)
/// ```
pub fn protover_string_supports_protocol(
    list: &str,
    proto: Proto,
    vers: u32,
) -> bool {
    let supported: HashMap<Proto, Vec<u32>>;

    match parse_protocols_from_string(list) {
        Ok(result) => supported = result,
        Err(_) => return false,
    }

    supported[&proto].contains(&vers)
}

/// Takes a protocol range and expands it to all numbers within that range.
/// For example, 1-3 expands to 1,2,3
/// Will return an error if the version range does not contain both a valid
/// lower and upper bound.
fn expand_version_range(range: &str) -> Result<Vec<u32>, &'static str> {
    if range.is_empty() {
        return Err("version string empty");
    }

    let mut parts = range.split("-");

    let lower_string: &str = parts.next().ok_or(
        "cannot parse protocol range lower bound",
    )?;

    let lower: u32 = u32::from_str_radix(lower_string, 10).or(Err(
        "cannot parse protocol range lower bound",
    ))?;

    let higher_string: &str = parts.next().ok_or(
        "cannot parse protocol range upper bound",
    )?;

    let higher: u32 = u32::from_str_radix(higher_string, 10).or(Err(
        "cannot parse protocol range upper bound",
    ))?;

    Ok((lower...higher).collect())
}

/// Find range checks to see if there is a continuous range of integers,
/// starting at the first in the list.
/// For example, if given vec![1, 2, 3, 5], find_range will return true,
/// as there is a continuous range, and 3, which is the last number in the
/// continuous range.
fn find_range(list: &Vec<u32>) -> (bool, u32) {
    if list.len() == 0 {
        return (false, 0);
    }

    let mut iterable = list.iter().peekable();
    let mut range_end: u32 = match iterable.next() {
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

fn contract_protocol_list<'a>(supported_hash: &'a HashSet<u32>) -> String {
    let mut supported_clone = supported_hash.clone();
    let mut supported: Vec<u32> = supported_clone.drain().collect();
    supported.sort();

    let mut final_output: Vec<std::string::String> = Vec::new();

    while supported.len() != 0 {
        let (has_range, end) = find_range(&supported);
        let current = supported.remove(0);

        if has_range {
            final_output.push(format!(
                "{}-{}",
                current.to_string(),
                &end.to_string(),
            ));
            supported.retain(|&x| x > end);
        } else {
            final_output.push(current.to_string());
        }
    }

    final_output.join(",")
}

fn parse_protocols_with_duplicates(
    protocols: Vec<String>,
) -> Result<HashMap<String, Vec<u32>>, &'static str> {
    let unified = protocols
        .iter()
        .flat_map(|ref k| k.split_whitespace().collect::<Vec<&str>>())
        .collect::<Vec<&str>>();

    let mut uniques: HashMap<String, Vec<u32>> = HashMap::new();

    for x in unified {
        let mut parts = x.splitn(2, "=");

        let proto: &str = match parts.next() {
            Some(n) => n,
            None => continue, // TODO how to handle malformed protos?
        };

        let v: &str = match parts.next() {
            Some(n) => n,
            None => continue, // TODO how to handle malformed protos?
        };

        let vers = match get_versions(v) {
            Ok(n) => n,
            Err(_) => continue,
        };

        let str_name = String::from(proto);
        if uniques.contains_key(&str_name) {
            let ref mut val = *uniques.get_mut(&str_name).unwrap();
            val.extend(vers.iter().cloned());
        } else {
            uniques.insert(str_name, vers);
        }
    }

    Ok(uniques)
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
    let empty = String::from("");

    if protos.is_empty() {
        return empty;
    }

    let protocols: HashMap<String, Vec<u32>>;

    // parse the protocol list into a hashmap
    match parse_protocols_with_duplicates(protos) {
        Ok(result) => protocols = result,
        Err(_) => return empty,
    }

    let mut final_output: HashMap<String, String> =
        HashMap::with_capacity(SUPPORTED_PROTOCOLS.len());

    for (protocol, versions) in protocols {
        let mut meets_threshold = HashSet::new();

        // keep only the versions which meet the given threshold
        for version in &versions {
            if !meets_threshold.contains(version) {
                if versions.iter().filter(|&y| *version == *y).count() >=
                    threshold as usize
                {
                    meets_threshold.insert(*version);
                }
            }
        }

        // for each protocol, create a string of its version list in the
        // expected protocol entry format.
        let contracted = contract_protocol_list(&meets_threshold);
        if !contracted.is_empty() {
            final_output.insert(protocol, contracted);
        }
    }

    write_vote_to_string(&final_output)
}

// TODO return a result
// Returns a String comprised of protocol entries in alphabetical order
fn write_vote_to_string(vote: &HashMap<String, String>) -> String {
    let mut keys: Vec<&String> = vote.keys().collect();
    keys.sort();

    let mut output = Vec::new();
    for key in keys {
        output.push(format!("{}={}", key, vote[key]));
    }
    output.join(" ")
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
pub fn is_supported_here(proto: Proto, vers: u32) -> bool {
    let currently_supported: HashMap<Proto, Vec<u32>>;

    match tor_supported() {
        Ok(result) => currently_supported = result,
        Err(_) => return false,
    }

    currently_supported[&proto].contains(&vers)
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

        // TODO handle non-integer characters?
        assert_eq!(Err("version string is empty"), get_versions(""));
        assert_eq!(Ok(vec![1]), get_versions("1"));
        assert_eq!(Ok(vec![1, 2]), get_versions("1,2"));
        assert_eq!(Ok(vec![1, 2, 3]), get_versions("1,2,3"));
        assert_eq!(Ok(vec![1, 2, 3]), get_versions("1-3"));
        assert_eq!(Ok(vec![1, 2, 3, 5]), get_versions("1-3,5"));
        assert_eq!(Ok(vec![1, 3, 4, 5]), get_versions("1,3-5"));
    }

    #[test]
    fn test_contains_only_ssupported_protocols() {
        use super::contains_only_ssupported_protocols;

        assert_eq!(false, contains_only_ssupported_protocols(""));
        assert_eq!(false, contains_only_ssupported_protocols("Cons="));
        assert_eq!(true, contains_only_ssupported_protocols("Cons=1"));
        assert_eq!(false, contains_only_ssupported_protocols("Cons=0"));
        assert_eq!(false, contains_only_ssupported_protocols("Cons=0-1"));
        assert_eq!(false, contains_only_ssupported_protocols("Cons=5"));
        assert_eq!(false, contains_only_ssupported_protocols("Cons=1-5"));
        assert_eq!(false, contains_only_ssupported_protocols("Cons=1,5"));
        assert_eq!(false, contains_only_ssupported_protocols("Cons=5,6"));
        assert_eq!(false, contains_only_ssupported_protocols("Cons=1,5,6"));
        assert_eq!(true, contains_only_ssupported_protocols("Cons=1,2"));
        assert_eq!(true, contains_only_ssupported_protocols("Cons=1-2"));
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
    fn test_find_range() {
        use super::find_range;

        assert_eq!((false, 0), find_range(&vec![]));
        assert_eq!((false, 1), find_range(&vec![1]));
        assert_eq!((true, 2), find_range(&vec![1, 2]));
        assert_eq!((true, 3), find_range(&vec![1, 2, 3]));
        assert_eq!((true, 3), find_range(&vec![1, 2, 3, 5]));
    }

    #[test]
    fn test_expand_version_range() {
        use super::expand_version_range;

        assert_eq!(Err("version string empty"), expand_version_range(""));
        assert_eq!(Ok(vec![1, 2]), expand_version_range("1-2"));
        assert_eq!(Ok(vec![1, 2, 3, 4]), expand_version_range("1-4"));
        assert_eq!(
            Err("cannot parse protocol range lower bound"),
            expand_version_range("a")
        );
        assert_eq!(
            Err("cannot parse protocol range upper bound"),
            expand_version_range("1-a")
        );
    }

    #[test]
    fn test_contract_protocol_list() {
        use std::collections::HashSet;
        use super::contract_protocol_list;

        {
            let mut versions = HashSet::<u32>::new();
            assert_eq!(String::from(""), contract_protocol_list(&versions));

            versions.insert(1);
            assert_eq!(String::from("1"), contract_protocol_list(&versions));

            versions.insert(2);
            assert_eq!(String::from("1-2"), contract_protocol_list(&versions));
        }

        {
            let mut versions = HashSet::<u32>::new();
            versions.insert(1);
            versions.insert(3);
            assert_eq!(String::from("1,3"), contract_protocol_list(&versions));
        }

        {
            let mut versions = HashSet::<u32>::new();
            versions.insert(1);
            versions.insert(2);
            versions.insert(3);
            versions.insert(4);
            assert_eq!(String::from("1-4"), contract_protocol_list(&versions));
        }

        {
            let mut versions = HashSet::<u32>::new();
            versions.insert(1);
            versions.insert(3);
            versions.insert(5);
            versions.insert(6);
            versions.insert(7);
            assert_eq!(
                String::from("1,3,5-7"),
                contract_protocol_list(&versions)
            );
        }

        {
            let mut versions = HashSet::<u32>::new();
            versions.insert(1);
            versions.insert(2);
            versions.insert(3);
            versions.insert(500);
            assert_eq!(
                String::from("1-3,500"),
                contract_protocol_list(&versions)
            );
        }
    }
}
