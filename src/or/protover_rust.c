/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file protover_rust.c
 * \brief Versioning information for different pieces of the Tor protocol.
 *
 * Starting in version 0.2.9.3-alpha, Tor places separate version numbers on
 * each of the different components of its protocol. Relays use these numbers
 * to advertise what versions of the protocols they can support, and clients
 * use them to find what they can ask a given relay to do.  Authorities vote
 * on the supported protocol versions for each relay, and also vote on the
 * which protocols you should have to support in order to be on the Tor
 * network. All Tor instances use these required/recommended protocol versions
 * to tell what level of support for recent protocols each relay has, and
 * to decide whether they should be running given their current protocols.
 *
 * The main advantage of these protocol versions numbers over using Tor
 * version numbers is that they allow different implementations of the Tor
 * protocols to develop independently, without having to claim compatibility
 * with specific versions of Tor.
 **/

/**
 * Given a protocol type and version number, return true iff we know
 * how to speak that protocol.
 */

#include "or.h"
#include "protover.h"
#include "rust_types.h"

#ifdef HAVE_RUST

int rust_protover_all_supported(const char *s, char **missing);
rust_str_ref_t rust_protover_compute_for_old_tor(const char *version);
rust_str_ref_t rust_protover_compute_vote(const smartlist_t *proto_votes, int threshold);
rust_str_ref_t rust_protover_get_supported_protocols(void);
int rust_protocol_list_supports_protocol(const char *list, protocol_type_t tp, uint32_t version);
int rust_protover_is_supported_here(protocol_type_t pr, uint32_t ver);

/**
 * This function is a wrapper for the Rust protover module, found at
 * rust_protover_is_supported_here in /src/rust/protover
 * Defined only when HAVE_RUST is defined.
 **/
int
protover_is_supported_here(protocol_type_t pr, uint32_t ver)
{
  return rust_protover_is_supported_here(pr, ver);
}

/**
 * This function is a wrapper for the Rust protover module, found at
 * rust_protover_list_supports_protocol in /src/rust/protover
 * Defined only when HAVE_RUST is defined.
 **/
int
protocol_list_supports_protocol(const char *list, protocol_type_t tp,
                                uint32_t version)
{
  return rust_protocol_list_supports_protocol(list, tp, version);
}

/**
 * This function is a wrapper for the Rust protover module, found at
 * rust_protover_get_supported_protocols in /src/rust/protover
 * Defined only when HAVE_RUST is defined.
 **/
const char *
protover_get_supported_protocols(void)
{
  rust_str_ref_t rust_protocols = rust_protover_get_supported_protocols();

  char *protocols = NULL;
  if (rust_protocols != NULL) {
    move_rust_str_to_c_and_free(rust_protocols, &protocols);
  }
  return protocols;
}

/**
 * This function is a wrapper for the Rust protover module, found at
 * rust_protover_compute_vote in /src/rust/protover
 * Defined only when HAVE_RUST is defined.
 **/
char *
protover_compute_vote(const smartlist_t *list_of_proto_strings,
                      int threshold)
{
  rust_str_ref_t rust_protocols = rust_protover_compute_vote(list_of_proto_strings, threshold);

  char *protocols = NULL;
  if (rust_protocols != NULL) {
    move_rust_str_to_c_and_free(rust_protocols, &protocols);
  }
  return protocols;
}

/**
 * This function is a wrapper for the Rust protover module, found at
 * rust_protover_all_supported in /src/rust/protover
 * Defined only when HAVE_RUST is defined.
 **/
int
protover_all_supported(const char *s, char **missing_out)
{
  rust_str_ref_t missing_out_copy = NULL;
  int is_supported  = rust_protover_all_supported(s, &missing_out_copy);

  if (!is_supported) {
    move_rust_str_to_c_and_free(missing_out_copy, missing_out);
  }

  return is_supported;
}

/**
 * This function is a wrapper for the Rust protover module, found at
 * rust_compute_for_old_tor in /src/rust/protover
 * Defined only when HAVE_RUST is defined.
 **/
const char *
protover_compute_for_old_tor(const char *version)
{
  rust_str_ref_t rust_protocols = rust_protover_compute_for_old_tor(version);

  char *protocols = NULL;
  if (rust_protocols != NULL) {
    move_rust_str_to_c_and_free(rust_protocols, &protocols);
  }
  return protocols;
}

#endif
