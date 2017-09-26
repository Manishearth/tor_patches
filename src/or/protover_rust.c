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

#ifdef HAVE_RUST

// This type is used to clearly mark strings that have been allocated in Rust,
// and therefore strictly need to use the free_rust_str method to free.
typedef char * rust_str;

int rust_protover_all_supported(const char *s, char **missing);
rust_str rust_protover_compute_for_old_tor(const char *version);
rust_str rust_protover_compute_vote(const smartlist_t *proto_votes, int threshold);
rust_str rust_protover_get_supported_protocols(void);
int rust_protocol_list_supports_protocol(const char *list, protocol_type_t tp, uint32_t version);
int rust_protover_is_supported_here(protocol_type_t pr, uint32_t ver);
void move_rust_str_to_c_and_free(char *src, char **dest);
void free_rust_str(char *ret);

/* Because Rust strings can only be freed from Rust, we first copy the string's
 * contents to a c pointer, and then free the Rust string.
 * TODO: This should go into a helper file in /src/common
 */
void move_rust_str_to_c_and_free(char *src, char **dest) {
  if (!src) {
    return;
  }

  if (!dest) {
    free_rust_str(src);
    return;
  }

  *dest = tor_strdup(src);
  free_rust_str(src);
}

int
protover_is_supported_here(protocol_type_t pr, uint32_t ver)
{
  return rust_protover_is_supported_here(pr, ver);
}

/**
 * Return true iff "list" encodes a protocol list that includes support for
 * the indicated protocol and version.
 */
int
protocol_list_supports_protocol(const char *list, protocol_type_t tp,
                                uint32_t version)
{
  return rust_protocol_list_supports_protocol(list, tp, version);
}
/** Return the canonical string containing the list of protocols
 * that we support. */
const char *
protover_get_supported_protocols(void)
{
  rust_str rust_protocols = rust_protover_get_supported_protocols();

  char *protocols = NULL;
  if (rust_protocols != NULL) {
    move_rust_str_to_c_and_free(rust_protocols, &protocols);
  }
  return protocols;
}

/**
 * Protocol voting implementation.
 *
 * Given a list of strings describing protocol versions, return a newly
 * allocated string encoding all of the protocols that are listed by at
 * least <b>threshold</b> of the inputs.
 *
 * The string is minimal and sorted according to the rules of
 * contract_protocol_list above.
 */
char *
protover_compute_vote(const smartlist_t *list_of_proto_strings,
                      int threshold)
{
  // copy data from rust macro
  rust_str rust_protocols = rust_protover_compute_vote(list_of_proto_strings, threshold);

  char *protocols = NULL;
  if (rust_protocols != NULL) {
    move_rust_str_to_c_and_free(rust_protocols, &protocols);
  }
  return protocols;
}

/** Return true if every protocol version described in the string <b>s</b> is
 * one that we support, and false otherwise.  If <b>missing_out</b> is
 * provided, set it to the list of protocols we do not support.
 *
 * NOTE: This is quadratic, but we don't do it much: only a few times per
 * consensus. Checking signatures should be way more expensive than this
 * ever would be.
 **/
int
protover_all_supported(const char *s, char **missing_out)
{
  char *missing_out_copy = NULL;
  int is_supported  = rust_protover_all_supported(s, &missing_out_copy);

  if (!is_supported) {
    move_rust_str_to_c_and_free(missing_out_copy, missing_out);
  }

  return is_supported;
}

/** Return a string describing the protocols supported by tor version
 * <b>version</b>, or an empty string if we cannot tell.
 *
 * Note that this is only used to infer protocols for Tor versions that
 * can't declare their own.
 **/
const char *
protover_compute_for_old_tor(const char *version)
{
  rust_str rust_protocols = rust_protover_compute_for_old_tor(version);

  char *protocols = NULL;
  if (rust_protocols != NULL) {
    move_rust_str_to_c_and_free(rust_protocols, &protocols);
  }
  return protocols;
}

#endif
