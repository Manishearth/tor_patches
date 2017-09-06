/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file protover.h
 * \brief Headers and type declarations for protover.c
 **/

#ifndef TOR_PROTOVER_H
#define TOR_PROTOVER_H

#include "container.h"
#include "compat_rust.h"

/** The first version of Tor that included "proto" entries in its
 * descriptors.  Authorities should use this to decide whether to
 * guess proto lines. */
/* This is a guess. */
#define FIRST_TOR_VERSION_TO_ADVERTISE_PROTOCOLS "0.2.9.3-alpha"

/** The protover version number that signifies HSDir support for HSv3 */
#define PROTOVER_HSDIR_V3 2
/** The protover version number that signifies HSv3 intro point support */
#define PROTOVER_HS_INTRO_V3 4

/** List of recognized subprotocols.
 *
 * Note that this submodule has a Rust implementation. In order to properly
 * translate C enums to Rust, we rely on the integer value of enums. This means
 * that this enum structure is order dependant. If the order of this enum needs
 * to be changed, be sure to update the corresponding Rust translation at
 * /src/rust/protover/ffi.rs
 *
 */
typedef enum protocol_type_t {
  PRT_LINK,
  PRT_LINKAUTH,
  PRT_RELAY,
  PRT_DIRCACHE,
  PRT_HSDIR,
  PRT_HSINTRO,
  PRT_HSREND,
  PRT_DESC,
  PRT_MICRODESC,
  PRT_CONS,
} protocol_type_t;

int protover_all_supported(const char *s, char **missing);
int protover_is_supported_here(protocol_type_t pr, uint32_t ver);
rust_str_t protover_get_supported_protocols(void);

rust_str_t protover_compute_vote(const smartlist_t *list_of_proto_strings,
                            int threshold);
rust_str_t protover_compute_for_old_tor(const char *version);
int protocol_list_supports_protocol(const char *list, protocol_type_t tp,
                                    uint32_t version);

void protover_free_all(void);

#ifdef PROTOVER_PRIVATE
/** Represents a range of subprotocols of a given type. All subprotocols
 * between <b>low</b> and <b>high</b> inclusive are included. */
typedef struct proto_range_t {
  uint32_t low;
  uint32_t high;
} proto_range_t;

/** Represents a set of ranges of subprotocols of a given type. */
typedef struct proto_entry_t {
  /** The name of the protocol.
   *
   * (This needs to handle voting on protocols which
   * we don't recognize yet, so it's a char* rather than a protocol_type_t.)
   */
  char *name;
  /** Smartlist of proto_range_t */
  smartlist_t *ranges;
} proto_entry_t;

STATIC void proto_entry_free(proto_entry_t *entry);

#ifndef HAVE_RUST
STATIC int str_to_protocol_type(const char *s, protocol_type_t *pr_out);
STATIC const char *protocol_type_to_str(protocol_type_t pr);
#endif

// Some functions are used as helpers for test_protover.c. Therefore, the below
// should be defined in the context of running tests, or if compiled without
// Rust support.
#if defined(TOR_UNIT_TESTS) ||  !defined(HAVE_RUST)
STATIC char *encode_protocol_list(const smartlist_t *sl);
STATIC smartlist_t *parse_protocol_list(const char *s);
STATIC void proto_entry_encode_into(smartlist_t *chunks, const proto_entry_t *entry);
#endif

#endif

#endif

