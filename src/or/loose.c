/* 
 * Copyright (c) 2015, Isis Lovecruft
 * Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file loose.c
 * \brief Functions for inserting additional hops into a loose-source routed circuit.
 *
 * See Tor proposal #188.
 **/

#define LOOSE_PRIVATE

#include "or.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuitstats.h"
#include "circuituse.h"
#include "command.h"
#include "connection_or.h"
#include "config.h"
#include "crypto.h"
#include "directory.h"
#include "loose.h"
#include "nodelist.h"
#include "relay.h"
#include "router.h"


static loose_or_circuit_t* loose_or_circuit_new(circid_t circ_id, channel_t *p_chan);
STATIC void loose_circuit_clear_cpath(loose_or_circuit_t *loose_circ);

/** Functions for getting information about a loose circuit's additional hops. */
static int loose_count_acceptable_nodes(void);
static char* loose_circuit_list_path(const loose_or_circuit_t *loose_circ, int verbose);
static char* loose_circuit_list_path_impl(const loose_or_circuit_t *loose_circ,
                                          int verbose, int verbose_names);

/** Functions for choosing additional hops in a loose-source routed circuit. */
static int loose_circuit_extend_cpath(loose_or_circuit_t *loose_circ,
                                      extend_info_t *entry);
static int loose_circuit_populate_cpath(loose_or_circuit_t *loose_circ,
                                        extend_info_t *entry);

/** Functions for handling specific cell types on a loose-source routed circuit. */
static int loose_circuit_finish_handshake(loose_or_circuit_t *loose_circ,
                                          const created_cell_t *reply);
static int loose_circuit_handle_first_hop(loose_or_circuit_t *loose_circ);
static int loose_circuit_extend_to_next_hop(loose_or_circuit_t *loose_circ);
static int loose_circuit_relay_cell_incoming(loose_or_circuit_t *loose_circ,
                                             crypt_path_t *layer_hint,
                                             cell_t *cell, cell_direction_t cell_direction);
static int loose_circuit_relay_cell_outgoing(loose_or_circuit_t *loose_circ,
                                             crypt_path_t *layer_hint,
                                             cell_t *cell, cell_direction_t cell_direction);


/** If 1, then we've successfully established a client circuit, and therefore
 * it's reasonable to believe we can handle creating loose circuits.
 */
char loose_circuits_are_possible = 0;
static char loose_can_complete_circuits = 0;


/**
 * Return 1 if we have successfully built a loose circuit, and nothing has
 * changed to make us think that maybe we can't.
 */
char
loose_have_completed_a_circuit(void)
{
  return loose_can_complete_circuits;
}

/**
 * Note that we have successfully built a loose circuit.
 */
void
loose_note_that_we_completed_a_circuit(void)
{
  loose_can_complete_circuits = 1;
}

/**
 * Note that something has happened (like a clock jump, or DisableNetwork) to
 * make us think that maybe we can't complete loose circuits.
 */
void
loose_note_that_we_maybe_cant_complete_circuits(void)
{
  loose_can_complete_circuits = 0;
}

/**
 * Allocate a new loose_or_circuit_t, containing the original <b>or_circ</b>.
 *
 * Based upon origin_circuit_new() and or_circuit_new().
 *
 * If <b>p_chan</b> is given, then connect the circuit to <b>p_chan</b> as
 * <b>p_circ_id</b>.  If <b>p_chan</b> is NULL, the circuit is unattached.
 *
 * Should only be called from loose_circuit_init().
 */
static loose_or_circuit_t *
loose_or_circuit_new(circid_t circ_id, channel_t *p_chan)
{
  loose_or_circuit_t *loose_circ;
  static uint32_t n_loose_circuits_allocated = 0;

  ++n_loose_circuits_allocated;
  log_debug(LD_CIRC, "Constructing loose_or_circuit_t. Number allocated: %d",
                     n_loose_circuits_allocated);

  loose_circ = tor_malloc_zero(sizeof(loose_or_circuit_t));
  loose_circ->or_.base_.magic = LOOSE_OR_CIRCUIT_MAGIC;

  /* We can't call or_circuit_new() here because the memory for the
   * or_circuit_t would get allocated twice. */
  if (p_chan)
    circuit_set_p_circid_chan(LOOSE_TO_OR_CIRCUIT(loose_circ), circ_id, p_chan);

  /* Behave as if we're the origin of this circuit by decrementing the maximum
   * RELAY_EARLY cell count in the same manner as in origin_circuit_new(). */
  loose_circ->or_.remaining_relay_early_cells = MAX_RELAY_EARLY_CELLS_PER_CIRCUIT;
  loose_circ->or_.remaining_relay_early_cells -= crypto_rand_int(2);
  cell_queue_init(&loose_circ->or_.p_chan_cells);
  init_circuit_base(LOOSE_TO_CIRCUIT(loose_circ));

  /* XXXprop#188 Do we want to update circuit build times for these weird
   *             circuits?  like it's done in origin_circuit_new()?        */
  circuit_build_times_update_last_circ(get_circuit_build_times_mutable());

  return loose_circ;
}

/**
 * Create and return a new loose-source routed circuit. Initialize its purpose
 * and build_state based upon our arguments.  The <b>flags</b> argument is a
 * bitfield of CIRCLAUNCH_* flags.
 *
 * Based upon origin_circuit_init().
 *
 * Should only be called from loose_circuit_establish_circuit().
 */
STATIC loose_or_circuit_t *
loose_or_circuit_init(circid_t circ_id, channel_t *p_chan,
                      uint8_t purpose, int flags)
{
  loose_or_circuit_t *loose_circ = loose_or_circuit_new(circ_id, p_chan);

  log_debug(LD_CIRC, "Initializing loose circuit...");

  circuit_set_state(LOOSE_TO_CIRCUIT(loose_circ), CIRCUIT_STATE_CHAN_WAIT);
  loose_circ->build_state = tor_malloc_zero(sizeof(cpath_build_state_t));
  loose_circ->build_state->onehop_tunnel =
    ((flags & CIRCLAUNCH_ONEHOP_TUNNEL) ? 1 : 0);
  loose_circ->build_state->need_uptime =
    ((flags & CIRCLAUNCH_NEED_UPTIME) ? 1 : 0);
  loose_circ->build_state->need_capacity =
    ((flags & CIRCLAUNCH_NEED_CAPACITY) ? 1 : 0);
  loose_circ->build_state->is_internal =
    ((flags & CIRCLAUNCH_IS_INTERNAL) ? 1 : 0);
  loose_circ->or_.base_.purpose = purpose;

  return loose_circ;
}

/**
 * Primary function for building a new loose-source routed circuit for a given
 * <b>purpose</b>.
 * 
 * If <b>entry</b> is given, use that node as the first additional hop.
 * Otherwise, pick a suitable entry guard.
 *
 * If <b>len</b> is greater than 0, then choose <b>len</b> number of hops to
 * inject into the underlying or_circuit_t.  Otherwise, if <b>len</b> is 0,
 * use the default (DEFAULT_LOOSE_ROUTE_LEN).
 *
 * Also, launch a connection to the first OR in the chosen path, if it's not
 * open already.  Finally, if the original create <b>cell</b> is given, store
 * a copy of it so that we can answer the client later (after constucting the
 * rest of our loose circuit).
 *
 * Based upon circuit_establish_circuit().
 */
loose_or_circuit_t *
loose_circuit_establish_circuit(circid_t circ_id, channel_t *p_chan,
                                extend_info_t *entry, int len,
                                uint8_t purpose, int flags, cell_t *cell)
{
  loose_or_circuit_t *loose_circ;
  int err_reason = 0;
  int length;

  if (!loose_circuits_are_possible) {
    log_debug(LD_GENERAL,
              "Started an attempt to establish a loose circuit, but it appears "
              "we haven't bootstrapped yet! Holding off on client connections "
              "for now.");
    return NULL;
  }

  loose_circ = loose_or_circuit_init(circ_id, p_chan, purpose, flags);
  log_debug(LD_CIRC, "Establishing loose circuit...");

  /* Allocate space for loose_circ->p_chan_create_cell and copy it */
  if (cell) {
    loose_circ->p_chan_create_cell = tor_malloc_zero(sizeof(cell_t));
    loose_circ->p_chan_create_cell = cell;
  }

  /* Determine the appropriate path length and store it in the state. */
  length = (len > 0) ? len : DEFAULT_LOOSE_ROUTE_LEN; // XXX cap to maximum?
  loose_circ->build_state->desired_path_len = length;

  entry = loose_circuit_pick_cpath_entry(loose_circ, entry);
  if (loose_circuit_populate_cpath(loose_circ, entry) < 0) {
    circuit_mark_for_close(LOOSE_TO_CIRCUIT(loose_circ), END_CIRC_REASON_NOPATH);
    return NULL;
  }
  // XXXprop#188 Do we want control events?
  //control_event_circuit_status(circ, CIRC_EVENT_LAUNCHED, 0);

  if ((err_reason = loose_circuit_handle_first_hop(loose_circ)) < 0) {
    circuit_mark_for_close(LOOSE_TO_CIRCUIT(loose_circ), -err_reason);
    return NULL;
  }

  assert_circuit_ok(LOOSE_TO_CIRCUIT(loose_circ));
  return loose_circ;
}

/**
 * Decide a suitable length for <b>loose_circ-&gt;cpath</b>, and pick an entry
 * router (or use <b>entry</b> if provided). Store these in the cpath.
 *
 * The returned extend_info_t will need to be freed later with
 * extend_info_free().
 *
 * Returns NULL if no <b>entry</b> was given and choose_good_entry_server()
 * was not able to find a suitable entry node.
 */
STATIC extend_info_t *
loose_circuit_pick_cpath_entry(loose_or_circuit_t *loose_circ,
                               extend_info_t *entry)
{
  extend_info_t *entry_ei;
  const node_t *node;

  if (entry) {          /* A first hop was specifically requested. */
    log_info(LD_CIRC, "Using requested first hop %s",
                      extend_info_describe(entry));
    /* XXXprop#188 Should we try to warn if the entry is in ExcludeNodes? */
    //entry_ei = extend_info_dup(entry);
    entry_ei = entry;
  } else {              /* We should pick an entry node */
    node = choose_good_entry_server(CIRCUIT_PURPOSE_OR,
                                    loose_circ->build_state);
    if (!node) {
      log_warn(LD_CIRC, "Failed to pick a suitable first hop for loose circuit.");
      return NULL;
    }
    entry_ei = extend_info_from_node(node, 0);
    tor_assert(entry_ei);
  }

  return entry_ei;
}

/**
 * Choose a suitable next hop in the <b>loose_circ-&gt;cpath-&gthead_ptr</b>,
 * based on <b>state</b>. Append the hop info to head_ptr.
 *
 * Based upon onion_extend_cpath().
 *
 * Return 1 if the path is complete, 0 if we successfully added a hop, and -1
 * on error.
 */
static int
loose_circuit_extend_cpath(loose_or_circuit_t *loose_circ, extend_info_t *entry)
{
  uint8_t purpose = loose_circ->or_.base_.purpose;
  cpath_build_state_t *state = loose_circ->build_state;
  int cur_len = cpath_get_len(loose_circ->cpath);
  extend_info_t *info = NULL;
  crypt_path_t *exit = NULL;

  if (cur_len >= state->desired_path_len) {
    log_debug(LD_CIRC, "Path is complete: %d steps long",
              state->desired_path_len);
    /* Store the last hop in our build_state so that utilities which expect it
     * to be there have it. */
    exit = cpath_get_hop(loose_circ->cpath, cur_len);
    state->chosen_exit = extend_info_dup(exit->extend_info);

    return 1;
  }

  log_debug(LD_CIRC, "Path is %d long; we want %d",
                     cur_len, state->desired_path_len);

  if (cur_len == 0) {
    if (!entry) {
      return -1;
    } else {
      info = extend_info_dup(entry);
    }
  } else {              /* Choose ORs until we've reached the desired length. */
    const node_t *r =
      choose_good_middle_server(purpose, state, loose_circ->cpath, cur_len);
    if (r) {
      info = extend_info_from_node(r, 0);
      tor_assert(info);
    }
  }
  if (!info) {
    log_warn(LD_CIRC, "Failed to find node for hop %d of our path. Discarding "
                      "this circuit.", cur_len);
    return -1;
  }
  log_debug(LD_CIRC, "Chose router %s for hop %d in loose circuit",
                      extend_info_describe(info), cur_len+1);
  onion_append_hop(&loose_circ->cpath, info);
  extend_info_free(info);

  return 0;
}

/**
 * Choose all the hops for <b>loose_circ-&gt;cpath</b>.  Stop and return 0
 * when we're happy, or return -1 if an error occurs.
 *
 * Plagiarised (pretty much completely) from circuit_populate_cpath(), and
 * TODO we should find a way to refactor circuit_populate_cpath that can
 * accommodate both origin_circuit_t and loose_or_circuit_t.
 *
 * Returns 0 if successful, otherwise -1 if there was some problem.
 */
static int
loose_circuit_populate_cpath(loose_or_circuit_t *loose_circ,
                             extend_info_t *entry)
{
  int n_tries = 0;
  const int using_ntor = circuits_can_use_ntor();

#define LOOSE_CIRCUIT_MAX_POPULATE_ATTEMPTS 32

  while (1) {
    int r = loose_circuit_extend_cpath(loose_circ, entry);
    if (r < 0) {
      log_info(LD_CIRC,"Generating cpath hop failed.");
      return -1;
    }
    if (r == 1) {
      /* This circuit doesn't need/shouldn't be forced to have an ntor hop */
      // XXXprop#188 Why do we not care if it's ntor if it's only one hop?
      if (loose_circ->build_state->desired_path_len <= 1 || ! using_ntor)
        return 0;
      /* This circuit has an ntor hop. great! */
      if (cpath_supports_ntor(loose_circ->cpath))
        return 0;
      /* No node in the circuit supports ntor.  Have we already tried too many
       * times? */
      if (++n_tries >= LOOSE_CIRCUIT_MAX_POPULATE_ATTEMPTS)
        break;
      /* Clear the path and retry */
      loose_circuit_clear_cpath(loose_circ);
    }
  }
  log_warn(LD_CIRC, "I tried for %d times, but I couldn't build a %d-hop "
           "loose circuit with at least one node that supports ntor.",
           LOOSE_CIRCUIT_MAX_POPULATE_ATTEMPTS,
           loose_circ->build_state->desired_path_len);

  return -1;
}

/**
 * Deallocate the linked list <b>loose_circ-&gt;cpath</b>, and remove the
 * cpath from <b>loose_circ</b>.
 *
 * Blatantly copied from circuit_clear_cpath().
 */
STATIC void
loose_circuit_clear_cpath(loose_or_circuit_t *loose_circ)
{
  crypt_path_t *victim, *head, *cpath;

  head = cpath = loose_circ->cpath;

  if (!cpath)
    return;

  /* It's circular, so we have to notice once we've gone all the way around. */
  while (cpath->next && cpath->next != head) {
    victim = cpath;
    cpath = victim->next;
    circuit_free_cpath_node(victim);
  }

  circuit_free_cpath_node(cpath);

  loose_circ->cpath = NULL;
}

/**
 * Free <b>loose_circ</b> and clear its cpath (by calling
 * loose_circuit_clear_cpath()) and build_state (by calling tor_free()).
 *
 * The rest of the memory freeing should be taken care of in circuit_free(),
 * since TO_OR_CIRCUIT() will also turn our loose_or_circuit_t into an
 * or_circuit_t, and free the members within that portion of the struct.
 *
 * TODO: Rather than calling loose_circuit_clear_cpath(), it would be great if
 * we could refactor circuit_clear_cpath() such that it could accommodate both
 * origin_circuit_t and loose_or_circuit_t. -IL
 */
void
loose_circuit_free(loose_or_circuit_t *loose_circ)
{
  static uint32_t n_loose_circuits_deallocated = 0;

  if (!loose_circ || !CIRCUIT_IS_LOOSE(loose_circ)) {
    log_warn(LD_BUG, "loose_circuit_free called with NULL/other circuit type!");
    return;
  }
  ++n_loose_circuits_deallocated;
  log_debug(LD_CIRC, "Freeing loose_or_circuit_t. Number deallocated: %d",
                     n_loose_circuits_deallocated);
  tor_free(loose_circ->build_state);
  loose_circuit_clear_cpath(loose_circ);
}

/**
 * Iterate through the hops in <b>loose_circ-&gt;cpath</b>, and allocate and
 * return information about the hops.
 *
 * If <b>verbose</b> is false, allocate and return a comma-separated list of
 * the currently built elements of <b>circ</b>.  If <b>verbose</b> is true,
 * also list information about link status in a more verbose format using
 * spaces.
 *
 * If <b>verbose_names</b> is false, give nicknames for Named routers and hex
 * digests for others; if <b>verbose_names</b> is true, use $DIGEST=Name style
 * names.
 *
 * Based upon circuit_list_path_impl().
 *
 * The returned string will need to be freed by the caller.
 *
 * Returns a string describing the hops in <b>loose_circ-&gt;cpath</b>.
 */
static char *
loose_circuit_list_path_impl(const loose_or_circuit_t *loose_circ,
                             int verbose, int verbose_names)
{
  smartlist_t *elements;
  char *s;

  elements = smartlist_new();

  if (verbose) {
    const char *nickname = build_state_get_exit_nickname(loose_circ->build_state);
    smartlist_add_asprintf(
      elements, "%s%s circ (length %d%s%s):",
      loose_circ->build_state->is_internal ? "internal" : "exit",
      loose_circ->build_state->need_uptime ? " (high-uptime)" : "",
      loose_circ->build_state->desired_path_len,
      (LOOSE_TO_CIRCUIT(loose_circ))->state == CIRCUIT_STATE_OPEN ? "" : ", last hop ",
      (LOOSE_TO_CIRCUIT(loose_circ))->state == CIRCUIT_STATE_OPEN ? "" :
      (nickname ? nickname : "*unnamed*"));
  }

  circuit_list_cpath(loose_circ->cpath, elements, verbose);

  s = smartlist_join_strings(elements, verbose ? " " : ",", 0, NULL);
  SMARTLIST_FOREACH(elements, char*, cp, tor_free(cp));
  smartlist_free(elements);
  return s;
}

/**
 * If <b>verbose</b> is false, allocate and return a comma-separated
 * list of the currently built elements of <b>loose_circ</b>.  If
 * <b>verbose</b> is true, also list information about link status in
 * a more verbose format using spaces.
 *
 * The returned string will need to be freed by the caller.
 */
static char *
loose_circuit_list_path(const loose_or_circuit_t *loose_circ, int verbose)
{
  return loose_circuit_list_path_impl(loose_circ, verbose, 0);
}

/** Log, at severity <b>severity</b>, and with log <b>domain</b>, the
 * nicknames of each router in <b>loose_circ</b>'s cpath. Also log the length
 * of the cpath, and the intended exit point.
 *
 * This is done by calling loose_circuit_list_path(), logging the returned
 * string, and then freeing it.
 */
STATIC void
loose_circuit_log_path(int severity, unsigned int domain,
                       const loose_or_circuit_t *loose_circ)
{
  char *s = loose_circuit_list_path(loose_circ, 1);
  tor_log(severity, domain, "%s", s);
  tor_free(s);
}

/**
 * Returns true if we should use CREATE_FAST cells to establish a connection
 * to the first injected hop in a loose-source routed circuit.
 *
 * Returns true always.
 */
MOCK_IMPL(STATIC int, loose_circuit_should_use_create_fast,(void))
{
  return 1;
}

/**
 * Start establishing the first injected hop of our loose-source routed
 * circuit.  Figure out what OR we should connect to, and if necessary start
 * the connection to it.  If we're already connected, then send the CREATE
 * cell.
 *
 * Plagiarised from circuit_handle_first_hop() in circuitbuild.c.
 *
 * Return 0 for ok, -reason if <b>loose_circ</b> should be marked for close.
 */
static int
loose_circuit_handle_first_hop(loose_or_circuit_t *loose_circ)
{
  crypt_path_t *firsthop;
  channel_t *n_chan;
  int err_reason = 0;
  const char *msg = NULL;
  int should_launch = 0;

  firsthop = onion_next_hop_in_cpath(loose_circ->cpath);
  tor_assert(firsthop);
  tor_assert(firsthop->extend_info);

  /* Now see if we're already connected to the first injected hop. */
  log_debug(LD_CIRC, "Looking for first loose-source routed hop %s...",
            safe_str(fmt_addrport(&firsthop->extend_info->addr,
                                  firsthop->extend_info->port)));

  n_chan = channel_get_for_extend(firsthop->extend_info->identity_digest,
                                  &firsthop->extend_info->addr,
                                  &msg,
                                  &should_launch);

  /* Not currently connected in a useful way. */
  if (!n_chan) {
    log_info(LD_CIRC, "Next router is %s: %s",
             safe_str(extend_info_describe(firsthop->extend_info)),
             msg ? msg : "???");
    loose_circ->or_.base_.n_hop = extend_info_dup(firsthop->extend_info);

    if (should_launch) {
      n_chan = channel_connect_for_circuit(
          &firsthop->extend_info->addr,
          firsthop->extend_info->port,
          firsthop->extend_info->identity_digest);
      if (!n_chan) {
        log_info(LD_CIRC, "Connection to first loose-source routed hop %s "
                          "failed. Closing.",
                          safe_str(fmt_addrport(&firsthop->extend_info->addr,
                                                firsthop->extend_info->port)));
        return -END_CIRC_REASON_CONNECTFAILED;
      }
    }
    log_debug(LD_CIRC, "Connection to %s for loose circuit in progress "
                       "(or finished). Good.",
                       safe_str(fmt_addrport(&firsthop->extend_info->addr,
                                             firsthop->extend_info->port)));
    /* Return success. The circuit will be taken care of automatically (it
     * may already have been) whenever n_chan reaches OR_CONN_STATE_OPEN. */
    return 0;
  } else {  /* We already have an open connection. Use it. */
    tor_assert(!loose_circ->or_.base_.n_hop);
    loose_circ->or_.base_.n_chan = n_chan;
    log_debug(LD_CIRC, "Connection to %s for loose circuit open. "
                       "Delivering first onion skin.",
                       safe_str(fmt_addrport(&firsthop->extend_info->addr,
                                             firsthop->extend_info->port)));
    if ((err_reason = loose_circuit_send_next_onion_skin(loose_circ)) < 0) {
      log_info(LD_CIRC, "loose_circuit_send_next_onion_skin failed.");
      loose_circ->or_.base_.n_chan = NULL;
      return err_reason;
    }
  }
  return 0;
}

/**
 * Begin to add additional hops to a circuit, <b>or_circ</b>, (for which we
 * are acting as an OR) by sending some type of CREATE* cell to the first hop
 * we would like to add.
 *
 * Plagiarised from the first half of circuit_send_next_onion_skin().
 */
int
loose_circuit_create(loose_or_circuit_t *loose_circ)
{
  create_cell_t *cc;
  int len;

  if (!loose_circ || !CIRCUIT_IS_LOOSE(loose_circ)) {
    log_warn(LD_BUG, "loose_circuit_create() wasn't called with a loose circuit!");
    return -END_CIRC_REASON_INTERNAL;
  }

  cc = tor_malloc_zero(sizeof(create_cell_t));

  if (loose_circuit_should_use_create_fast() != 0) {
    cc->cell_type = CELL_CREATE_FAST;
    cc->handshake_type = ONION_HANDSHAKE_TYPE_FAST;
    note_request("cell: create fast", 1);
  } else {
    log_warn(LD_CIRC, "Don't know how to use a CREATE or CREATE2 cell to "
                      "establish a circuit to our first additional hop.");
    return -END_CIRC_REASON_INTERNAL;
  }

  log_debug(LD_CIRC,
            "Creating onionskin with %s cell for hop %s on loose circuit.",
            cell_command_to_string(cc->cell_type),
            safe_str(extend_info_describe(loose_circ->cpath->extend_info)));
  len = onion_skin_create(cc->handshake_type,
                          loose_circ->cpath->extend_info,
                          &loose_circ->cpath->handshake_state,
                          cc->onionskin);
  if (len < 0) {
    log_warn(LD_CIRC, "onion_skin_create for loose circuit failed.");
    return -END_CIRC_REASON_INTERNAL;
  }
  cc->handshake_len = len;

  /* For the following to have effect, the circuit should be in
   * CIRCUIT_STATE_CHAN_WAIT (in order to get circuit_n_chan_done() to call
   * circuit_deliver_create_cell() with the stored create cell for us. */
  LOOSE_TO_CIRCUIT(loose_circ)->n_chan_create_cell = cc;
  log_debug(LD_CIRC,
            "Loose circuit n_chan is %s. (expected: \"%s\" or \"%s\")",
            circuit_state_to_string(LOOSE_TO_CIRCUIT(loose_circ)->state),
            circuit_state_to_string(CIRCUIT_STATE_CHAN_WAIT),
            circuit_state_to_string(CIRCUIT_STATE_OPEN));

  /* Set the circuit state to CIRCUIT_STATE_CHAN_WAIT so that
   * circuit_n_chan_done() can find our circuit and deliver the stored
   * create cell. */
  circuit_set_state(LOOSE_TO_CIRCUIT(loose_circ), CIRCUIT_STATE_CHAN_WAIT);

  /*
  if (LOOSE_TO_CIRCUIT(loose_circ)->state == CIRCUIT_STATE_OPEN) {
    log_debug(LD_CIRC,
              "Channel to first hop %s was already open! "
              "Sending %s cell to %s for loose circuit...",
              safe_str(extend_info_describe(loose_circ->cpath->extend_info)),
              cell_command_to_string(cc->cell_type),
              safe_str(extend_info_describe(loose_circ->cpath->extend_info)));
    if (circuit_deliver_create_cell(
         LOOSE_TO_CIRCUIT(loose_circ),
         LOOSE_TO_CIRCUIT(loose_circ)->n_chan_create_cell, 0) < 0) {
      return -END_CIRC_REASON_RESOURCELIMIT;
    }

    circuit_set_state(LOOSE_TO_CIRCUIT(loose_circ), CIRCUIT_STATE_BUILDING);
  } */

  loose_circ->cpath->state = CPATH_STATE_AWAITING_KEYS;
  return 0;
}

/**
 * A CREATED cell, <b>reply</b>, came back to us on circuit
 * <b>loose_circ</b>.  (The body of <b>reply</b> varies depending on what sort
 * of handshake this is.)
 *
 * Calculate the appropriate keys and digests, make sure KH is correct, and
 * initialize this hop of the cpath.
 *
 * Blatantly plagiarised from circuit_finish_handshake().
 *
 * NOTE: We do _not_ want to count loose-source routed circuits, into which we
 * are injecting additional hops, w.r.t path bias calculations. This is due to
 * the simple reason that an OP could specify us (an OR) within a circuit path
 * which also includes a bunch of other ORs -- which the OP knows to be down
 * or misbehaving -- thus causing us to conclude that something is wrong with
 * our Guard (or some other node(s) we chose to inject into the OP's circuit)
 * and pick a new Guard.
 *
 * Return -<b>reason</b> if we want to mark <b>loose_circ</b> for close, else
 * return 0.
 */
static int
loose_circuit_finish_handshake(loose_or_circuit_t *loose_circ,
                               const created_cell_t *reply)
{
  char keys[CPATH_KEY_MATERIAL_LEN];
  crypt_path_t *hop;
  const char *msg = NULL;

  tor_assert(reply);
  tor_assert(loose_circ->cpath);

  if (loose_circ->cpath->state == CPATH_STATE_AWAITING_KEYS) {
    hop = loose_circ->cpath;
  } else {
    hop = onion_next_hop_in_cpath(loose_circ->cpath);
    if (!hop) {     /* We got an EXTENDED when we're all done? */
      log_warn(LD_PROTOCOL, "We got an extended when loose-source routed "
                            "circuit was already built? Closing.");
      return -END_CIRC_REASON_TORPROTOCOL;
    }
  }

  if (hop->state != CPATH_STATE_AWAITING_KEYS) {
    log_warn(LD_PROTOCOL, "The first injected hop in our loose-source routed "
                          "circuit was in strange state %d (expected: %d). "
                          "Closing.", hop->state, CPATH_STATE_AWAITING_KEYS);
    return -END_CIRC_REASON_TORPROTOCOL;
  }

  if (onion_skin_client_handshake(hop->handshake_state.tag,
                                  &hop->handshake_state,
                                  reply->reply, reply->handshake_len,
                                  (uint8_t*)keys, sizeof(keys),
                                  (uint8_t*)hop->rend_circ_nonce,
                                  &msg) < 0) {
    if (msg) {
      log_warn(LD_CIRC, "onion_skin_client_handshake failed for loose "
                        "circuit: %s", msg);
      return -END_CIRC_REASON_TORPROTOCOL;
    }
  }

  onion_handshake_state_release(&hop->handshake_state);

  if (circuit_init_cpath_crypto(hop, keys, 0) < 0) {
    return -END_CIRC_REASON_TORPROTOCOL;
  }

  hop->state = CPATH_STATE_OPEN;
  log_info(LD_CIRC, "Finished building loose-source routed circuit hop:");
  loose_circuit_log_path(LOG_INFO, LD_CIRC, loose_circ);
  // XXXprop#188 Do we want controller events?
  //control_event_circuit_status(loose_circ, CIRC_EVENT_EXTENDED, 0);

  return 0;
}

/**
 * Process a <b>created_cell</b>, which has just arrived on <b>loose_circ</b>.
 *
 * The <b>create_cell</b> will be handed to loose_circuit_finish_handshake()
 * in order to establish the shared keys with the OR that sent the
 * <b>create_cell</b> to us.
 *
 * Lastly, loose_circuit_send_next_onion_skin() will be called to send the
 * next cell.
 *
 * Returns 0 on success, otherwise returns -REASON for which <b>loose_circ</b>
 * should be closed.
 */
int
loose_circuit_process_created_cell(loose_or_circuit_t *loose_circ,
                                   created_cell_t *created_cell)
{
  int err = 0;

  log_debug(LD_OR, "Processing created cell from first additional hop "
                   "in a loose-source routed circuit.");

  tor_assert(loose_circ);
  tor_assert(CIRCUIT_IS_LOOSE(loose_circ));

  err = loose_circuit_finish_handshake(loose_circ, created_cell);
  if (err < 0) {
    log_info(LD_OR, "loose_circuit_finish_handshake failed.");
    return err;
  }
  log_debug(LD_OR, "Moving to next skin for loose circuit.");

  if ((err = loose_circuit_send_next_onion_skin(loose_circ)) < 0) {
    log_info(LD_OR, "loose_circuit_send_next_onion_skin failed.");
    return err;
  }

  return 0;
}

/**
 * Return the number of routers that are currently up and available for
 * building circuits through.
 */
static int
loose_count_acceptable_nodes(void)
{
  const or_options_t *options = get_options();
  int num = 0;

  SMARTLIST_FOREACH(nodelist_get_list(), const node_t *, node, {
    /* Don't count nodes which either aren't running. */
    if (!node->is_running)
      continue;
    /* If the node is invalid, check if our AllowInvalidRouters settings would
     * let us use the node in as a middle or an exit.  If neither, don't count
     * it. */
    if (!(node->is_valid || (options->AllowInvalid_ &
                             (ALLOW_INVALID_MIDDLE || ALLOW_INVALID_EXIT))))
      continue;
    /* Don't count nodes for which we're missing a descriptor. */
    if (!node_has_descriptor(node))
      continue;
    /* Don't count nodes which allow single hop exits, if we're excluding them. */
    if (options->ExcludeSingleHopRelays && node_allows_single_hop_exits(node))
      continue;
    ++num;
  });
  return num;
}

/**
 * Do additional actions after <b>loose_circ</b> has finished building.
 */
STATIC void
loose_circuit_has_opened(loose_or_circuit_t *loose_circ)
{
  int reason;

  /* Mark that this circuit has been successfully opened, that we can treat it
   * differently in the case that we try to extend it further later. */
  loose_circ->has_opened = 1;
  circuit_reset_failure_count(0);

  /* If this is the first (recent) loose circuit we've built, then note so,
   * and clear the state storing information on whether we're online/offline
   * or have broken connections. */
  if (!loose_have_completed_a_circuit()) {
    loose_note_that_we_completed_a_circuit();
    log_notice(LD_GENERAL, "Tor has successfully constructed a "
                           "loose-source routed circuit.");
    log_notice(LD_GENERAL, "We currently know of %d routers in the network.",
                           loose_count_acceptable_nodes());
    clear_broken_connection_map(1);
  }

  /* Free the create cell stored in circ->n_chan_create_cell. */
  //tor_free(LOOSE_TO_CIRCUIT(loose_circ)->n_chan_create_cell);  // XXX
  //LOOSE_TO_CIRCUIT(loose_circ)->n_chan_create_cell = NULL;

  circuit_set_state(LOOSE_TO_CIRCUIT(loose_circ), CIRCUIT_STATE_OPEN);
  log_info(LD_CIRC, "Loose circuit built!");

  if (loose_circ->p_chan_create_cell) {
    log_debug(LD_CIRC, "Sending created cell back to OP...");
    reason = command_answer_create_cell(LOOSE_TO_CIRCUIT(loose_circ),
                                        LOOSE_TO_OR_CIRCUIT(loose_circ)->p_chan,
                                        loose_circ->p_chan_create_cell);
    if (reason < 0) {
      log_warn(LD_CIRC,
               "Error while responding to OP create cell for loose circuit.");
      circuit_mark_for_close(LOOSE_TO_CIRCUIT(loose_circ), reason);
    }
    log_debug(LD_CIRC, "Finished sending CREATED to OP on loose circuit %d",
                       LOOSE_TO_CIRCUIT(loose_circ)->global_circuitlist_idx);
    tor_free(loose_circ->p_chan_create_cell);
  }
}

/**
 * Extend a <b>loose_circ</b> according to the hops in its cpath.
 * 
 * Returns 0 on success, and -<b>reason</b> if the circuit should be closed.
 */
int
loose_circuit_extend(loose_or_circuit_t *loose_circ)
{
  const crypt_path_t *cpath;
  crypt_path_t *hop;
  int reason;

  cpath = loose_circ->cpath;
  hop = onion_next_hop_in_cpath(loose_circ->cpath);

  while (hop && hop != cpath) {
    log_debug(LD_CIRC, "Deciding whether to extend loose circuit...");

    /* If we don't have another hop, then we're done with doing our own
     * EXTEND*s (to inject additional hops into this circuit).  We'll handle
     * the OP's EXTENDS in loose_circuit_relay_cell_incoming(). */
    if (hop && hop != cpath) {
      reason = loose_circuit_extend_to_next_hop(loose_circ);
      if (reason < 0) {
        return reason;
      }
    }
    hop = onion_next_hop_in_cpath(loose_circ->cpath);
  }

  log_debug(LD_CIRC, "We're done extending loose circuit.");
  /* We skip doing circuit build timeout stuffs here, because we don't want to
   * timeout a loose circuit when we're really building it for an OP.  The OP
   * can timeout on their origin_circuit_t if our underlying or_circuit_t is
   * taking too long. */
  loose_circuit_has_opened(loose_circ); /* Do other actions as necessary. */

  /* XXXX Also, we're skipping calling circuit_rep_hist_note_result() (or some
   * version that could handle loose_or_circuit_t). We probably *do* want to
   * hack this in, in the future. -IL */
  return 0;
}

/**
 * Extend <b>loose_circ</b> to the next hop in <b>loose_circ-&gt;cpath</b>.
 *
 * Mostly plagiarised from the `else` clause in circuit_send_next_onion_skin().
 *
 * Returns 0 on success, and -<b>reason</b> if the circuit should be closed.
 */
static int
loose_circuit_extend_to_next_hop(loose_or_circuit_t *loose_circ)
{
  extend_cell_t extend;
  const node_t *prev_node;
  crypt_path_t *hop;
  int len;

  tor_assert(loose_circ->cpath->state == CPATH_STATE_OPEN);
  tor_assert((LOOSE_TO_CIRCUIT(loose_circ))->state == CIRCUIT_STATE_BUILDING);
  hop = onion_next_hop_in_cpath(loose_circ->cpath);
  memset(&extend, 0, sizeof(extend));

  log_debug(LD_CIRC, "Extending loose circuit to %s.",
                     hop->extend_info->identity_digest);

  if (!(CIRCUIT_IS_LOOSE(loose_circ))) {
    log_warn(LD_BUG, "Tried to call loose_circuit_extend_to_hop() for "
                     "non-loose circuit!");
    return -END_CIRC_REASON_INTERNAL;
  }

  if (tor_addr_family(&hop->extend_info->addr) != AF_INET) {
    log_warn(LD_BUG, "Trying to extend to a non-IPv4 address.");
    return -END_CIRC_REASON_INTERNAL;
  }
    
  prev_node = node_get_by_id(hop->prev->extend_info->identity_digest);
  circuit_pick_extend_handshake(&extend.cell_type,
                                &extend.create_cell.cell_type,
                                &extend.create_cell.handshake_type,
                                prev_node,
                                hop->extend_info);

  tor_addr_copy(&extend.orport_ipv4.addr, &hop->extend_info->addr);
  extend.orport_ipv4.port = hop->extend_info->port;
  tor_addr_make_unspec(&extend.orport_ipv6.addr);
  memcpy(extend.node_id, hop->extend_info->identity_digest, DIGEST_LEN);

  len = onion_skin_create(extend.create_cell.handshake_type,
                          hop->extend_info,
                          &hop->handshake_state,
                          extend.create_cell.onionskin);
  if (len < 0) {
    log_warn(LD_CIRC, "onion_skin_create failed for loose circuit.");
    return -END_CIRC_REASON_INTERNAL;
  }
  extend.create_cell.handshake_len = len;

  log_info(LD_CIRC, "Sending extend relay cell for loose circuit.");
  note_request("cell: extend", 1);
  {
    uint8_t command = 0;
    uint8_t payload[RELAY_PAYLOAD_SIZE];
    uint16_t payload_len = 0;

    if (extend_cell_format(&command, &payload_len, payload, &extend) < 0) {
      log_warn(LD_CIRC, "Couldn't format extend cell for loose circuit.");
      return -END_CIRC_REASON_INTERNAL;
    }

    /* Send it to hop->prev, because it will transfer it to a create cell and
     * then send to hop. */
    /* XXXprop#188  WAT.  Is this really what we do??? */
    if (relay_send_command_from_edge(0, LOOSE_TO_CIRCUIT(loose_circ), command,
                                     (char*)payload, payload_len, hop->prev) < 0) {
      return 0; /* Circuit is closed.*/
    }
    hop->state = CPATH_STATE_AWAITING_KEYS;
  }
  return 0;
}

/**
 * Having received a recognized cell from our first addition hop on a loose
 * circuit, we should upwrap and decrypt the cell w.r.t. each of the
 * additional hops, and send it back along the circuit to the OP.
 *
 * Returns 0 on success, and -<b>reason</b> if the circuit should be closed.
 */
static int
loose_circuit_relay_cell_incoming(loose_or_circuit_t *loose_circ,
                                  crypt_path_t *layer_hint,
                                  cell_t *cell, cell_direction_t cell_direction)
{
  channel_t *chan;        /* Where to send the cell. */
  crypt_path_t *this_hop; /* The hop we're currently decrypting from. */
  crypt_path_t *cpath;
  relay_header_t rh;

  log_debug(LD_OR, "Handling incoming relay cell type %d on loose circuit %d.",
            cell->command, LOOSE_TO_CIRCUIT(loose_circ)->global_circuitlist_idx);

  /* Set the circ_id to the one for the previous hop. */
  cell->circ_id = LOOSE_TO_OR_CIRCUIT(loose_circ)->p_circ_id;
  chan = LOOSE_TO_OR_CIRCUIT(loose_circ)->p_chan;
  this_hop = cpath = loose_circ->cpath;
  relay_set_digest(this_hop->b_digest, cell);

  if (this_hop->state != CPATH_STATE_OPEN) {
    log_warn(LD_PROTOCOL, "Relay cell before first created cell? Closing.");
    return -END_CIRC_REASON_TORPROTOCOL;
  }
  /* Iterate through all the additional hops in our loose_circ->cpath (in
   * forward order) and decrypt the cell w.r.t. each hop in turn. */ 
  do {
    if (!this_hop) {
      log_warn(LD_OR, "Additional hop for loose circuit was strangely "
                      "missing! Closing circuit.");
      return -END_CIRC_REASON_INTERNAL;
    }
    log_debug(LD_OR, "Decrypting a layer of the relay cell for a loose circuit.");
    if (crypto_cipher_crypt_inplace(this_hop->f_crypto,
                                    (char *)cell->payload, CELL_PAYLOAD_SIZE) < 0) {
      log_warn(LD_BUG, "Error decrypting relay cell payload! Closing.");
      return -END_CIRC_REASON_INTERNAL;
    }
    /* We essentially treat every cell as "recognized".  That is, since this
     * is a loose-source routed circuit, we want to send relay cells not
     * intended for us *and* cells intended for us through our leaky pipe, no
     * matter what the underlying payload is. */
    relay_header_unpack(&rh, cell->payload);
    if (rh.recognized == 0) {
      /* It's possibly recognized, but check the digest to be sure. */
      if (relay_digest_matches(this_hop->b_digest, cell)) {
        layer_hint = this_hop;
        log_debug(LD_OR, "During relay cell decryption, cell became recognized "
                         "at hop %s", this_hop->extend_info->identity_digest);
        break;
      }
    }
    this_hop = this_hop->next;
  } while (this_hop != cpath && this_hop->state == CPATH_STATE_OPEN);

  if (!layer_hint) {
    log_warn(LD_OR, "Incoming relay cell on loose circuit not recognized. Closing.");
    return -END_CIRC_REASON_TORPROTOCOL;
  }

  ++stats_n_relay_cells_relayed;
  append_cell_to_circuit_queue(LOOSE_TO_CIRCUIT(loose_circ), chan,
                               cell, cell_direction, rh.stream_id);
  return 0;
}

/**
 * Having received a recognized cell from the OP on a loose circuit, we should
 * wrap up and encrypt the cell to each of the additional hops, and send it
 * along to the next one.
 *
 * For instance, an OP's extend_cell would be encrypt it to the next
 * additional hop in <b>loose_circ</b>, and sent it along inside a RELAY_EARLY
 * cell.
 *
 * Returns 0 on success, and -<b>reason</b> if the circuit should be closed.
 */
static int
loose_circuit_relay_cell_outgoing(loose_or_circuit_t *loose_circ,
                                  crypt_path_t *layer_hint,
                                  cell_t *cell, cell_direction_t cell_direction)
{
  channel_t *chan;        /* Where to send the cell. */
  crypt_path_t *this_hop; /* The hop we're currently encrypting to. */

  log_debug(LD_OR, "Handling outgoing relay cell type %d on loose circuit %d.",
            cell->command, LOOSE_TO_CIRCUIT(loose_circ)->global_circuitlist_idx);

  /* Set the circ_id to the one for the next hop. */
  cell->circ_id = LOOSE_TO_CIRCUIT(loose_circ)->n_circ_id;
  chan = LOOSE_TO_CIRCUIT(loose_circ)->n_chan;

  tor_assert(loose_circ);
  tor_assert(loose_circ->cpath);
  tor_assert(loose_circ->cpath->prev);
  this_hop = loose_circ->cpath->prev; /* Take the last loose hop first. */

  tor_assert(this_hop->f_digest);  // XXX We don't have f_digest
  relay_set_digest(this_hop->f_digest, cell);

  /* Iterate through all the additional hops in our loose_circ->cpath (in
   * reverse) and encrypt the cell to each hop in turn. */ 
  do {
    if (!this_hop) {
      log_warn(LD_OR, "Additional hop for loose circuit was strangely "
                      "missing! Closing circuit.");
      return -END_CIRC_REASON_INTERNAL;
    }
    log_debug(LD_OR, "Encrypting a layer of the relay cell for a loose circuit.");
    if (crypto_cipher_crypt_inplace(this_hop->f_crypto,
                                    (char *)cell->payload, CELL_PAYLOAD_SIZE) < 0) {
      log_warn(LD_BUG, "Error encrypting relay cell payload! Closing.");
      return -END_CIRC_REASON_INTERNAL;
    }
    this_hop = this_hop->prev;
  } while (this_hop != loose_circ->cpath->prev);

  ++stats_n_relay_cells_relayed;
  append_cell_to_circuit_queue(LOOSE_TO_CIRCUIT(loose_circ), chan,
                               cell, cell_direction, 0);
  return 0;
}

/**
 * XXX Do we really need these checks?  Couldn't we just crypt the relay cell
 * as if it was not meant for us, and let whichever additional hop on our
 * loose_circ->cpath drop it because it's unrecognized?
 *
 * Returns 1 if we should continue to process the relay cell with header
 * <b>rh</b>, 0 if we should drop the cell, and -<b>reason</b> if loose_circ
 * should be marked for close.
 */
static int
loose_circuit_check_relay_cell_header(cell_t *cell)
{
  relay_header_t rh;

  tor_assert(cell);

  relay_header_unpack(&rh, cell->payload);

  if (rh.length > RELAY_PAYLOAD_SIZE) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Relay cell length field too long. Closing circuit.");
    return -END_CIRC_REASON_TORPROTOCOL;
  }

  if (rh.stream_id == 0) {
    switch (rh.command) {
      case RELAY_COMMAND_BEGIN:
      case RELAY_COMMAND_CONNECTED:
      case RELAY_COMMAND_END:
      case RELAY_COMMAND_RESOLVE:
      case RELAY_COMMAND_RESOLVED:
      case RELAY_COMMAND_BEGIN_DIR:
        log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
               "Relay command %s with zero stream_id. Dropping.",
               cell_command_to_string(cell->command));
        return 0;
      default:
        ;
    }
  }

  return 1;
}

/**
 * DOCDOC
 *
 * Loosely based on pieces of circuit_package_relay_cell(), relay_crypt(),
 * circuit_receive_relay_cell(), and circuit_package_relay_cell().
 */
int
loose_circuit_process_relay_cell(loose_or_circuit_t *loose_circ,
                                 crypt_path_t *layer_hint,
                                 cell_t *cell, cell_direction_t cell_direction,
                                 char recognized)
{
  static int num_seen = 0;
  int reason = 0;

  tor_assert(loose_circ);
  tor_assert(CIRCUIT_IS_LOOSE(loose_circ));
  tor_assert(cell);
  tor_assert(cell_direction == CELL_DIRECTION_IN ||
             cell_direction == CELL_DIRECTION_OUT);

  ++num_seen;
  ++stats_n_relay_cells_delivered;
  log_debug(LD_OR,
            "Processing %s relay cell with command %s for loose circuit %d...",
            recognized ? "recognized" : "unrecognized",
            cell_command_to_string(cell->command),
            LOOSE_TO_CIRCUIT(loose_circ)->global_circuitlist_idx);

  if (recognized) {
    if ((reason = loose_circuit_check_relay_cell_header(cell)) < 0) {
      return reason;
    }
  }
  /* Heading towards the OP's next chosen hop. We'll need to wrap whatever
   * this thing is up in a RELAY_EARLY cell and pass it along. */
  if (cell_direction == CELL_DIRECTION_OUT) {
    log_debug(LD_OR, "Sending away from origin.");
    return loose_circuit_relay_cell_outgoing(loose_circ, layer_hint,
                                             cell, cell_direction);
  }
  /* Heading towards the OP. We'll need to unwrap and decrypt all of the
   * loose onion layers. */
  if (cell_direction == CELL_DIRECTION_IN) {
    log_debug(LD_OR, "Sending towards origin.");
    return loose_circuit_relay_cell_incoming(loose_circ, layer_hint,
                                             cell, cell_direction);
  }

  log_warn(LD_OR, "Direction for relay cell on loose circuit was neither "
                  "in nor out? Closing.");
  return -END_CIRC_REASON_INTERNAL;
}

/**
 * Send the next cell for constructing <b>loose_circ</b>.
 *
 * Returns 0 on success, and -<b>reason</b> if the circuit should be closed.
 */
MOCK_IMPL(int,
loose_circuit_send_next_onion_skin,(loose_or_circuit_t *loose_circ))
{
  int reason;

  if (loose_circ->cpath->state == CPATH_STATE_CLOSED) {
    log_debug(LD_CIRC, "Doing loose_circuit_create()...");
    reason = loose_circuit_create(loose_circ);

    if (reason < 0) {
      return reason;
    }
  } else {
    log_debug(LD_CIRC, "Doing loose_circuit_extend()...");
    return loose_circuit_extend(loose_circ);
  }

  return 0;
}
