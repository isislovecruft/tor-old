/* 
 * Copyright (c) 2015, Isis Lovecruft
 * Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define TOR_CHANNEL_INTERNAL_
#define LOOSE_PRIVATE

#include "or.h"
#include "test.h"
#include "testsupport.h"
#include "channel.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "loose.h"
#include "onion_fast.h"

/******************************************************************************
 * The following are all stolen verbatim from test_circuitlist.c, because I
 * wasn't sure if it was okay to include functions from another test_* file.
 * -isis
 ******************************************************************************/
#define GOT_CMUX_ATTACH(mux_, circ_, dir_) do {  \
    tt_int_op(cam.ncalls, OP_EQ, 1);             \
    tt_ptr_op(cam.cmux, OP_EQ, (mux_));          \
    tt_ptr_op(cam.circ, OP_EQ, (circ_));         \
    tt_int_op(cam.dir, OP_EQ, (dir_));           \
    memset(&cam, 0, sizeof(cam));                \
  } while (0)

#define GOT_CMUX_DETACH(mux_, circ_) do {        \
    tt_int_op(cdm.ncalls, OP_EQ, 1);             \
    tt_ptr_op(cdm.cmux, OP_EQ, (mux_));          \
    tt_ptr_op(cdm.circ, OP_EQ, (circ_));         \
    memset(&cdm, 0, sizeof(cdm));                \
  } while (0)

static channel_t *
new_fake_channel(void)
{
  channel_t *chan = tor_malloc_zero(sizeof(channel_t));
  channel_init(chan);
  return chan;
}

static struct {
  int ncalls;
  void *cmux;
  void *circ;
  cell_direction_t dir;
} cam;

static void
circuitmux_attach_mock(circuitmux_t *cmux, circuit_t *circ,
                       cell_direction_t dir)
{
  ++cam.ncalls;
  cam.cmux = cmux;
  cam.circ = circ;
  cam.dir = dir;
}

static struct {
  int ncalls;
  void *cmux;
  void *circ;
} cdm;

static void
circuitmux_detach_mock(circuitmux_t *cmux, circuit_t *circ)
{
  ++cdm.ncalls;
  cdm.cmux = cmux;
  cdm.circ = circ;
}

/************************** END PLAGIARISED CODE ******************************/

/******************************************************************************
 *                           MOCKED FUNCTIONS
 ******************************************************************************/

/**
 * Mocked version of loose_circuit_should_use_create_fast() that pretends we
 * should use some cell type other than a CELL_CREATE_FAST in
 * loose_circuit_send_create_cell().
 */
static int
mock_loose_circuit_should_use_create_fast(void)
{
  return 0;
}

/**
 * Mocked version of loose_circuit_send_next_onion_skin() which does nothing
 * and always returns success.
 */
static int
mock_success_loose_circuit_send_next_onion_skin(loose_or_circuit_t *loose_circ)
{
  return 0;
}

/**
 * Pretend that choose_good_entry_server() couldn't find a suitable entry node.
 */
static const node_t *
mock_choose_good_entry_server_null(uint8_t purpose, cpath_build_state_t *state)
{
  const node_t *choice = NULL;

  (void)purpose;
  (void)state;

  return choice;
}

/**
 * Version of choose_good_entry_server() which returns the same mocked entry
 * node every time.
 */
static const node_t *
mock_choose_good_entry_server(uint8_t purpose, cpath_build_state_t *state)
{
  static node_t mock_node;
  static routerstatus_t mock_rs;
  static routerinfo_t mock_ri;

  (void)purpose;
  (void)state;

  memset(&mock_node, 0, sizeof(node_t));
  memset(&mock_rs, 0, sizeof(routerstatus_t));
  memset(&mock_ri, 0, sizeof(routerinfo_t));

  strlcpy(mock_rs.nickname, "TestOR", sizeof(mock_rs.nickname));
  mock_node.rs = &mock_rs;

  mock_ri.addr = 123456789u;
  mock_ri.or_port = 9001;
  mock_node.ri = &mock_ri;

  memcpy(mock_node.identity,
         "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
         "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA",
         DIGEST_LEN);

  return &mock_node;
}
/************************** END MOCKED FUNCTIONS ******************************/


/******************************************************************************
 *                             UNITTESTS
 ******************************************************************************/

/**
 * Simple exercises for the functionality of loose_have_completed_a_circuit(),
 * loose_note_that_we_completed_a_circuit(), and
 * loose_note_that_we_maybe_cant_complete_circuits().
 */
static void
test_loose_can_complete_circuits(void *arg)
{
  (void)arg;

  /* Should start out false. */
  tt_int_op(loose_have_completed_a_circuit(), OP_EQ, 0);

  /* Setting it to true should make it true. */
  loose_note_that_we_completed_a_circuit();
  tt_int_op(loose_have_completed_a_circuit(), OP_EQ, 1);

  /* Setting it to false should make it false. */
  loose_note_that_we_maybe_cant_complete_circuits();
  tt_int_op(loose_have_completed_a_circuit(), OP_EQ, 0);

done:
  ;
}

/**
 * Calling loose_circuit_free() with NULL log a warning and do nothing.
 */
static void
test_loose_circuit_free(void *arg)
{
  loose_or_circuit_t *loose_circ = NULL;

  (void)arg;
  loose_circuit_free(loose_circ);
}

/**
 * Calling loose_circuit_log_path() should log some info about the cpath.
 */
static void
test_loose_circuit_log_path(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);
  loose_circuit_log_path(LOG_WARN, LD_CIRC, loose_circ);

done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  UNMOCK(choose_good_entry_server);
}


/**
 * Calling loose_circuit_establish_circuit() when loose_circuits_are_possible
 * is false should return NULL.
 */
static void
test_loose_circuit_establish_circuit_not_possible(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;

  (void)arg;

  loose_circuits_are_possible = 0;
  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(!loose_circ);
  tt_assert(loose_circ == NULL);

done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
}

/**
 * Calling loose_circuit_establish_circuit() when loose_circuits_are_possible
 * is true should allocate and construct a loose_or_circuit_t.
 */
static void
test_loose_circuit_establish_circuit_unattached(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);
  tt_assert(loose_circ->cpath);
  tt_assert(loose_circ->build_state);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ)->marked_for_close, OP_EQ, 0);

done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  UNMOCK(choose_good_entry_server);
}

/**
 * Calling loose_circuit_establish_circuit() when loose_circuits_are_possible
 * is true, but no suitable entry server is available, should mark the
 * loose_circuit_t for close and return NULL.
 */
static void
test_loose_circuit_establish_circuit_unattached_no_entry(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(choose_good_entry_server, mock_choose_good_entry_server_null);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(!loose_circ);

done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  UNMOCK(choose_good_entry_server);
}

/**
 * Calling loose_circuit_establish_circuit() when loose_circuits_are_possible
 * is true should allocate and construct a loose_or_circuit_t.  Since circ_id
 * and p_chan are passed in, the circuit should be successfully attached to a
 * circuitmux.
 *
 * Mostly plagiarised from test_clist_maps() in test_circuitlist.c.
 */
static void
test_loose_circuit_establish_circuit_attached(void *arg)
{
  loose_or_circuit_t *loose_circ1, *loose_circ2;
  extend_info_t *entry = NULL;
  circid_t circ_id = 100;
  channel_t *ch1 = new_fake_channel();
  channel_t *ch2 = new_fake_channel();
  channel_t *ch3 = new_fake_channel();

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);

  memset(&cam, 0, sizeof(cam));
  memset(&cdm, 0, sizeof(cdm));

  tt_assert(ch1);
  tt_assert(ch2);
  tt_assert(ch3);
  ch1->cmux = tor_malloc(1);
  ch2->cmux = tor_malloc(1);
  ch3->cmux = tor_malloc(1);

  /* Set up the first circuit */
  loose_circ1 = loose_circuit_establish_circuit(circ_id, ch1, entry,
                                                0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ1);
  tt_assert(loose_circ1->cpath);
  tt_assert(loose_circ1->build_state);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ1)->marked_for_close, OP_EQ, 0);

  GOT_CMUX_ATTACH(ch1->cmux, loose_circ1, CELL_DIRECTION_IN);
  tt_int_op(LOOSE_TO_OR_CIRCUIT(loose_circ1)->p_circ_id, OP_EQ, 100);
  tt_ptr_op(LOOSE_TO_OR_CIRCUIT(loose_circ1)->p_chan, OP_EQ, ch1);

  /* Set up the second circuit */
  loose_circ2 = loose_circuit_establish_circuit(circ_id, ch2, entry,
                                                0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ2);
  tt_assert(loose_circ2->cpath);
  tt_assert(loose_circ2->build_state);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ2)->marked_for_close, OP_EQ, 0);

  GOT_CMUX_ATTACH(ch2->cmux, loose_circ2, CELL_DIRECTION_IN);
  tt_int_op(LOOSE_TO_OR_CIRCUIT(loose_circ2)->p_circ_id, OP_EQ, 100);
  tt_ptr_op(LOOSE_TO_OR_CIRCUIT(loose_circ2)->p_chan, OP_EQ, ch2);

  circuit_set_n_circid_chan(LOOSE_TO_CIRCUIT(loose_circ1), 200, ch2);
  GOT_CMUX_ATTACH(ch2->cmux, loose_circ1, CELL_DIRECTION_OUT);

  circuit_set_n_circid_chan(LOOSE_TO_CIRCUIT(loose_circ2), 200, ch1);
  GOT_CMUX_ATTACH(ch1->cmux, loose_circ2, CELL_DIRECTION_OUT);

  /* Check that we can retrieve them from the global circuitlist. */
  tt_ptr_op(circuit_get_by_circid_channel(200, ch1), OP_EQ, LOOSE_TO_CIRCUIT(loose_circ2));
  tt_ptr_op(circuit_get_by_circid_channel(200, ch2), OP_EQ, LOOSE_TO_CIRCUIT(loose_circ1));
  tt_ptr_op(circuit_get_by_circid_channel(100, ch2), OP_EQ, LOOSE_TO_CIRCUIT(loose_circ2));
  /* Try the same thing again, to test the "fast" path. */
  tt_ptr_op(circuit_get_by_circid_channel(100, ch2), OP_EQ, LOOSE_TO_CIRCUIT(loose_circ2));
  tt_assert(circuit_id_in_use_on_channel(100, ch2));
  tt_assert(! circuit_id_in_use_on_channel(101, ch2));

  /* Try changing the circuitid and channel of that circuit. */
  circuit_set_p_circid_chan(LOOSE_TO_OR_CIRCUIT(loose_circ1), 500, ch3);
  GOT_CMUX_DETACH(ch1->cmux, LOOSE_TO_CIRCUIT(loose_circ1));
  GOT_CMUX_ATTACH(ch3->cmux, LOOSE_TO_CIRCUIT(loose_circ1), CELL_DIRECTION_IN);
  tt_ptr_op(circuit_get_by_circid_channel(100, ch1), OP_EQ, NULL);
  tt_assert(! circuit_id_in_use_on_channel(100, ch1));
  tt_ptr_op(circuit_get_by_circid_channel(500, ch3), OP_EQ, LOOSE_TO_CIRCUIT(loose_circ1));

  /* Now let's see about destroy handling. */
  tt_assert(! circuit_id_in_use_on_channel(205, ch2));
  tt_assert(circuit_id_in_use_on_channel(200, ch2));
  channel_note_destroy_pending(ch1, 200);
  channel_note_destroy_pending(ch1, 205);
  channel_note_destroy_pending(ch2, 100);
  tt_assert(circuit_id_in_use_on_channel(205, ch1))
  tt_assert(circuit_id_in_use_on_channel(200, ch2));
  tt_assert(circuit_id_in_use_on_channel(100, ch2));

  tt_assert(LOOSE_TO_CIRCUIT(loose_circ2)->n_delete_pending != 0);
  tt_ptr_op(circuit_get_by_circid_channel(200, ch1), OP_EQ, LOOSE_TO_CIRCUIT(loose_circ2));
  tt_ptr_op(circuit_get_by_circid_channel(100, ch2), OP_EQ, LOOSE_TO_CIRCUIT(loose_circ2));

  /* Okay, now free ch2 and make sure that the circuit ID is STILL not
   * usable, because we haven't declared the destroy to be nonpending */
  tt_int_op(cdm.ncalls, OP_EQ, 0);
  circuit_free(LOOSE_TO_CIRCUIT(loose_circ2));
  loose_circ2 = NULL; /* prevent free */
  tt_int_op(cdm.ncalls, OP_EQ, 2);
  memset(&cdm, 0, sizeof(cdm));
  tt_assert(circuit_id_in_use_on_channel(200, ch1));
  tt_assert(circuit_id_in_use_on_channel(100, ch2));
  tt_ptr_op(circuit_get_by_circid_channel(200, ch1), OP_EQ, NULL);
  tt_ptr_op(circuit_get_by_circid_channel(100, ch2), OP_EQ, NULL);

  /* Now say that the destroy is nonpending */
  channel_note_destroy_not_pending(ch1, 200);
  tt_ptr_op(circuit_get_by_circid_channel(200, ch1), OP_EQ, NULL);
  channel_note_destroy_not_pending(ch2, 100);
  tt_ptr_op(circuit_get_by_circid_channel(100, ch2), OP_EQ, NULL);
  tt_assert(! circuit_id_in_use_on_channel(200, ch1));
  tt_assert(! circuit_id_in_use_on_channel(100, ch2));

done:
  if (loose_circ1)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ1));
  if (loose_circ2)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ2));
  if (ch1)
    tor_free(ch1->cmux);
  if (ch2)
    tor_free(ch2->cmux);
  if (ch3)
    tor_free(ch3->cmux);
  tor_free(ch1);
  tor_free(ch2);
  tor_free(ch3);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
}

/**
 * Calling loose_circuit_pick_cpath_entry() should pick a valid entry (guard)
 * node.
 */
static void
test_loose_circuit_pick_cpath_entry(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;

  (void)arg;

  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  loose_circ = loose_or_circuit_init(circ_id, p_chan, CIRCUIT_PURPOSE_OR, 0);
  entry = loose_circuit_pick_cpath_entry(loose_circ, entry);
  tt_assert(entry);

done:
  extend_info_free(entry);
  UNMOCK(choose_good_entry_server);
}

/**
 * Calling loose_circuit_pick_cpath_entry(), when choose_good_entry_server()
 * can't find a suitable entry node, should return NULL.
 */
static void
test_loose_circuit_pick_cpath_entry_null(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  extend_info_t *entry = NULL;

  (void)arg;

  MOCK(choose_good_entry_server, mock_choose_good_entry_server_null);
  loose_circ = loose_or_circuit_init(circ_id, p_chan, CIRCUIT_PURPOSE_OR, 0);
  entry = loose_circuit_pick_cpath_entry(loose_circ, entry);
  tt_ptr_op(entry, OP_EQ, NULL);

done:
  UNMOCK(choose_good_entry_server);
}

/**
 * Calling loose_circuit_pick_cpath_entry(), when an entry node is already
 * chosen should simply return the extend_info_t for the chosen node.
 */
static void
test_loose_circuit_pick_cpath_entry_chosen(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = NULL;
  channel_t *p_chan = NULL;
  const node_t *chosen_node;
  extend_info_t *entry, *chosen_entry = NULL;

  (void)arg;

  chosen_node = mock_choose_good_entry_server(0, NULL);
  chosen_entry = extend_info_from_node(chosen_node, 0);
  tt_want(chosen_node);
  tt_want(chosen_entry);

  MOCK(choose_good_entry_server, mock_choose_good_entry_server_null);
  loose_circ = loose_or_circuit_init(circ_id, p_chan, CIRCUIT_PURPOSE_OR, 0);
  entry = loose_circuit_pick_cpath_entry(loose_circ, chosen_entry);

  tt_ptr_op(entry, OP_EQ, chosen_entry);
  tt_str_op(entry->nickname, OP_EQ, chosen_entry->nickname);
  tt_str_op(entry->identity_digest, OP_EQ, chosen_entry->identity_digest);
  tt_mem_op(entry->identity_digest, OP_EQ,
            "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA"
            "\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA\xAA", DIGEST_LEN);

done:
  UNMOCK(choose_good_entry_server);
}

/**
 * Calling loose_circuit_send_create_cell() should construct a create_cell_t
 * and store it in the loose_circuit_t.
 */
static void
test_loose_circuit_send_create_cell(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  extend_info_t *entry = NULL;
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

  result = loose_circuit_send_create_cell(loose_circ);
  tt_int_op(result, OP_EQ, 0); /* Should return okay. */

  /* The create cell should be stored in the underlying circuit_t. */
  tt_assert(LOOSE_TO_CIRCUIT(loose_circ)->n_chan_create_cell);

  /* We want (and expect) it to be a CELL_CREATE_FAST, but if in the future we
   * were to implement this to produce a different type of create cell, that
   * might be okay too. */
  tt_want_int_op(LOOSE_TO_CIRCUIT(loose_circ)->n_chan_create_cell->cell_type,
                 OP_EQ, CELL_CREATE_FAST);
  tt_want_int_op(LOOSE_TO_CIRCUIT(loose_circ)->n_chan_create_cell->handshake_type,
                 OP_EQ, ONION_HANDSHAKE_TYPE_FAST);

  /* Regardless, the handshake length totes should be greater than zero. */
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ)->n_chan_create_cell->handshake_len, OP_GT, 0);

  /* And, lastly, the circuit state should be CIRCUIT_STATE_CHAN_WAIT. */
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ)->state, OP_EQ, CIRCUIT_STATE_CHAN_WAIT);

done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  if (p_chan)
    tor_free(p_chan->cmux);
  tor_free(p_chan);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
}

/**
 * Calling loose_circuit_send_create_cell(), when
 * loose_circuit_should_use_create_fast() tells us to use CELL_CREATE rather
 * than CELL_CREATE_FAST, should log a warning and return
 * -END_CIRC_REASON_INTERNAL.
 */
static void
test_loose_circuit_send_create_cell_no_create_fast(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  extend_info_t *entry = NULL;
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(loose_circuit_should_use_create_fast, mock_loose_circuit_should_use_create_fast);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

  result = loose_circuit_send_create_cell(loose_circ);
  tt_int_op(result, OP_EQ, -END_CIRC_REASON_INTERNAL);

done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  if (p_chan)
    tor_free(p_chan->cmux);
  tor_free(p_chan);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(loose_circuit_should_use_create_fast);
}

/**
 * Calling loose_circuit_send_create_cell() with NULL should return
 * -END_CIRC_REASON_INTERNAL.
 */
static void
test_loose_circuit_send_create_cell_null(void *arg)
{
  loose_or_circuit_t *loose_circ = NULL;
  int result;

  (void)arg;

  result = loose_circuit_send_create_cell(loose_circ);
  tt_int_op(result, OP_EQ, -END_CIRC_REASON_INTERNAL);

done:
  ;
}

/**
 * Calling loose_circuit_process_created_cell() should call
 * loose_circuit_finish_handshake() and complete both successfully.
 *
 * If loose_circuit_process_created_cell() is called a second time for the
 * same circuit, then we should hit the "We got an extended when loose-source
 * routed circuit was already built? Closing." error in
 * loose_circuit_finish_handshake() and return -END_CIRC_REASON_TORPROTOCOL.
 */
static void
test_loose_circuit_process_created_cell(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  extend_info_t *entry = NULL;
  create_cell_t *create;
  created_cell_t created;
  cell_t created_cell;
  uint8_t keys[CPATH_KEY_MATERIAL_LEN];
  uint8_t rend_whatevs[DIGEST_LEN];
  int result, len;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(loose_circuit_send_next_onion_skin, mock_success_loose_circuit_send_next_onion_skin);

  memset(&created, 0, sizeof(created_cell_t));
  memset(&created_cell, 0, sizeof(cell_t));

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

  /* Make a create cell. */
  tt_int_op(loose_circuit_send_create_cell(loose_circ), OP_EQ, 0);
  create = LOOSE_TO_CIRCUIT(loose_circ)->n_chan_create_cell;
  tt_assert(create);

  /* What create_cell_parse() and create_cell_init() would do. */
  create->cell_type = CELL_CREATE_FAST;
  create->handshake_type = ONION_HANDSHAKE_TYPE_FAST;
  create->handshake_len = CREATE_FAST_LEN;

  len = onion_skin_server_handshake(ONION_HANDSHAKE_TYPE_FAST,
                                    create->onionskin,
                                    create->handshake_len,
                                    NULL, created.reply,
                                    keys, CPATH_KEY_MATERIAL_LEN,
                                    rend_whatevs);
  tt_int_op(len, OP_GE, 0); /* Handshake length should be >= 0. */
  created.cell_type = CELL_CREATED_FAST;
  created.handshake_len = len;

  /* And pack it into the cell_t… */
  tt_int_op(created_cell_format(&created_cell, &created), OP_GE, 0);

  /* And then everything should be peachy keen. */
  result = loose_circuit_process_created_cell(loose_circ, &created);
  tt_int_op(result, OP_EQ, 0);

  /* But if we call loose_circuit_process_created_cell() again, we should get
   * -END_CIRC_REASON_TORPROTOCOL. */
  result = loose_circuit_process_created_cell(loose_circ, &created);
  tt_int_op(result, OP_EQ, -END_CIRC_REASON_TORPROTOCOL);

done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  if (p_chan)
    tor_free(p_chan->cmux);
  tor_free(p_chan);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(loose_circuit_send_next_onion_skin);
}

/**
 * Calling loose_circuit_process_created_cell() with a bad created cell should
 * return -END_CIRC_REASON_TORPROTOCOL, because the handshake was unable to
 * complete.
 */
static void
test_loose_circuit_process_created_cell_bad_created_cell(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  extend_info_t *entry = NULL;
  created_cell_t created;
  int result;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);
  MOCK(loose_circuit_send_next_onion_skin, mock_success_loose_circuit_send_next_onion_skin);

  memset(&created, 0, sizeof(created_cell_t));
  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

  /* The handshake should have failed this time, since there's nothing in
   * the cell_t. */
  result = loose_circuit_process_created_cell(loose_circ, &created);
  tt_int_op(result, OP_EQ, -END_CIRC_REASON_TORPROTOCOL);

done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  if (p_chan)
    tor_free(p_chan->cmux);
  tor_free(p_chan);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
  UNMOCK(loose_circuit_send_next_onion_skin);
}

/**
 * Calling loose_circuit_has_opened() should set the circuit state to
 * CIRCUIT_STATE_OPEN and call loose_note_that_we_have_complete_a_circuit().
 */
static void
test_loose_circuit_has_opened(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  extend_info_t *entry = NULL;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);
  tt_int_op(loose_have_completed_a_circuit(), OP_EQ, 0);

  loose_circuit_has_opened(loose_circ);
  tt_int_op(loose_have_completed_a_circuit(), OP_EQ, 1);
  tt_int_op(LOOSE_TO_CIRCUIT(loose_circ)->state, OP_EQ, CIRCUIT_STATE_OPEN);

done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  if (p_chan)
    tor_free(p_chan->cmux);
  tor_free(p_chan);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
}  

/*
 * Calling loose_circuit_extend() when the cpath has already been completely
 * extended to should just call loose_circuit_has_opened() and return 0.
 */
static void
test_loose_circuit_extend_no_cpath_next(void *arg)
{
  loose_or_circuit_t *loose_circ;
  circid_t circ_id = 100;
  channel_t *p_chan = new_fake_channel();
  extend_info_t *entry = NULL;
  int result;

  (void)arg;

  loose_circuits_are_possible = 1;
  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  MOCK(choose_good_entry_server, mock_choose_good_entry_server);

  loose_circ = loose_circuit_establish_circuit(circ_id, p_chan, entry,
                                               0, CIRCUIT_PURPOSE_OR, 0);
  tt_assert(loose_circ);

  result = loose_circuit_extend(loose_circ);
  tt_int_op(result, OP_EQ, 0);

done:
  if (loose_circ)
    circuit_free(LOOSE_TO_CIRCUIT(loose_circ));
  if (p_chan)
    tor_free(p_chan->cmux);
  tor_free(p_chan);
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
  UNMOCK(choose_good_entry_server);
}


#define TEST_LOOSE(name, flags) \
  { #name, test_loose_##name, (flags), NULL, NULL }

struct testcase_t loose_tests[] = {
  TEST_LOOSE(can_complete_circuits, TT_FORK),
  TEST_LOOSE(circuit_free, TT_FORK),
  TEST_LOOSE(circuit_log_path, TT_FORK),
  TEST_LOOSE(circuit_establish_circuit_not_possible, TT_FORK),
  TEST_LOOSE(circuit_establish_circuit_unattached, TT_FORK),
  TEST_LOOSE(circuit_establish_circuit_unattached_no_entry, TT_FORK),
  TEST_LOOSE(circuit_establish_circuit_attached, TT_FORK),
  TEST_LOOSE(circuit_pick_cpath_entry, TT_FORK),
  TEST_LOOSE(circuit_pick_cpath_entry_null, TT_FORK),
  TEST_LOOSE(circuit_pick_cpath_entry_chosen, TT_FORK),
  TEST_LOOSE(circuit_send_create_cell, TT_FORK),
  TEST_LOOSE(circuit_send_create_cell_no_create_fast, TT_FORK),
  TEST_LOOSE(circuit_send_create_cell_null, TT_FORK),
  TEST_LOOSE(circuit_process_created_cell, TT_FORK),
  TEST_LOOSE(circuit_process_created_cell_bad_created_cell, TT_FORK),
  TEST_LOOSE(circuit_has_opened, TT_FORK),
  TEST_LOOSE(circuit_extend_no_cpath_next, TT_FORK),
  END_OF_TESTCASES
};
