/* 
 * Copyright (c) 2015, Isis Lovecruft
 * Copyright (c) 2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file loose.h
 * \brief Header file for loose.c.
 **/

#ifndef TOR_LOOSE_H
#define TOR_LOOSE_H

#include "onion.h"
#include "testsupport.h"

extern char loose_circuits_are_possible;

/** Functions for storing state on whether we believe we can create loose circuits. */
char loose_have_completed_a_circuit(void);
void loose_note_that_we_completed_a_circuit(void);
void loose_note_that_we_maybe_cant_complete_circuits(void);

/** Functions for creating loose circuits. */
loose_or_circuit_t* loose_circuit_establish_circuit(circid_t circ_id, channel_t *p_chan,
                                                    extend_info_t *entry, int len,
                                                    uint8_t purpose, int flags);

/** Function for freeing loose circuits.  Used in circuit_free(). */
void loose_circuit_free(loose_or_circuit_t *loose_circ);

/* Functions for handling specific cell types on a loose circuit. */
#ifdef LOOSE_PRIVATE
STATIC int loose_circuit_send_create_cell(loose_or_circuit_t *loose_circ);
STATIC int loose_circuit_extend(loose_or_circuit_t *loose_circ);
#endif
int loose_circuit_process_created_cell(loose_or_circuit_t *loose_circ,
                                       created_cell_t *created_cell);
int loose_circuit_process_relay_cell(loose_or_circuit_t *loose_circ,
                                     crypt_path_t *layer_hint,
                                     cell_t *cell, cell_direction_t cell_direction,
                                     char recognized);
void loose_circuit_store_create_cell(loose_or_circuit_t *loose_circ, cell_t *cell);
void loose_circuit_answer_create_cell(loose_or_circuit_t *loose_circ, cell_t *cell);
MOCK_DECL(int, loose_circuit_send_next_onion_skin,(loose_or_circuit_t *loose_circ));


/*******************************************************************************/
/*               Declarations for unittests in test_loose.c.                   */
/*******************************************************************************/

#ifdef LOOSE_PRIVATE

STATIC loose_or_circuit_t* loose_or_circuit_init(circid_t circ_id, channel_t *p_chan,
                                                 uint8_t purpose, int flags);
STATIC extend_info_t* loose_circuit_pick_cpath_entry(loose_or_circuit_t *loose_circ,
                                                     extend_info_t *entry);
STATIC void loose_circuit_log_path(int severity, unsigned int domain,
                                   const loose_or_circuit_t *loose_circ);

/** Function for handling extra tasks when a loose circuit has completed. */
STATIC void loose_circuit_has_opened(loose_or_circuit_t *loose_circ);

MOCK_DECL(STATIC int, loose_circuit_should_use_create_fast,(void));
#endif


#endif
