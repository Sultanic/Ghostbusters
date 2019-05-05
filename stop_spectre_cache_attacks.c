#ifdef PLUGINS_NEW
#ifdef __aarch64__

#include <stdio.h>
#include <assert.h>
#include <locale.h>
#include <inttypes.h>
#include "../plugins.h"

/**
 * Mitigation for Spectre v1 | v2 | v1, v2 | v1, v2, v3, v4.
 * 
 * Method:
 * Detect cache timing side-channel attacks.
 * Temporarily serialize load instructions with completion.
 * 
 * Problems:
 * Cache attacks might find new approaches.
 * There are some unavoidable false positives. (Only way to avoid them is with Taint Tracking)
 * It's possible for the attacker to perform the analysis (cache attack) in a separate process.
 */

#define DW 400             // Detection window
#define WALK_LENGTH 500
#define IS_LOAD (1 << 22)

/**
 * Global State:
 *  Tells whether program is in running mode, or walking mode.
 *  Running means it's working normally. Walking means there's a few extra barriers around.
 */
struct global_state {
  enum modes{running, walking} mode;
  enum atk_types{NONE,FR,PP,ET,FF} atk_type;
  int fatigue;  // Duration of walk
} GS;

/**
 * Detector State:
 *  Used for keeping track of patterns. There are four of them.
 *  Flush+Reload, Prime+Probe, Evict+Time, Flush+Flush.
 */
struct detector_state {
  int level;
  int distance;
  uint32_t shared; // Holds a shared address
};

/**
 * All-in-one thread data
 */
struct states {
  struct global_state TS;     // Thread state
  struct detector_state FRDS; // Flush + Reload
  struct detector_state PPDS; // Prime + Probe
  struct detector_state ETDS; // Evict + Time
  struct detector_state FFDS; // Flush + Flush
};

int ghostbuster_pre_thread_handler(mambo_context *ctx) {
  struct states *s = mambo_alloc(ctx, sizeof(struct states));
  assert(s != NULL);
  mambo_set_thread_plugin_data(ctx, s);

  /* Initialize thread data */
  s->TS.mode = running;
  s->TS.atk_type = NONE;
  s->TS.fatigue = 0;
  s->FRDS.level = 0; s->FRDS.distance = 0;
  s->PPDS.level = 0; s->PPDS.distance = 0;
  s->ETDS.level = 0; s->ETDS.distance = 0;
  s->FFDS.level = 0; s->FFDS.distance = 0;

  return 0;
}

void is_load_or_store_with_rt(mambo_context *ctx, bool *is_load, bool *is_store, uint32_t *rt) {
  *is_load = false;
  *is_store = false;

  uint32_t *inst = (uint32_t *)ctx->code.read_address;

  switch (ctx->code.inst) {
    case A64_LDR_LIT: {
      uint32_t opc, v, imm19;
      a64_LDR_lit_decode_fields(ctx->code.read_address, &opc, &v, &imm19, rt);
      // !PRFM
      if (opc == 3 && v == 0) break;

      *is_load = true;
      break;
    }
    case A64_LDX_STX:
    case A64_LDP_STP:
    case A64_LDX_STX_MULTIPLE:
    case A64_LDX_STX_MULTIPLE_POST:
    case A64_LDX_STX_SINGLE:
    case A64_LDX_STX_SINGLE_POST:
      if (*inst & IS_LOAD) {
        *is_load = true;
      } else {
        *is_store = true;
      }
      break;
    case A64_LDR_STR_IMMED:
    case A64_LDR_STR_REG:
    case A64_LDR_STR_UNSIGNED_IMMED: {
      uint32_t sz, v, opc, imm12, rn;
      a64_LDR_STR_unsigned_immed_decode_fields(ctx->code.read_address, &sz, &v, &opc, &imm12, &rn, rt);
      // !PRFM - the sz, v, and opc fields are identical between the three encodings
      if (sz == 3 && v == 0 && opc == 2) break;

      if ((*inst >> 22) & 3) {
        *is_load = true;
      } else {
        *is_store = true;
      }
      break;
    }
  }
}

void check_FlushReload(mambo_context *ctx, struct states *s) {
  // Flush
  if(s->FRDS.level == 0 && ctx->code.inst == A64_SYS) {
    /* DC CIVAC = SYS #011, C7, 1011, #001, <Xt> */
    uint32_t sys_op1, sys_crn, sys_crm, sys_op2, sys_rt;
    a64_SYS_decode_fields(ctx->code.read_address, &sys_op1, &sys_crn, &sys_crm, &sys_op2, &sys_rt);
    if(sys_op1 == 0b011 && sys_crm == 0b1110 && sys_op2 == 0b001) {
      s->FRDS.shared = sys_rt;
      s->FRDS.distance = 0;
      s->FRDS.level++;
    }
  }
  // Victim function (branch call)
  else if(s->FRDS.level == 1 && (mambo_get_branch_type(ctx) & BRANCH_CALL)) {
    s->FRDS.distance = 0;
    s->FRDS.level++;
  }
  // Timed read (DSB then LDR then DSB)
  else if(s->FRDS.level == 2 && ctx->code.inst == A64_DSB) {
    s->FRDS.distance = 0;
    s->FRDS.level++;
  }
  else if(s->FRDS.level == 3) {
    bool is_load, is_store;
    uint32_t rt;
    is_load_or_store_with_rt(ctx, &is_load, &is_store, &rt);
    if(is_load && rt == s->FRDS.shared) {
      s->FRDS.distance = 0;
      s->FRDS.level++;
    }
  }
  else if(s->FRDS.level == 4 && ctx->code.inst == A64_DSB) {
    s->FRDS.distance = 0;
    s->FRDS.level++;
  }
  // Compare with threshold (conditional branch)
  else if(s->FRDS.level == 5 && (mambo_get_branch_type(ctx) & BRANCH_COND)) {
    s->FRDS.distance = 0;
    s->FRDS.level = 0;
    s->TS.mode = walking;
    s->TS.atk_type = FR;
    s->TS.fatigue = WALK_LENGTH;
  }
  else if(s->FRDS.level > 0 /*&& ctx->code.inst != A64_HINT*/) {
    s->FRDS.distance++;
  }
  if(s->FRDS.distance > DW /*|| ((s->FRDS.level == 2 || s->FRDS.level == 3) && s->FRDS.distance > 1)*/) {
    s->FRDS.distance = 0;
    s->FRDS.level = 0;
  }
}

void check_PrimeProbe(mambo_context *ctx, struct states *s) {
  // Prime (Load)
  if(s->PPDS.level == 0) {
    bool is_load_1, is_store_1;
    uint32_t rt_1;
    is_load_or_store_with_rt(ctx, &is_load_1, &is_store_1, &rt_1);
    if(is_load_1) {
      s->PPDS.shared = rt_1;
      s->PPDS.distance = 0;
      s->PPDS.level++;
    }
  }
  // Victim function (branch call)
  else if(s->PPDS.level == 1 && (mambo_get_branch_type(ctx) & BRANCH_CALL)) {
    s->PPDS.distance = 0;
    s->PPDS.level++;
  }
  // Timed read (DSB then LDR then DSB)
  else if(s->PPDS.level == 2 && ctx->code.inst == A64_DSB) {
    s->PPDS.distance = 0;
    s->PPDS.level++;
  }
  else if(s->PPDS.level == 3) {
    bool is_load_2, is_store_2;
    uint32_t rt_2;
    is_load_or_store_with_rt(ctx, &is_load_2, &is_store_2, &rt_2);
    if(is_load_2 && rt_2 == s->PPDS.shared) {
      s->PPDS.distance = 0;
      s->PPDS.level++;
    }
  }
  else if(s->PPDS.level == 4 && ctx->code.inst == A64_DSB) {
    s->PPDS.distance = 0;
    s->PPDS.level++;
  }
  // Compare with threshold (conditional branch)
  else if(s->PPDS.level == 5 && (mambo_get_branch_type(ctx) & BRANCH_COND)) {
    s->PPDS.distance = 0;
    s->PPDS.level = 0;
    s->TS.mode = walking;
    s->TS.atk_type = PP;
    s->TS.fatigue = WALK_LENGTH;
  }
  else if(s->PPDS.level > 0 /*&& ctx->code.inst != A64_HINT*/) {
    s->PPDS.distance++;
  }
  if(s->PPDS.distance > DW  /*|| ((s->FRDS.level == 2 || s->FRDS.level == 3) && s->FRDS.distance > 1)*/) {
    s->PPDS.distance = 0;
    s->PPDS.level = 0;
  }
}

void check_EvictTime(mambo_context *ctx, struct states *s) {
  // Victim function (branch call)
  if(s->ETDS.level == 0 && (mambo_get_branch_type(ctx) & BRANCH_CALL)) {
    s->ETDS.distance = 0;
    s->ETDS.level++;
  }
  // Timed read (DSB then BLR then DSB)
  else if(s->ETDS.level == 1 && ctx->code.inst == A64_DSB) {
    s->ETDS.distance = 0;
    s->ETDS.level++;
  }
  else if(s->ETDS.level == 2 && (mambo_get_branch_type(ctx) & BRANCH_CALL)) {
    s->ETDS.distance = 0;
    s->ETDS.level++;
  }
  else if(s->ETDS.level == 3 && ctx->code.inst == A64_DSB) {
    s->ETDS.distance = 0;
    s->ETDS.level++;
  }
  // Compare with threshold (conditional branch)
  else if(s->PPDS.level == 4 && (mambo_get_branch_type(ctx) & BRANCH_COND)) {
    s->ETDS.distance = 0;
    s->ETDS.level = 0;
    s->TS.mode = walking;
    s->TS.atk_type = ET;
    s->TS.fatigue = WALK_LENGTH;
  }
  else if(s->ETDS.level > 0 /*&& ctx->code.inst != A64_HINT*/) {
    s->ETDS.distance++;
  }
  if(s->ETDS.distance > DW) {
    s->ETDS.distance = 0;
    s->ETDS.level = 0;
  }
}

void check_FlushFlush(mambo_context *ctx, struct states *s) {
  // Timed flush (DSB then DC then DSB)
  if(s->FFDS.level == 0 && ctx->code.inst == A64_DSB) {
    s->FFDS.distance = 0;
    s->FFDS.level++;
  }
  else if(s->FFDS.level == 1 && ctx->code.inst == A64_SYS) {
    uint32_t sys_op1, sys_crn, sys_crm, sys_op2, sys_rt;
    a64_SYS_decode_fields(ctx->code.read_address, &sys_op1, &sys_crn, &sys_crm, &sys_op2, &sys_rt);
    if(sys_op1 == 0b011 && sys_crm == 0b1110 && sys_op2 == 0b001) {
      s->FFDS.shared = sys_rt;
      s->FFDS.distance = 0;
      s->FFDS.level++;
    }
  }
  else if(s->FFDS.level == 2 && ctx->code.inst == A64_DSB) {
    s->FFDS.distance = 0;
    s->FFDS.level++;
  }
  // Compare with threshold (conditional branch)
  else if(s->FFDS.level == 3 && ctx->code.inst == A64_B_COND) {
    s->FFDS.distance = 0;
    s->FFDS.level++;
  }
  // Victim function (branch call)
  else if(s->FFDS.level == 4 && (mambo_get_branch_type(ctx) & BRANCH_CALL)) {
    s->FFDS.distance = 0;
    s->FFDS.level = 0;
    s->TS.mode = walking;
    s->TS.atk_type = FF;
    s->TS.fatigue = WALK_LENGTH;
  }
  else if(s->FFDS.level > 0 /*&& ctx->code.inst != A64_HINT*/) {
    s->FFDS.distance++;
  }
  if(s->FFDS.distance > DW /*|| ((s->FRDS.level == 0 || s->FRDS.level == 1) && s->FRDS.distance > 1)*/) {
    s->FFDS.distance = 0;
    s->FFDS.level = 0;
  }
}

void stop_spectre_v1234(mambo_context *ctx, struct states *s) {
  /* When walking, retire all previous memory instructions before loading any other */
  if(s->TS.mode == walking && mambo_is_load(ctx)) {
    uint32_t LD_crm = 0b1111;
    emit_a64_DSB(ctx, LD_crm);
    s->TS.fatigue--;
  }
}

void stop_spectre_v1(mambo_context *ctx, struct states *s) {
  /* When walking, do not speculate conditional branches */
  if(s->TS.mode == walking && (mambo_get_branch_type(ctx) & BRANCH_COND)) {
    uint32_t LD_crm = 0b1111;
    emit_a64_DMB(ctx, LD_crm);
    s->TS.fatigue--;
  }
}

void stop_spectre_v2(mambo_context *ctx, struct states *s) {
  /* When walking, do not speculate indirect branches */
  if(s->TS.mode == walking && (mambo_get_branch_type(ctx) & BRANCH_INDIRECT)) {
    uint32_t LD_crm = 0b1111;
    emit_a64_DSB(ctx, LD_crm);
    s->TS.fatigue--;
  }
}

int ghostbuster_pre_inst_handler(mambo_context *ctx) {
  struct states *s = mambo_get_thread_plugin_data(ctx);

  /* Detect cache attacks */
  check_FlushReload(ctx, s);
  check_PrimeProbe(ctx, s);
  check_EvictTime(ctx, s);
  check_FlushFlush(ctx, s);

  /* Stop speculative execution */
  stop_spectre_v1234(ctx, s);
  // stop_spectre_v1(ctx, s);
  // stop_spectre_v2(ctx, s);

  /* Return to running mode when done walking */
  if(s->TS.fatigue == 1) {
    s->TS.mode = running;
    // s->TS.atk_type = NONE;
  }

  return 0;
}

int ghostbuster_post_bb_handler(mambo_context *ctx) {
  struct states *s = mambo_get_thread_plugin_data(ctx);

  /* Update global state with thread state (if this thread found an attack) */
  if(s->TS.mode == walking && GS.mode == running /*&& TS.fatigue == WALK_LENGTH*/) {
    GS.mode = s->TS.mode;
    GS.atk_type = s->TS.atk_type;
  }

  /* Update thread state with global state (if other thread found an attack) */
  if(s->TS.atk_type == NONE && GS.mode == walking) {
    s->TS.mode = walking;
    s->TS.atk_type = GS.atk_type;
    s->TS.fatigue = WALK_LENGTH;
  }

  /* Reset global state after attack is dealt with */
  if(s->TS.atk_type != NONE && s->TS.mode == running && GS.mode == walking) {
    GS.mode = running;
    // GS.atk_type = NONE;
  }

  return 0;
}

int ghostbuster_post_thread_handler(mambo_context *ctx) {
  struct states *s = mambo_get_thread_plugin_data(ctx);

  mambo_free(ctx, s);
  return 0;
}

__attribute__((constructor)) void ghostbuster_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  /* Initialize global state */
  GS.mode     = running;
  GS.atk_type = NONE;
  GS.fatigue  = 0;

  mambo_register_pre_thread_cb(ctx, &ghostbuster_pre_thread_handler);
  mambo_register_pre_inst_cb(ctx, &ghostbuster_pre_inst_handler);
  mambo_register_post_basic_block_cb(ctx, &ghostbuster_post_bb_handler);
  mambo_register_post_thread_cb(ctx, &ghostbuster_post_thread_handler);

  setlocale(LC_NUMERIC, "");
}

#endif // __aarch64__
#endif // PLUGINS_NEW
