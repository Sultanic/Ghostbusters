#ifdef PLUGINS_NEW
#ifdef __aarch64__

#include <stdio.h>
#include <assert.h>
#include <locale.h>
#include <inttypes.h>
#include "../plugins.h"

/**
 * Mitigation for Spectre v4.
 * 
 * Method:
 * Check load alias with previous store.
 * If aliased, then serialize.
 * 
 * Problems:
 * Only covers variant 4. Not restraining enough.
 */

/**
 * Alias State:
 *  Used for keeping track of previous store's address.
 */
struct alias_state {
  uintptr_t addr; // Holds the store's address
  uintptr_t temp; // Holds the current load's address
};

int ghostbuster_pre_thread_handler(mambo_context *ctx) {
  struct alias_state *s = mambo_alloc(ctx, sizeof(struct alias_state));
  assert(s != NULL);
  mambo_set_thread_plugin_data(ctx, s);

  /* Initialize thread data */
  s->addr = 0;
  s->temp = 0;

  return 0;
}

int ghostbuster_pre_inst_handler(mambo_context *ctx) {
  struct alias_state *s = mambo_get_thread_plugin_data(ctx);

  bool is_load, is_store;
  _a64_is_load_or_store(ctx, &is_load, &is_store);

  if(is_load || is_store) {
    mambo_cond cond = mambo_get_cond(ctx);
    mambo_branch skip_br;
    int ret;
    if (cond != AL) {
      ret = mambo_reserve_branch(ctx, &skip_br);
      assert(ret == 0);
    }

    /* Calculate and save address of store/load */
    emit_push(ctx, (1 << 0) | (1 << 1));    

    ret = mambo_calc_ld_st_addr(ctx, 0);
    assert(ret == 0);
    emit_set_reg_ptr(ctx, 1, s);

    uint32_t str_size = 0b11, str_v = 0b1, str_opc = 0b00, str_option = 0b01, str_s = 0b0;
    uint32_t str_rt = 0; // Register to store
    uint32_t str_rn = 1; // Register to store to
    uint32_t str_rm = (is_store) ? 0 : 8; // Offset
    emit_a64_LDR_STR_reg(ctx, str_size, str_v, str_opc, str_rm, str_option, str_s, str_rn, str_rt);

    emit_pop(ctx, (1 << 0) | (1 << 1));

    if (cond != AL) {
      ret = emit_local_branch_cond(ctx, &skip_br, invert_cond(cond));
      assert(ret == 0);
    }

    /* Check following load's address, prevent RAW violation if aliased */
    if(is_load && s->temp == s->addr) {
      uint32_t LD_crm = 0b1111;
      emit_a64_DMB(ctx, LD_crm);
    }
  }

  return 0;
}

int ghostbuster_post_thread_handler(mambo_context *ctx) {
  struct alias_state *s = mambo_get_thread_plugin_data(ctx);

  mambo_free(ctx, s);
  return 0;
}

__attribute__((constructor)) void ghostbuster_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  mambo_register_pre_thread_cb(ctx, &ghostbuster_pre_thread_handler);
  mambo_register_pre_inst_cb(ctx, &ghostbuster_pre_inst_handler);
  mambo_register_post_thread_cb(ctx, &ghostbuster_post_thread_handler);

  setlocale(LC_NUMERIC, "");
}

#endif // __aarch64__
#endif // PLUGINS_NEW
