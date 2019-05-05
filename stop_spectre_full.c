#ifdef PLUGINS_NEW
#ifdef __aarch64__

#include <stdio.h>
#include <assert.h>
#include <locale.h>
#include <inttypes.h>
#include "../plugins.h"

/**
 * Mitigation for Spectre v1, v2, v3, v4.
 * 
 * Method:
 * Disable speculative execution completely. (and worse)
 * 
 * Problems:
 * Too much performance hit.
 */

int ghostbuster_pre_inst_handler(mambo_context *ctx) {
  if(mambo_is_load(ctx)) {
    uint32_t LD_crm = 0b1111;
    emit_a64_DSB(ctx, LD_crm);
  }
  return 0;
}

__attribute__((constructor)) void ghostbuster_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

  mambo_register_pre_inst_cb(ctx, &ghostbuster_pre_inst_handler);

  setlocale(LC_NUMERIC, "");
}

#endif // __aarch64__
#endif // PLUGINS_NEW
