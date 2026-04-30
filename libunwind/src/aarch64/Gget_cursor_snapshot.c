#include "unwind_i.h"

int
unw_get_cursor_snapshot (unw_cursor_t *cursor, unw_cursor_snapshot_t *snapshot)
{
  struct cursor *c = (struct cursor *) cursor;

  if (!snapshot)
    return -UNW_EINVAL;

  snapshot->cfa = c->dwarf.cfa;
  snapshot->ip  = c->dwarf.ip;
  snapshot->loc_sp = DWARF_GET_LOC (c->dwarf.loc[UNW_AARCH64_SP]);
  snapshot->loc_ip = DWARF_GET_LOC (c->dwarf.loc[UNW_AARCH64_X30]);
  snapshot->loc_fp = DWARF_GET_LOC (c->dwarf.loc[UNW_AARCH64_X29]);
  snapshot->dwarf_step_ret    = c->dwarf_step_ret;
  snapshot->step_method       = c->step_method;
  snapshot->frame_type        = c->frame_info.frame_type;
  snapshot->cfa_reg_sp        = c->frame_info.cfa_reg_sp;
  snapshot->cfa_reg_offset    = c->frame_info.cfa_reg_offset;
  snapshot->loc_info          = (unw_frame_record_location_t) c->loc_info;

  return 0;
}
