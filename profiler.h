#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void profiler_start();
void profiler_stop();
void profile_add_frame(void *ptr);
void profile_pop_frame();
void profile_pop_all_frames();
void profile_set_pc(uint32_t *pc);

#ifdef __cplusplus
}
#endif
  
