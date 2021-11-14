#ifndef VM_FRAME_H
#define VM_FRAME_H

void pinning (void *buffer, unsigned size);
void unpinning (void *buffer, unsigned size);
bool evict_frame(void);
void *frame_for_swap;

#endif