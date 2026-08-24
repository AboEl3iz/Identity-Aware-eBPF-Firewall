#ifndef __MAPS_H__
#define __MAPS_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

/* Helper macro for BTF map definitions */
#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif

#ifndef __type
#define __type(name, val) val *name
#endif

#endif /* __MAPS_H__ */
