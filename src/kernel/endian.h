#ifndef ENDIAN_H
#define ENDIAN_H

#include <bpf/bpf_endian.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define __bpf_le32_to_cpu(x)		(x)
# define __bpf_cpu_to_le32(x)		(x)
# define __bpf_constant_le32_to_cpu(x)	(x)
# define __bpf_constant_cpu_to_le32(x)	(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# define __bpf_le32_to_cpu(x)		__builtin_bswap32(x)
# define __bpf_cpu_to_le32(x)		__builtin_bswap32(x)
# define __bpf_constant_le32_to_cpu(x)  ___bpf_swab32(x)
# define __bpf_constant_cpu_to_le32(x)  ___bpf_swab32(x)
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define bpf_cpu_to_le32(x)			\
	(__builtin_constant_p(x) ?		\
	 __bpf_constant_cpu_to_le32(x) : __bpf_cpu_to_le32(x))
#define bpf_le32_to_cpu(x)			\
	(__builtin_constant_p(x) ?		\
	 __bpf_constant_le32_to_cpu(x) : __bpf_le32_to_cpu(x))

#endif
