/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file */
#ifndef __S390_UTIL_MMIO_H
#define __S390_UTIL_MMIO_H
#include <stdbool.h>
#include <stdint.h>
#include <endian.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/auxv.h>

#include <util/compiler.h>

/* s390 requires special instructions to access IO memory. Originally there
   were only privileged IO instructions that are exposed via special syscalls.
   Starting with z15 there are also non-privileged memory IO (MIO) instructions
   we can execute in user-space. Despite the hardware support this requires
   support in the kernel. If MIO instructions are available is indicated in an
   ELF hardware capability.
 */
extern bool s390_is_mio_supported;

union register_pair {
	unsigned __int128 pair;
	struct {
		uint64_t even;
		uint64_t odd;
	};
};

/* The following pcilgi and pcistgi instructions allow IO memory access from
   user-space but are only available on z15 and newer.
*/
static inline uint64_t s390_pcilgi(const void *ioaddr, size_t len)
{
	union register_pair ioaddr_len = {.even = (uint64_t)ioaddr, .odd = len};
	uint64_t val;
	int cc;

	asm volatile (
		/* pcilgi */
		".insn   rre,0xb9d60000,%[val],%[ioaddr_len]\n"
		"ipm     %[cc]\n"
		"srl     %[cc],28\n"
		: [cc] "=d" (cc), [val] "=d" (val),
		  [ioaddr_len] "+&d" (ioaddr_len.pair) :: "cc");
	if (unlikely(cc))
		val = -1ULL;

	return val;
}

static inline void s390_pcistgi(void *ioaddr, uint64_t val, size_t len)
{
	union register_pair ioaddr_len = {.even = (uint64_t)ioaddr, .odd = len};
	int cc;

	do {
		asm volatile (
			/* pcistgi */
			".insn   rre,0xb9d40000,%[val],%[ioaddr_len]\n"
			"ipm     %[cc]\n"
			"srl     %[cc],28\n"
			: [cc] "=d" (cc), [ioaddr_len] "+&d" (ioaddr_len.pair)
			: [val] "d" (val)
			: "cc", "memory");
		if (cc == 2) /* busy */
			usleep(1);
	} while (cc == 2);
}

/* This is the block store variant of unprivileged IO access instructions */
static inline void s390_pcistbi(void *ioaddr, const void *data, size_t len)
{
	const uint8_t *src = data;

	asm volatile (
		/* pcistbi */
		".insn   rsy,0xeb00000000d4,%[len],%[ioaddr],%[src]\n"
		: [len] "+d" (len)
		: [ioaddr] "d" ((uint64_t *)ioaddr),
		  [src] "Q" (*src)
		: "cc");
}

static inline void s390_pciwb(void)
{
	if (s390_is_mio_supported)
		asm volatile (".insn rre,0xb9d50000,0,0\n"); /* pciwb */
	else
		asm volatile("" ::: "memory");
}

static inline void s390_mmio_write(void *mmio_addr, const void *val,
				   size_t length)
{
	syscall(__NR_s390_pci_mmio_write, mmio_addr, val, length);
}

static inline void s390_mmio_read(const void *mmio_addr, void *val,
				  size_t length)
{
	syscall(__NR_s390_pci_mmio_read, mmio_addr, val, length);
}

#define MAKE_WRITE(_NAME_, _SZ_)                                               \
	static inline void _NAME_##_be(void *addr, __be##_SZ_ value)           \
	{                                                                      \
		if (s390_is_mio_supported)                                     \
			s390_pcistgi(addr, value, sizeof(value));              \
		else                                                           \
			s390_mmio_write(addr, &value, sizeof(value));          \
	}                                                                      \
	static inline void _NAME_##_le(void *addr, __le##_SZ_ value)           \
	{                                                                      \
		if (s390_is_mio_supported)                                     \
			s390_pcistgi(addr, value, sizeof(value));              \
		else                                                           \
			s390_mmio_write(addr, &value, sizeof(value));          \
	}
#define MAKE_READ(_NAME_, _SZ_)                                                \
	static inline __be##_SZ_ _NAME_##_be(const void *addr)                 \
	{                                                                      \
		__be##_SZ_ res;                                                \
		if (s390_is_mio_supported)                                     \
			res = s390_pcilgi(addr, sizeof(res));                  \
		else                                                           \
			s390_mmio_read(addr, &res, sizeof(res));               \
		return res;                                                    \
	}                                                                      \
	static inline __le##_SZ_ _NAME_##_le(const void *addr)                 \
	{                                                                      \
		__le##_SZ_ res;                                                \
		if (s390_is_mio_supported)                                     \
			res = s390_pcilgi(addr, sizeof(res));                  \
		else                                                           \
			s390_mmio_read(addr, &res, sizeof(res));               \
		return res;                                                    \
	}


static inline void mmio_write8(void *addr, uint8_t value)
{
	if (s390_is_mio_supported)
		s390_pcistgi(addr, value, sizeof(value));
	else
		s390_mmio_write(addr, &value, sizeof(value));
}

static inline uint8_t mmio_read8(const void *addr)
{
	uint8_t res;
	if (s390_is_mio_supported)
		res = s390_pcilgi(addr, sizeof(res));
	else
		s390_mmio_read(addr, &res, sizeof(res));

	return res;
}

#endif /* __S390_UTIL_MMIO_H */
