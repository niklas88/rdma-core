/* GPLv2 or OpenIB.org BSD (MIT) See COPYING file

   These accessors always map to PCI-E TLPs in predictable ways. Translation
   to other buses should follow similar definitions.

   write32(mem, 1)
      Produce a 4 byte MemWr TLP with bit 0 of DW byte offset 0 set
   write32_be(mem, htobe32(1))
      Produce a 4 byte MemWr TLP with bit 0 of DW byte offset 3 set
   write32_le(mem, htole32(1))
      Produce a 4 byte MemWr TLP with bit 0 of DW byte offset 0 set

   For ordering these accessors are similar to the Kernel's concept of
   writel_relaxed(). When working with UC memory the following hold:

   1) Strong ordering is required when talking to the same device (eg BAR),
      and combining is not permitted:

       write32(mem, 1);
       write32(mem + 4, 1);
       write32(mem, 1);

      Must produce three TLPs, in order.

   2) Ordering ignores all pthread locking:

       pthread_spin_lock(&lock);
       write32(mem, global++);
       pthread_spin_unlock(&lock);

      When run concurrently on all CPUs the device must observe all stores,
      but the data value will not be strictly increasing.

   3) Interaction with DMA is not ordered. Explicit use of a barrier from
      udma_barriers is required:

	*dma_mem = 1;
	udma_to_device_barrier();
	write32(mem, GO_DMA);

   4) Access out of program order (eg speculation), either by the CPU or
      compiler is not permitted:

	if (cond)
	   read32();

      Must not issue a read TLP if cond is false.

   If these are used with WC memory then #1 and #4 do not apply, and all WC
   accesses must be bracketed with mmio_wc_start() // mmio_flush_writes()
*/

#ifndef __UTIL_MMIO_H
#define __UTIL_MMIO_H

#include <linux/types.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>
#include <endian.h>

#include <config.h>
#include <util/compiler.h>

/* The first step is to define the 'raw' accessors. To make this very safe
   with sparse we define two versions of each, a le and a be - however the
   code is always identical.
*/
#ifdef __s390x__
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/auxv.h>

/* s390 requires special instructions to access IO memory. Originally there
   were only privileged IO instructions that are exposed via special syscalls.
   Starting with z15 there are also non-privileged memory IO (MIO) instructions
   we can execute in user-space. Despite the hardware support this requires
   support in the kernel. If MIO instructions are available is indicated in an
   ELF hardware capability.
 */
extern int s390_mio_supported;

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

	asm volatile (
		"       .insn   rre,0xb9d60000,%[val],%[ioaddr_len]\n"
		: [val] "=d" (val),
		  [ioaddr_len] "+&d" (ioaddr_len.pair) :: "cc");
	return val;
}

static inline void s390_pcistgi(void *ioaddr, uint64_t val, size_t len)
{
	union register_pair ioaddr_len = {.even = (uint64_t)ioaddr, .odd = len};

	asm volatile (
		"       .insn   rre,0xb9d40000,%[val],%[ioaddr_len]\n"
		: [ioaddr_len] "+&d" (ioaddr_len.pair)
		: [val] "d" (val)
		: "cc", "memory");
}

/* This is the block store variant of unprivileged IO access instructions */
static inline void s390_pcistbi(void *ioaddr, const void *data, size_t len)
{
	const uint8_t *src = data;

	asm volatile (
		"       .insn   rsy,0xeb00000000d4,%[len],%[ioaddr],%[src]\n"
		: [len] "+d" (len)
		: [ioaddr] "d" ((uint64_t *)ioaddr),
		  [src] "Q" (*src)
		: "cc");
}

static inline void s390_mmio_write(void *mmio_addr, const void *val,
				   size_t length)
{
	// FIXME: Check for error and call abort?
	syscall(__NR_s390_pci_mmio_write, mmio_addr, val, length);
}

static inline void s390_mmio_read(const void *mmio_addr, void *val,
				  size_t length)
{
	// FIXME: Check for error and call abort?
	syscall(__NR_s390_pci_mmio_read, mmio_addr, val, length);
}

#define MAKE_WRITE(_NAME_, _SZ_)                                               \
	static inline void _NAME_##_be(void *addr, __be##_SZ_ value)           \
	{                                                                      \
		if (likely(s390_mio_supported))                                \
			s390_pcistgi(addr, value, sizeof(value));              \
		else                                                           \
			s390_mmio_write(addr, &value, sizeof(value));          \
	}                                                                      \
	static inline void _NAME_##_le(void *addr, __le##_SZ_ value)           \
	{                                                                      \
		if (likely(s390_mio_supported))                                \
			s390_pcistgi(addr, value, sizeof(value));              \
		else                                                           \
			s390_mmio_write(addr, &value, sizeof(value));          \
	}
#define MAKE_READ(_NAME_, _SZ_)                                                \
	static inline __be##_SZ_ _NAME_##_be(const void *addr)                 \
	{                                                                      \
		__be##_SZ_ res;                                                \
		if (likely(s390_mio_supported))                                \
			res = s390_pcilgi(addr, sizeof(res));                  \
		else                                                           \
			s390_mmio_read(addr, &res, sizeof(res));               \
		return res;                                                    \
	}                                                                      \
	static inline __le##_SZ_ _NAME_##_le(const void *addr)                 \
	{                                                                      \
		__le##_SZ_ res;                                                \
		if (likely(s390_mio_supported))                                \
			res = s390_pcilgi(addr, sizeof(res));                  \
		else                                                           \
			s390_mmio_read(addr, &res, sizeof(res));               \
		return res;                                                    \
	}


static inline void mmio_write8(void *addr, uint8_t value)
{
	if (likely(s390_mio_supported))
		s390_pcistgi(addr, value, sizeof(value));
	else
		s390_mmio_write(addr, &value, sizeof(value));
}

static inline uint8_t mmio_read8(const void *addr)
{
	uint8_t res;
	if (likely(s390_mio_supported))
		res = s390_pcilgi(addr, sizeof(res));
	else
		s390_mmio_read(addr, &res, sizeof(res));
	return res;
}
#else /* __s390x__ */

#define MAKE_WRITE(_NAME_, _SZ_)                                               \
	static inline void _NAME_##_be(void *addr, __be##_SZ_ value)           \
	{                                                                      \
		atomic_store_explicit((_Atomic(uint##_SZ_##_t) *)addr,         \
				      (__force uint##_SZ_##_t)value,           \
				      memory_order_relaxed);                   \
	}                                                                      \
	static inline void _NAME_##_le(void *addr, __le##_SZ_ value)           \
	{                                                                      \
		atomic_store_explicit((_Atomic(uint##_SZ_##_t) *)addr,         \
				      (__force uint##_SZ_##_t)value,           \
				      memory_order_relaxed);                   \
	}
#define MAKE_READ(_NAME_, _SZ_)                                                \
	static inline __be##_SZ_ _NAME_##_be(const void *addr)                 \
	{                                                                      \
		return (__force __be##_SZ_)atomic_load_explicit(               \
		    (_Atomic(uint##_SZ_##_t) *)addr, memory_order_relaxed);    \
	}                                                                      \
	static inline __le##_SZ_ _NAME_##_le(const void *addr)                 \
	{                                                                      \
		return (__force __le##_SZ_)atomic_load_explicit(               \
		    (_Atomic(uint##_SZ_##_t) *)addr, memory_order_relaxed);    \
	}

static inline void mmio_write8(void *addr, uint8_t value)
{
	atomic_store_explicit((_Atomic(uint8_t) *)addr, value,
			      memory_order_relaxed);
}
static inline uint8_t mmio_read8(const void *addr)
{
	return atomic_load_explicit((_Atomic(uint32_t) *)addr,
				    memory_order_relaxed);
}
#endif /* __s390x__ */

MAKE_WRITE(mmio_write16, 16)
MAKE_WRITE(mmio_write32, 32)

MAKE_READ(mmio_read16, 16)
MAKE_READ(mmio_read32, 32)

#if SIZEOF_LONG == 8
MAKE_WRITE(mmio_write64, 64)
MAKE_READ(mmio_read64, 64)
#else
void mmio_write64_be(void *addr, __be64 val);
static inline void mmio_write64_le(void *addr, __le64 val)
{
	mmio_write64_be(addr, (__be64 __force)val);
}

/* There is no way to do read64 atomically, rather than provide some sketchy
   implementation we leave these functions undefined, users should not call
   them if SIZEOF_LONG != 8, but instead implement an appropriate version.
*/
__be64 mmio_read64_be(const void *addr);
__le64 mmio_read64_le(const void *addr);
#endif /* SIZEOF_LONG == 8 */

#undef MAKE_WRITE
#undef MAKE_READ

/* Now we can define the host endian versions of the operator, this just includes
   a call to htole.
*/
#define MAKE_WRITE(_NAME_, _SZ_)                                               \
	static inline void _NAME_(void *addr, uint##_SZ_##_t value)            \
	{                                                                      \
		_NAME_##_le(addr, htole##_SZ_(value));                         \
	}
#define MAKE_READ(_NAME_, _SZ_)                                                \
	static inline uint##_SZ_##_t _NAME_(const void *addr)                  \
	{                                                                      \
		return le##_SZ_##toh(_NAME_##_le(addr));                       \
	}

/* This strictly guarantees the order of TLP generation for the memory copy to
   be in ascending address order.
*/
#ifdef __s390x__
#define S390_PCI_MAX_WRITE_SIZE 128
static inline uint8_t s390_get_max_write_size(uint64_t src, uint64_t dst, int len, int max)
{
	int count = len > max ? max : len, size = 1;

	while (!(src & 0x1) && !(dst & 0x1) && ((size << 1) <= count)) {
		dst = dst >> 1;
		src = src >> 1;
		size = size << 1;
	}
	return size;
}

static inline void mmio_memcpy_x64(void *dst, const void *src, size_t bytecnt)
{
	int size;

	if (unlikely(!s390_mio_supported))
		s390_mmio_write(dst, src, bytecnt);

	while (bytecnt > 0) {
		size = s390_get_max_write_size((uint64_t __force) dst,
					       (uint64_t) src, bytecnt,
					       S390_PCI_MAX_WRITE_SIZE);
		if (size > 8) /* main path */
			s390_pcistbi(dst, src, size);
		else if (size == 8)
			s390_pcistgi(dst, *(uint64_t *)src, 8);
		else if (unlikely(size == 4))
			s390_pcistgi(dst, *(uint32_t *)src, 4);
		else if (unlikely(size == 2))
			s390_pcistgi(dst, *(uint16_t *)src, 2);
		else if (unlikely(size == 1))
			s390_pcistgi(dst, *(uint8_t *)src, 1);

		src += size;
		dst += size;
		bytecnt -= size;
	}
	return;
}
#elif defined(__aarch64__) || defined(__arm__)
#include <arm_neon.h>

static inline void _mmio_memcpy_x64_64b(void *dest, const void *src)
{
	vst4q_u64(dest, vld4q_u64(src));
}

static inline void _mmio_memcpy_x64(void *dest, const void *src, size_t bytecnt)
{
	do {
		_mmio_memcpy_x64_64b(dest, src);
		bytecnt -= sizeof(uint64x2x4_t);
		src += sizeof(uint64x2x4_t);
		dest += sizeof(uint64x2x4_t);
	} while (bytecnt > 0);
}

#define mmio_memcpy_x64(dest, src, bytecount)                                  \
	({                                                                     \
		if (__builtin_constant_p((bytecount) == 64))                   \
			_mmio_memcpy_x64_64b((dest), (src));                   \
		else                                                           \
			_mmio_memcpy_x64((dest), (src), (bytecount));          \
	})

#else
/* Transfer is some multiple of 64 bytes */
static inline void mmio_memcpy_x64(void *dest, const void *src, size_t bytecnt)
{
	uintptr_t *dst_p = dest;

	/* Caller must guarantee:
	    assert(bytecnt != 0);
	    assert((bytecnt % 64) == 0);
	    assert(((uintptr_t)dest) % __alignof__(*dst) == 0);
	    assert(((uintptr_t)src) % __alignof__(*dst) == 0);
	*/

	/* Use the native word size for the copy */
	if (sizeof(*dst_p) == 8) {
		const __be64 *src_p = src;

		do {
			/* Do 64 bytes at a time */
			mmio_write64_be(dst_p++, *src_p++);
			mmio_write64_be(dst_p++, *src_p++);
			mmio_write64_be(dst_p++, *src_p++);
			mmio_write64_be(dst_p++, *src_p++);
			mmio_write64_be(dst_p++, *src_p++);
			mmio_write64_be(dst_p++, *src_p++);
			mmio_write64_be(dst_p++, *src_p++);
			mmio_write64_be(dst_p++, *src_p++);

			bytecnt -= 8 * sizeof(*dst_p);
		} while (bytecnt > 0);
	} else if (sizeof(*dst_p) == 4) {
		const __be32 *src_p = src;

		do {
			mmio_write32_be(dst_p++, *src_p++);
			mmio_write32_be(dst_p++, *src_p++);
			bytecnt -= 2 * sizeof(*dst_p);
		} while (bytecnt > 0);
	}
}
#endif

MAKE_WRITE(mmio_write16, 16)
MAKE_WRITE(mmio_write32, 32)
MAKE_WRITE(mmio_write64, 64)

MAKE_READ(mmio_read16, 16)
MAKE_READ(mmio_read32, 32)
MAKE_READ(mmio_read64, 64)

#undef MAKE_WRITE
#undef MAKE_READ

#endif
