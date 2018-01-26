#include <atomic.h>
#include <page_alloc.h>
#include <pgtable.h>
#include <limits.h>
#include <errno.h>
#include <cpu.h>
#include <numa.h>

#ifndef USERSPACE
#include <lock.h>
#include <logging.h>
#endif


typedef struct free_area_struct {
	struct list_head	free_list;
} free_area_t;

/*
 * Allocator information.
 */
struct numa_node_struct;
typedef struct pglist_data {
	/*
	 * Commonly accessed fields:
	 */
	struct lock		lock;
	unsigned long		free_pages;
	void			*start;
	struct pglist_data	*next;

	/*
	 * free areas of different sizes
	 */
	free_area_t		free_area[MAX_ORDER];

	/*
	 * Map contains one bit per page. Bit i in map, with j = number of
	 * consecutive ones at the least significant end of i's binary
	 * representation, contains xor of allocated for level j blocks (i >> j)
	 * and 1 + (i >> j). See also comment above __free_pages_ok.
	 */
	unsigned long		*map;
	mem_map_t		*mem_map;

	/*
	 * rarely used fields:
	 */
	unsigned long		size;
	struct numa_node_struct *node;
} pg_data_t;

typedef struct numa_node_struct {
	int32_t		node_id;
	pg_data_t	*areas;
} numa_node_t;

static atomic_t available_reservation;
static u32 max_nodes;
static u32 allocated_nodes;
static numa_node_t *numa_nodes;

/*
 * Debugging check.
 */
#define BAD_RANGE(numa, page)						\
(									\
	(((page) - numa->mem_map) >= (numa->size))			\
	|| ((page) < numa->mem_map)					\
)

static int __free_pages_ok(pg_data_t *pgdat, struct page *page,
			   unsigned int order);

#define BITMAP_INDEX(index, order) \
	(((index) & ~(1UL << (order))) | ((1UL << (order)) - 1))
#define MARK_USED(index, order, map) \
	__change_bit(BITMAP_INDEX(index, order), (map))

static inline struct page *expand(pg_data_t *pgdat, struct page *page,
	 unsigned long index, int low, int high, free_area_t * area)
{
	unsigned long size = 1 << high;

	while (high > low) {
		assert(!BAD_RANGE(pgdat, page));
		area--;
		high--;
		size >>= 1;
		list_add(&(area)->free_list, &(page)->list);
		MARK_USED(index, high, pgdat->map);
		index += size;
		page += size;
	}
	assert(!BAD_RANGE(pgdat, page));
	return page;
}

/*
 * must be called with &pgdat->lock held
 */
static struct page *rmqueue(pg_data_t *pgdat, unsigned int order)
{
	free_area_t *area = pgdat->free_area + order;
	unsigned int curr_order = order;
	struct list_node *head, *curr;
	struct page *page;

	do {
		head = &area->free_list.n;
		curr = head->next;

		if (curr != head) {
			unsigned int index;

			page = list_entry(curr, struct page, list);
			assert(!BAD_RANGE(pgdat, page));
			list_del(curr);
			index = page - pgdat->mem_map;
			MARK_USED(index, curr_order, pgdat->map);
			pgdat->free_pages -= 1UL << order;

			page = expand(pgdat, page, index, order, curr_order,
				      area);

			set_page_count(page, 1);
			page->order = order;
			return page;
		}
		curr_order++;
		area++;
	} while (curr_order < MAX_ORDER);

	return NULL;
}

static numa_node_t *get_numa_node(int n)
{
	assert(n < allocated_nodes);
	return &numa_nodes[n];
}

static numa_node_t *get_node_by_id(int32_t node_id)
{
	int i;

	for (i = 0; i < allocated_nodes; i++)
		if (numa_nodes[i].node_id == node_id)
			return &numa_nodes[i];

	return NULL;
}

static pg_data_t *get_pgdata_of_page(void *p)
{
	int i, j=0;
	numa_node_t *node;
	pg_data_t *pgdat;
	void *start, *end;

	/*
	 * @todo: To scale on a multiple numa system, implement
	 * a efficient datastructure.
	 *
	 * Start from the local node, than to the nearest
	 * neighbor, gradually progressing to the farthest node.
	 */
	i = 0;
	while (j++ < allocated_nodes) {
		node = get_numa_node(i);

		pgdat = node->areas;
		while (pgdat) {
			start = pgdat->start;
			end =  pgdat->start + (pgdat->size << UV_PAGE_SHIFT);

			if (p >= start && p < end)
				return pgdat;

			pgdat = pgdat->next;
		}
		i = (i+1) % allocated_nodes;
	}
	return NULL;
}

int32_t get_numa_node_id_of_page(void *p)
{
	pg_data_t *pgdat = get_pgdata_of_page(p);

	if (pgdat)
		return pgdat->node->node_id;

	return NUMA_NO_NODE;
}

/*
 * This is the 'heart' of the buddy allocator:
 *
 * Must be called with &pgdat->lock held
 */
static struct page *pg_alloc_pages(pg_data_t *pgdat, unsigned int order)
{
	struct page * page;

	page = rmqueue(pgdat, order);
	if (page)
		return page;

	pr_notice("__alloc_pages: %u-order allocation failed\n", order);
	return NULL;
}

/*
 * Allocate at most n pages. Store the number allocated in n_alloc.
 *
 * Must be called with &pgdat->lock held.
 */
static void *pg_alloc_n_pages(pg_data_t *pgdat, size_t n, size_t *n_alloc)
{
	unsigned int order;

	for (order = MAX_ORDER - 1; (1UL << order) > n; order--);

	do {
		struct page *page = pg_alloc_pages(pgdat, order);
		if (page) {
			*n_alloc = 1UL << order;
			return pgdat->start +
				((page - pgdat->mem_map) << UV_PAGE_SHIFT);
		}
	} while (order-- != 0);

	return NULL;
}

/* Allocate at most n pages. Store the number allocated in n_alloc. */
void *__alloc_n_pages(size_t n, size_t *n_alloc)
{
	int i, j=0;
	pg_data_t *pgdat;
	numa_node_t *node;
	void *retpage = NULL;
	int32_t my_numa_id = this_cpu()->numa_node_id;

	for (i = 0 ; i < allocated_nodes; i++) {
		node = get_numa_node(i);
		if (node->node_id == my_numa_id)
			break;
	}
	/* If the DT is not exposing the ibm,secure-memory, we don't know the
	 * node a secure memory is attached to. Thus all the numa nodes id are
	 * NUMA_NO_NODE (-1). So it is expected that we exit the previous loop
	 * without finding the numa node. In that case, we'll walk all the nodes
	 * to find some available secure memory.
	 */
	if (i >= allocated_nodes)
		i = 0;

	/*
	 * start from the local node, than to the nearest
	 * neighbor, gradually progressing to the farthest node.
	 */
	while (j++ < allocated_nodes) {
		node = get_numa_node(i);

		pgdat = node->areas;
		while (pgdat) {
			lock(&pgdat->lock);
			if (pgdat->free_pages >= n)
				retpage =  pg_alloc_n_pages(pgdat, n, n_alloc);
			unlock(&pgdat->lock);

			if (retpage)
				return retpage;

			pgdat = pgdat->next;
		}
		i = (i+1) % allocated_nodes;
	}
	return NULL;
}

static int __free_pages(pg_data_t *pgdat, struct page *page)
{
	if (page->count == 0) {
		pr_notice("%s: freeing already free page=0x%llx\n",
				__func__, (u64)page);
		return U_INVAL;
	}

	if (put_page_testzero(page))
		return __free_pages_ok(pgdat, page, page->order);
	else
		return 0;
}

int _free_pages(void *p)
{
	pg_data_t *pgdat;
	unsigned long addr;

	pgdat = get_pgdata_of_page(p);
	addr = p - pgdat->start;

	if (addr & UV_PAGE_OFFSET_MASK) {
		pr_notice("%s: invalid free addr=%lx\n",__func__, addr);
		return U_INVAL;
	}

	return __free_pages(pgdat, pgdat->mem_map + (addr >> UV_PAGE_SHIFT));
}

/*
 * Freeing function for a buddy system allocator.
 *
 * The concept of a buddy system is to maintain direct-mapped tables
 * (containing bit values) for memory blocks of various "orders".
 * The bottom level table contains the map for the smallest allocatable
 * units of memory (here, pages), and each level above it describes
 * pairs of units from the levels below, hence, "buddies".
 * At a high level, all that happens here is marking the table entry
 * at the bottom level available, and propagating the changes upward
 * as necessary, plus some accounting needed to play nicely with other
 * parts of the VM system.
 * At each level, we keep one bit for each pair of blocks, which
 * is set to 1 iff only one of the pair is allocated.  So when we
 * are allocating or freeing one, we can derive the state of the
 * other.  That is, if we allocate a small block, and both were
 * free, the remainder of the region must be split into blocks.
 * If a block is freed, and its buddy is also free, then this
 * triggers coalescing into a block of larger size.
 *
 * The bits are stored in a packed representation in pgdat->map. Level 0 is
 * stored at the even indices, level one in indices ending with 01 in binary,
 * level two ending in 011, and so on. For simplicity, one bit per page is
 * allocated, but this may be more than necessary since not all blocks have
 * buddies, and there isn't any need to store levels >= MAX_ORDER.
 */

static int __free_pages_ok(pg_data_t *pgdat, struct page *page, unsigned int order)
{
	unsigned long page_idx, mask;
	free_area_t *area;

	mask = (~0UL) << order;
	page_idx = page - pgdat->mem_map;
	if (page_idx & ~mask) {
		pr_notice("page_alloc: invalid free\n");
		return U_INVAL;
	}

	area = pgdat->free_area + order;

	lock(&pgdat->lock);

	pgdat->free_pages -= mask;

	while (mask + (1 << (MAX_ORDER-1))) {
		struct page *buddy1, *buddy2;
		unsigned long bitmap_index;

		assert(area < pgdat->free_area + MAX_ORDER);
		bitmap_index = BITMAP_INDEX(page_idx, order);
		if (!__test_and_change_bit(bitmap_index, pgdat->map))
			/*
			 * the buddy page is still allocated.
			 */
			break;
		/*
		 * Move the buddy up one level.
		 * This code is taking advantage of the identity:
		 * 	-mask = 1+~mask
		 */
		buddy1 = pgdat->mem_map + (page_idx ^ -mask);
		buddy2 = pgdat->mem_map + page_idx;
		assert(!BAD_RANGE(pgdat, buddy1));
		assert(!BAD_RANGE(pgdat, buddy2));

		list_del(&buddy1->list);
		mask <<= 1;
		area++;
		order++;
		page_idx &= mask;
	}
	list_add(&area->free_list, &(pgdat->mem_map + page_idx)->list);

	unlock(&pgdat->lock);
	return 0;
}

#define LONG_ALIGN(x) (((x)+(sizeof(long))-1)&~((sizeof(long))-1))

static unsigned long max_free_pages(unsigned long totalpages)
{
	unsigned long total_bits;

	/*
	 * x = free_pages
	 * metadata_bits = round_up_to_page(x * (1 + 8*sizeof(struct_page)))
	 * (assuming that struct_page's size is a whole number of longs)
	 *
	 * x * UV_PAGE_SIZE * 8 + metadata_bits <=
	 *         totalpages * UV_PAGE_SIZE * 8
	 * x * (UV_PAGE_SIZE * 8 + sizeof(struct_page) * 8 + 1) <=
	 *         totalpages * UV_PAGE_SIZE * 8
	 * x <= (totalpages * UV_PAGE_SIZE * 8) /
	 *         (UV_PAGE_SIZE * 8 + sizeof(struct_page) * 8 + 1)
	 */

	// No overflow
	assert(totalpages <= (ULONG_MAX >> (UV_PAGE_SHIFT + 3)));

	// Alignment
	assert(sizeof(struct page) % sizeof(unsigned long) == 0);

	total_bits = totalpages << (UV_PAGE_SHIFT + 3);
	return total_bits / ((UV_PAGE_SIZE + sizeof(struct page)) * 8 + 1);
}

int init_numa(u32 nodes)
{
	/* allocate the numa_nodes */
	numa_nodes =  zalloc(sizeof(numa_node_t) * nodes);
	if (!numa_nodes)
		return ENOMEM;

	max_nodes = nodes;
	allocated_nodes = 0;
	atomic_set(&available_reservation, 0);
	return 0;
}

static numa_node_t *allocate_numa_node(void)
{
	if (allocated_nodes >= max_nodes)
		return NULL;

	return &numa_nodes[allocated_nodes++];
}

void add_numa_node(int32_t node_id, void *start, size_t length)
{
	size_t totalpages;
	unsigned long start_paddr = (unsigned long) start;
	struct page *page;
	pg_data_t *pgdat;
	unsigned int order;
	unsigned long bitmap_size;
	unsigned long free_pages;
	void* metadata;
	numa_node_t *node;

	unsigned long i;
	const unsigned long required_alignment = 1UL << (MAX_ORDER-1);

	pr_debug("ADDING numa nodes %d [0x%p - 0x%p]\n",
		 node_id, start, start + length);

	/*
	 * We can deal with memory not attached to a numa node unless we
	 * allocate a node for node_id = NUMA_NO_NODE.
	 */
	if (node_id == NUMA_NO_NODE) {
		pr_error("Can't add secure area not attached to a NUMA node.\n");
		return;
	}

	/* Round up the start address and adjust the length accordingly */
	if (start_paddr & ~UV_PAGE_MASK) {
		start_paddr = (start_paddr & UV_PAGE_MASK) + UV_PAGE_SIZE;

		/*
		 * Check if the aligned address is not over the end of the
		 * secure are to register.
		 */
		if ((void *)start_paddr >= (start + length))
			goto out_too_small;

		length -= start_paddr - (unsigned long)start;
		pr_debug("Aligning: 0x%p -> 0x%lx (size: 0x%lx)\n",
			 start, start_paddr, length);

	}

	start = (void *) start_paddr;

	totalpages = length >> UV_PAGE_SHIFT;
	free_pages = max_free_pages(totalpages);

	if (!free_pages) {
out_too_small:
		pr_debug("Ignoring too small secure chunk\n");
		return;
	}

	node = get_node_by_id(node_id);
	if (!node) {
		node = allocate_numa_node();
		if (!node) {
			pr_error("ERROR Too many NUMA nodes\n");
			return;
		}
		node->node_id = node_id;
	}

	pgdat = zalloc(sizeof(pg_data_t));
	if (!pgdat) {
		pr_info("no more numa nodes available\n");
		return;
	}

	// Allocate metadata.
	metadata = start + (free_pages << UV_PAGE_SHIFT);
	pgdat->mem_map = metadata;
	pgdat->map = metadata + free_pages * sizeof(mem_map_t);
	memset(pgdat->mem_map, 0, free_pages * sizeof(mem_map_t));

	/* Round up to the nearest long of bits. */
	bitmap_size = LONG_ALIGN((free_pages + 7) >> 3);
	memset(pgdat->map, 0, bitmap_size);

	pr_info("page_alloc: %lu pages, %lu free, %lu metadata.\n",
		totalpages, free_pages, totalpages - free_pages);
	pgdat->size = free_pages;
	init_lock(&pgdat->lock);
	pgdat->free_pages = 0;
	pgdat->start = start;

	if ((start_paddr >> UV_PAGE_SHIFT) & (required_alignment-1))
		pr_notice("page_alloc: wrong alignment\n");

	for (i = 0; i < MAX_ORDER; i++)
		list_head_init(&pgdat->free_area[i].free_list);

	/* Add pages to free lists. */

	page = pgdat->mem_map;
	order = MAX_ORDER - 1;
	while (free_pages) {
		size_t size;
		while ((1UL << order) > free_pages) order--;
		size = 1UL << order;

		set_page_count(page, 1);
		page->order = order;
		__free_pages(pgdat, page);

		free_pages -= size;
		page += size;
	}
	atomic_add_return_relaxed(pgdat->size, &available_reservation);

	/* Link this area to the node */
	pgdat->node = node;
	pgdat->next = node->areas;
	node->areas = pgdat;
}

/*
 * The reservation system is a honorary system. The caller will be told if we
 * can accommodate the reservation.  However we expect the caller to enforce
 * self-discipline by not requesting more pages than reserved. The page
 * allocation code will not enforce the discipline. We trust the caller.  The
 * caller must also cleanup its reservation once done, by calling
 * __release_reservation().
 *
 * @n: number of UV_PAGE_SIZE pages.
 */
bool __make_reservation(size_t n)
{
	int val;

	if ((val = atomic_sub_return_relaxed(n, &available_reservation)) < 0) {
		atomic_add_return_relaxed(n, &available_reservation);
		return false;
	}

#ifdef RESERVATION_DEBUG
	pr_notice("%s: reserved=%x available=%x \n",
		  __func__, (unsigned int)n, val);
#endif /* RESERVATION_DEBUG */
	return true;
}

void __release_reservation(size_t n)
{
	int val = atomic_add_return_relaxed(n, &available_reservation);
#ifdef RESERVATION_DEBUG
	pr_notice("%s: released=%x available=%x \n",
		  __func__, (unsigned int)n, val);
#else /* RESERVATION_DEBUG */
	(void)val;
#endif /* RESERVATION_DEBUG */
}
