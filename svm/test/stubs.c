#include <compiler.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <types.h>

#include <libfdt.h>

#include "stubs.h"

void _prlog(int log_level __attribute__((unused)), const char* fmt, ...) __attribute__((format (printf, 2, 3)));

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif
#define prlog(l, f, ...) do { _prlog(l, pr_fmt(f), ##__VA_ARGS__); } while(0)

typedef struct mem_node {
	u64	base;
	u64	size;
} mem_node_t;

void _prlog(int log_level __attribute__((unused)), const char* fmt, ...)
{
        va_list ap;

        va_start(ap, fmt);
        vprintf(fmt, ap);
        va_end(ap);
}

int alloc_fdt(void **fdt, size_t first_mem_block_size)
{
	int ret = 0;
	int len;
	void *_fdt = NULL;
	mem_node_t mem_node =
		{ .base = 0, .size = cpu_to_be64(first_mem_block_size) };

	_fdt = NULL;
	len = 0x30000;

	_fdt = malloc(len);

	if (!_fdt) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = fdt_create(_fdt, len);
	if (ret)
		goto err_out;

	ret = fdt_add_reservemap_entry(_fdt, 0xdaf0000, 0x10000);
	if (ret)
		goto err_out;

	ret = fdt_finish_reservemap(_fdt);
	if (ret)
		goto err_out;

	ret = fdt_begin_node(_fdt, ""); // Begin
	if (ret)
		goto err_out;

	ret = fdt_property_string(_fdt, "device_type", "chrp");
	if (ret)
		goto err_out;
	ret = fdt_property_string(_fdt, "model",
				  "IBM pSeries (emulated by qemu)");
	if (ret)
		goto err_out;
	ret = fdt_property_string(_fdt, "compatible", "qemu,pseries");
	if (ret)
		goto err_out;

	fdt_begin_node(_fdt, "chosen"); // Begin chosen
	if (ret)
		goto err_out;

	ret = fdt_property_cell(_fdt, "linux,initrd-start", 0x1b30000);
	if (ret)
		goto err_out;

	ret = fdt_end_node(_fdt); // End chosen
	if (ret)
		goto err_out;

	fdt_begin_node(_fdt, "memory@0"); // Begin memory@0
	if (ret)
		goto err_out;

	ret = fdt_property(_fdt, "reg", &mem_node, sizeof(mem_node_t));
	if (ret)
		goto err_out;

	ret = fdt_end_node(_fdt); // End memory@0
	if (ret)
		goto err_out;

	ret = fdt_end_node(_fdt); // End
	if (ret)
		goto err_out;

	ret = fdt_finish(_fdt);
	if (ret)
		goto err_out;

	goto out;

err_out:
	if (_fdt)
		free(_fdt);

out:
	*fdt = _fdt;
	return ret;
}

void free_fdt(void *fdt)
{
	free(fdt);
}
