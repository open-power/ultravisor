#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <malloc.h>
#include <endian.h>

#define	UV_ESMB_GET_FILE	0xF14C

extern int getfile_ucall(uint64_t ucall, uint64_t offset, uint64_t *fname);

void debug_params(uint64_t arg1, uint64_t arg2, uint64_t arg3);

int verbose = 0;
int testmode;

void debug_params(uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
	fprintf(stderr, "Args: [0x%016"PRIx64", 0x%016"PRIx64", 0x%016"PRIx64"]\n",
			arg1, arg2, arg3);
}

/*
 * dump first 64 and (upto) last 64 bytes from buf.
 */
static void dump_buf(FILE *fp, char buf[], int len)
{
	int i, count;

	if (!len)
		return;

	count = len;

	/* when testing print only upto first 64 and last 64 bytes */
	if (testmode && count > 64)
		count = 64;

	for (i = 0; i < count; i++)
		fprintf(fp, "%c", buf[i]);
	fprintf(fp, "\n");

	if ((len-count) == 0)
		return;

	if ((len-count) > 64) {
		i = len - 64;
		fprintf(fp, "... (%d bytes)\n", (i-count));
	}

	for (; i < len; i++)
		fprintf(fp, "%c",buf[i]);
	fprintf(fp, "\n");
}

static void dump_array(FILE *fp, uint64_t *dwords, int n)
{
        int i;

        for (i = 0; i < n; i++)
		fprintf(fp, "%s(): dwords[%d]: 0x%" PRIx64 "\n", __func__,
				i, dwords[i]);
}

int bytes_to_dwords(char *bytes, int nbytes, uint64_t *dwords, int ndw)
{
        int i, j, shift;

        if (nbytes > ndw * 8)
                return -1;

        memset(dwords, 0, ndw * 8);
        for (i = 0, j = 0, shift = 56; i < nbytes; i++) {
                dwords[j] |= ((uint64_t) bytes[i] << shift);
                shift -= 8;
                if (shift < 0) {
                        j++;
                        shift = 56;
                }
        }

	if (verbose)
		dump_array(stderr, dwords, ndw);

        return 0;
}

void dwords_to_bytes(uint64_t *dwords, int ndw, char *bytes)
{
        int i, j, shift;

        memset(bytes, 0, ndw*8+1);
        for (i = 0, j = 0, shift = 56; i < ndw; j++) {
                bytes[j] = (char) ((dwords[i] >> shift) & 0xFF);
                shift -= 8;
                if (shift < 0) {
                        shift = 56;
                        i++;
                }
        }
}

#define NUM_DWORDS 8

static int do_ucall(char *fname)
{
	int nbytes;
	char buf[65];
	uint64_t offset;
	uint64_t dwords[NUM_DWORDS];

	memset(buf, '@', sizeof(buf));

	offset = (uint64_t)0;

	do {
		/* filename cannot have NULLs in it, so ok to use strlen() */
		bytes_to_dwords(fname, strlen(fname), dwords, NUM_DWORDS);

		nbytes = getfile_ucall(UV_ESMB_GET_FILE, offset, dwords);

		if (verbose) {
			fprintf(stderr, "esmb-get-file[%s] offset %lu, nbytes"
					" %d\n", fname, offset, nbytes);
			fflush(stderr);
		}

		if (nbytes < 0) {
			fprintf(stderr, "[esmb-get-file[%s] failed, nbytes %d, %s\n",
					fname, nbytes, strerror(errno));
			/* exit so we can check UV logs before they wrap :-( */
			exit(1);
		}

		dwords_to_bytes(dwords, NUM_DWORDS, buf);

		dump_buf(stdout, buf, nbytes);

		offset += nbytes;
	} while(nbytes > 0);

	return nbytes;
}

static int do_test(char *filename)
{
	int rc;

	rc = do_ucall(filename);

	if (verbose)
		fprintf(stderr, "esmb-get-file[%s]: rc %d\n", filename, rc);

	return rc;
}

static void usage()
{
	/*
	 * If filename is not specified, assume "default"
	 */
	fprintf(stderr, "\n");
	fprintf(stderr, "esmb-get-file [-f filename]");
	fprintf(stderr, "\n");
}

#define MAX_FILENAME 65
char filename[MAX_FILENAME];

int main(int argc, char *argv[])
{
	int opt;

	snprintf(filename, sizeof(filename), "%s", "file-1");

	while((opt = getopt(argc, argv, "f:v")) != -1) {
		switch(opt) {
		case 'f':
			if (strnlen(optarg, sizeof(filename)) > sizeof(filename)) {
				fprintf(stderr, "filename length of %s exceeds %d\n",
						optarg, sizeof(filename));
				exit(1);
			}
			snprintf(filename, sizeof(filename), "%s", optarg);
			break;

		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			exit(1);
		}
	}

	if (optind != argc) {
		fprintf(stderr, "Unexpected arg %s\n", argv[optind]);
		usage();
	}

	return do_test(filename);
}
