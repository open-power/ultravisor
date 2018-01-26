#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <errno.h>

/*
 * Define a vector of 256 double-words.
 */
typedef uint64_t v8di   __attribute__ ((vector_size(2048)));

v8di a;
v8di b;
v8di c;
v8di cmp;

int itns;
int mils;

static void handle_intr(int sig)
{
	uint64_t count = mils * 1000000 + itns;

	printf("Caught SIGINT. Exiting after %lld iterations\n", count);
	exit(0);
}

int main(void)
{
	int i, N;

	N = sizeof(v8di) / sizeof(uint64_t);

	printf("N %d, Sizeof: double %d, v8di %d, a %d\n", N,
				sizeof(double), sizeof(v8di), sizeof(a));
	printf("Runs continuously. Hit CTRL-C to stop\n");

	/* Run until stopped by user */
repeat:
	itns++;

	signal(SIGINT, handle_intr);

	for (i = 0; i < N; i++) {
		a[i] = 11;
		b[i] = a[i] * 22;
	}

	for (i = 0; i < N; i++) {
		c[i] = a[i] * 22;
	}

	cmp = b == c;
	for (i = 0; i < N; i++) {
		if (!cmp[i]) {
			printf("FAIL: iteration %d i %d b/c/cmp: %ld/%ld/%ld\n",
					itns, i, b[i], c[i], cmp[i]);
			exit(1);
		}
	}

	if (itns == 1000000) {
		itns = 0;
		mils++;
		if (!(mils % 10))
			printf("Completed %d million iterations\n", mils);
	}

	goto repeat;
}
