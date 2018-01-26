.file   "ucall.S"
.abiversion 2
.section .text
.align 3

.section .text
.align 2
.globl getfile_ucall
.type getfile_ucall @function

getfile_ucall:
	/* Minmum 112 byte stack */
	stdu	%r1, -112(%r1)
	mflr	%r0
	std	%r0, 128(%r1)
	std	%r31, 32(%r1)
	mr	%r31, %r5
	/* r3 contains ucall number */
	/* r4 contains file offset */
	/* r5 contains the dwords[] which must be copied into r5:r12 */
	ld	%r5, 0(%r31)
	ld	%r6, 8(%r31)
	ld	%r7, 16(%r31)
	ld	%r8, 24(%r31)
	ld	%r9, 32(%r31)
	ld	%r10, 40(%r31)
	ld	%r11, 48(%r31)
	ld	%r12, 56(%r31)
	sc	2
	/* r3 contains return value (number of bytes) */
	/* r4:r11 contains the (upto) 64 bytes of data */
	std	%r4, 0(%r31)
	std	%r5, 8(%r31)
	std	%r6, 16(%r31)
	std	%r7, 24(%r31)
	std	%r8, 32(%r31)
	std	%r9, 40(%r31)
	std	%r10, 48(%r31)
	std	%r11, 56(%r31)
	ld	%r31, 32(%r1)
	ld	%r0, 128(%r1)
	mtlr	%r0
	ld	%r1, 0(%r1)
	blr
