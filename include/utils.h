#ifndef __UTILS_H
#define __UTILS_H

#define ARRAY_LENGTH(X) (sizeof(X) / sizeof((X)[0]))

extern void __noreturn _abort(const char *msg);
extern char __sym_map_start[];
extern char __sym_map_end[];
extern char __attrconst tohex(uint8_t nibble);
extern size_t snprintf_symbol(char *buf, size_t len, uint64_t addr);
extern uint64_t generate_random_number(void);

/* @todo: Terminate just the SVM not entire UV */
#define svm_assert(rstate, condition)				\
{								\
	if (!(condition)) {					\
		pr_error("%s:%d ASSERT\n", __FILE__, __LINE__);	\
		svm_abort(rstate);				\
	}							\
}

#endif /* __UTILS_H */
