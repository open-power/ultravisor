/* Copyright 2019 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef MASKED_SPRS_H
#define MASKED_SPRS_H

#define MASKED_SPR(r, i, v)	r##idx,

enum sprs {
	MASKED_SPR_FIRST = -1,
	#include "core/masked-sprs-raw.h"
	MASKED_SPR_LAST,
};

#undef MASKED_SPR

static inline void check_masked_spr_defs(void)
{
	int index = 0;
	/*
	 * This dummy switch statement detects duplicate indices
	 * (copy-paste errors) in masked-sprs.h as they can lead
	 * to incorrect or missed restore of some registers!
	 */
	switch(index) {
#define	MASKED_SPR(r, i, v)	case i:
#include "core/masked-sprs-raw.h"
#undef MASKED_SPR
		break;
	}
}

#endif /* MASKED_SPRS_H */
