=============
Locking Notes
=============

.. contents::
        :depth: 3

.. sectnum::
        :depth: 3

Global locks
============
Following is the current list of global locks (i.e locks not embedded in
a structure) along with some notes on their usage and possible optimizations
if any.

#. con_lock
	Used to serialize messages to the console.

#. reinit_lock
	Unused in UV. Used in skiboot. Can be dropped.

#. excp_counter_lock
	Used to assign an unique id to each exception.

#. dl_lock
	Used by deadlock checker

#. bt_lock
	Used when dumping back traces.

#. stack_check_lock
	Used when stack-checks are enabled in the compiler.

#. svm_lock
	Global SVM lock. 
		- Used to map lpid to svm
		- Used to protect partition table
		- Used during create/destroy of svm but could be optimized there:
			- svm_cleanup() operates entirely on the SVM and does not need
			  the global svm_lock.
			- create_svm() only needs the lock to check if an svm object
			  exists for the lpid. After that it can drop the global lock
			  (SVMs are not a global list but are independent objects)

#. xscom_lock
	Used when reading/writing xscoms.

#. mem_region_lock
	Used when reserving, allocating memory from memory regions.

#. drbg_lock
	Used when issuing calls to the mbedtls random bit generator.

Local locks
============

There are several locks that are embedded in data structures and since
they are more optimal than the global locks, they are not covered here.
Following are some notes about a few of the embedded locks:

#. svm->page_lock

	Used to serialize page-in, page-out and page-invalidate calls.
	But it is a coarse lock in that independent pages/ptes accesses
	are also serialized. Can that be optimized with a per-page lock?

#. ultra_heap.free_list_lock

	Used during memory allocation by memalign(). 
	
	In local_alloc(), free_list lock is in addition to mem_region_lock
	but local_alloc() is not used in UV. There is more unused code in
	core/mem_region.c like region type REGION_MEMORY, mem_reserve(),
	mem_reserve_fw() mem_reserve_hwbuf()(carried over from skiboot).

Optimization Tasks
==================

Following are some of the optimizations/improvements we should explore
after we have added more stability to the UV.

	- Lock instrumentation so we can measure the contention of locks
	  and to identify bottle-necks

	- Explore finer-grained svm->page_lock so that independent pages/ptes
	  are not blocked on the same lock.

	- Optimize use of svm->lock during svm_cleanup()

	- Consider dropping dead/unused code that got carried over from skiboot
