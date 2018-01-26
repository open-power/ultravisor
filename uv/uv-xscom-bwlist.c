// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2019 IBM Corp.
 */

#include "uv-xscom-bwlist.h"
#include "uv-xscom-security.h"
#include <stdlib.h>
#ifndef __PPE__
#include <string.h>
#endif
#include <device.h>
#include <ctype.h>
#include <logging.h>

#ifndef __PPE__
static bool isSecurityListInitDone = false;
#endif
static GenSecurityListTables_t secListTableSupport;
__attribute__((__const__)) uint32_t get_shift_len(uint32_t mask, uint8_t shifts);
void binary_search_table2( const _t2_table_t *table2,
                    const uint32_t search_key,
                    range_t *x_range,
		    map_t *search_result);
void  binary_search_table3( const _t3_table_t *table3,
                    const uint32_t search_key,
                    range_t *x_range,
		    map_t *search_result);
static const size_t SEC_LIST_TABLE_HDR_SIZE = sizeof(sec_header_dump_t);
void printSecurityAccessTables (void);
void get_uvbwlist_addr (u64 *ibuf_start_addr, u64 *size);

// #define XSCOM_UV_BWLIST_DEBUG
static GenSecurityListTables_t UVsecListTableSupport;

// Helper function to figure out the number of shifts required for the mask
__attribute__((__const__)) uint32_t get_shift_len(uint32_t mask, uint8_t shifts)
{
    return ((mask>>shifts) & 0x01) ? (shifts) : (get_shift_len(mask, ++shifts));
}

void binary_search_table2( const _t2_table_t *table2,
                    const uint32_t search_key,
                    range_t *x_range,
		    map_t *search_result)
{
    map_t ret = {false, 0}; // found=false

    while((x_range->start <= x_range->end) &&
          (ret.key == false))
    {
        int32_t midpoint = (x_range->start + x_range->end) / 2;
        uint32_t ele;

	/* Get midpoint */
	ele = table2->table[midpoint].key;
        if(search_key == ele)
        {
            ret.key = true;
            ret.value = midpoint;
        }
        else if(search_key < ele)
        {
            x_range->end = midpoint - 1;
        }
        else
        {
            x_range->start = midpoint + 1;
        }
    }

    search_result->key = ret.key;
    search_result->value = ret.value;
    return ;
}

void  binary_search_table3( const _t3_table_t *table3,
                    const uint32_t search_key,
                    range_t *x_range,
		    map_t *search_result)
{
    map_t ret = {false, 0}; // found=false

    while((x_range->start <= x_range->end) &&
          (ret.key == false))
    {
        int32_t midpoint = (x_range->start + x_range->end) / 2;
        uint32_t ele;

	/* Get midpoint */
	ele = table3->table[midpoint].value;
        if(search_key == ele)
        {
            ret.key = true;
            ret.value = midpoint;
        }
        else if(search_key < ele)
        {
            x_range->end = midpoint - 1;
        }
        else
        {
            x_range->start = midpoint + 1;
        }
    }
    search_result->key = ret.key;
    search_result->value = ret.value;
    return ;
}

//----------------------------------------------------------------------------
//  @brief Public function used for init all white, black and grey list table
//  data, WhiteList/ BalckList Tables [T1, T2 and T3] and GreyList [T1]
//----------------------------------------------------------------------------
bool _is_present_addr( const _t1_table_t *table1,
                           const _t2_table_t *table2,
                           const _t3_table_t *table3,
                           const uint32_t i_addr)
{
    map_t search_result;
    range_t search_range;
    uint32_t search_key;
    size_t i = 0;

    for(i = 0; i < table1->size; i++)
    {
        search_key = (i_addr & table1->mask) >> get_shift_len(table1->mask, 0);
	
        if((table1->table[i].key_start <= search_key) &&
           (table1->table[i].key_end >= search_key))
        {
            search_key = (i_addr & table2->mask) >> get_shift_len(table2->mask, 0);
            search_range.start = i ? table1->table[i-1].value : 0;
            search_range.end = table1->table[i].value - 1;
            binary_search_table2(
			table2,
                        search_key,
                        &search_range,
			&search_result);
            if(search_result.key == true)
            {
                // Found the key in table 2
                search_range.start = (search_result.value ?
                                table2->table[search_result.value-1].value : 0);
                search_range.end =
                                table2->table[search_result.value].value - 1;
                search_key = (i_addr & table3->mask) >>
                                               get_shift_len(table3->mask, 0);
                // Search table 3
                binary_search_table3(
					    table3,
                                            search_key,
                                            &search_range,
					    &search_result);
                if(search_result.key == true)
                {
                    // Found the number
                    return true;
                }
            }
        }
    }
    return false;
}

//----------------------------------------------------------------------------
//  @brief Look up tables to find if the given address with mask is present
//  on GreyList Table [T1]
//----------------------------------------------------------------------------
bool _is_present(const _gl_t1_table_t *table1,
                 const uint32_t i_addr,
                 const uint64_t i_mask)
{
    bool ret = false;
    for(size_t i = 0; i < table1->size; i++)
    {
        // Not using mask in table for search
        if((table1->table[i].key ==  i_addr) &&
           (( i_mask & (~table1->table[i].value)) == 0 ))
        {
            ret = true;
            break;
        }
    }
    return ret;
}

//----------------------------------------------------------------------------
//  @brief Public function used for address verification for a given type of
//  access.
//----------------------------------------------------------------------------
bool isAccessAllowed(const uint32_t i_addr, uint64_t i_mask,
                     secAccessType i_type)
{
    bool ret = true;
#ifndef __PPE__
    if(!isSecurityListInitDone)
    {
        ret = false; // Table Init was not yet done
    }
    else if(i_type == WRITE_ACCESS)
    {
        ret = _is_present_addr( &secListTableSupport.wl_t1,
                           &secListTableSupport.wl_t2,
                           &secListTableSupport.wl_t3,
                           i_addr );
        if( (ret == false ) && (i_mask != 0xffffffffffffffffull ))
        {
            ret = _is_present( &secListTableSupport.gl_t1,
                               i_addr, i_mask );
        }
        if ( ret == false ) {
	     // Check the Ultravisor Exception List
             ret = _is_present_addr( &UVsecListTableSupport.wl_t1,
                           &UVsecListTableSupport.wl_t2,
                           &UVsecListTableSupport.wl_t3,
                           i_addr );
#ifdef XSCOM_UV_BWLIST_DEBUG
	     if ( ret == false ) {
		     pr_error("ULTRAVISOR Write Access Denied for 0x%x\n",
			      (uint32_t)i_addr);
	     }
#endif
	}
    }
    else if(i_type == READ_ACCESS)
    {
        ret = !_is_present_addr( &secListTableSupport.bl_t1,
                            &secListTableSupport.bl_t2,
                            &secListTableSupport.bl_t3,
                            i_addr );
	// Check the Ultravisor Exception List
	if ( ret == false ) {
		ret = !_is_present_addr( &UVsecListTableSupport.bl_t1,
					 &UVsecListTableSupport.bl_t2,
					 &UVsecListTableSupport.bl_t3,
					 i_addr );
#ifdef XSCOM_UV_BWLIST_DEBUG
		if ( ret == false ) {
			pr_error("ULTRAVISOR Read Access Denied for 0x%x\n",
				 (uint32_t)i_addr);
		}
#endif
	}
    }
#endif
    return ret;
}

void printSecurityAccessTables (void)
{

        int size = 0;
	int i = 0;

	pr_error("WhiteList \n");
	// Table 1
	// uint8_t key_start;
	// uint8_t key_end;
	// uint8_t value;
	size = secListTableSupport.wl_t1.size;
	pr_error("Table 1: Size = %d \n", size);
	pr_error("{Key Start , Key End , Value} \n");
	for ( i = 0; i < size; i ++) {
	    pr_error("{0x%.2x, 0x%.2x, 0x%.2x}, ",
		     secListTableSupport.wl_t1.table[i].key_start,
		     secListTableSupport.wl_t1.table[i].key_end,
		     secListTableSupport.wl_t1.table[i].value);
	}
	pr_error("\n");

	// Table 2
	// uint8_t  key;
	//  uint16_t value;
	size = secListTableSupport.wl_t2.size;
	pr_error("Table 2: Size = %d \n", size);
	pr_error("{Key ,Value} \n");
	for ( i = 0; i < size; i ++) {
		pr_error("{0x%.2x, 0x%.4x}, ",
			 secListTableSupport.wl_t2.table[i].key,
			 secListTableSupport.wl_t2.table[i].value);
	}
	pr_error("\n");

	// Table 3
	//  uint16_t value;
	size = secListTableSupport.wl_t3.size;
	pr_error("Whitelist Table 3: Size = %d \n", size);
	pr_error("{Key ,Value} \n");
	for ( i = 0; i < size; i ++) {
	    pr_error("{0x%.4x}, ",
		     secListTableSupport.wl_t3.table[i].value);
	}
	pr_error("\n");

	pr_error("\n BlackList \n");
	// Table 1
	// uint8_t key_start;
	// uint8_t key_end;
	// uint8_t value;
	size = secListTableSupport.bl_t1.size;
	pr_error("Table 1: Size = %d \n", size);
	pr_error("{Key Start , Key End , Value} \n");
	for ( i = 0; i < size; i ++) {
		pr_error("{0x%.2x, 0x%.2x, 0x%.2x}, ",
			 secListTableSupport.bl_t1.table[i].key_start,
			 secListTableSupport.bl_t1.table[i].key_end,
			 secListTableSupport.bl_t1.table[i].value);
	}
	pr_error("\n");

	// Table 2
	// uint8_t  key;
	//  uint16_t value;
	size = secListTableSupport.bl_t2.size;
	pr_error("Table 2: Size = %d \n", size);
	pr_error("{Key ,Value} \n");
	for ( i = 0; i < size; i ++) {
		pr_error("{0x%.2x, 0x%.4x}, ",
			 secListTableSupport.bl_t2.table[i].key,
			 secListTableSupport.bl_t2.table[i].value);
	}
	pr_error("\n");

	// Table 3
	//  uint16_t value;
	size = secListTableSupport.bl_t3.size;
	pr_error("Blacklist Table 3: Size = %d \n", size);
	pr_error("{Key ,Value} \n");
	for ( i = 0; i < size; i ++) {
	    pr_error("{0x%.4x}, ",
		     secListTableSupport.bl_t3.table[i].value);
	}
	pr_error("\n");

	pr_error("\n GreyList \n");
	/*@brief Format of Grey list table date */
    	// 	typedef struct
    	// {
	// uint32_t key;
	// uint64_t value;
    	// } _gl_t1_t;  // Total 12 bytes


	size = secListTableSupport.gl_t1.size;
	pr_error("GreyList Table 1: Size = %d \n", size);
	for ( i = 0; i < size; i ++) {
		pr_error("{0x%.8x, 0x%.16x}, ",
			 (uint32_t)secListTableSupport.gl_t1.table[i].key,
			 (uint32_t)secListTableSupport.gl_t1.table[i].value);
	}
	pr_error("\n");

}

//----------------------------------------------------------------------------
//  @brief Helper function used to get the starting address and size of the
//  Reserved Memory section that holds the UVBWLIST. This memory is populated by Hostboot.
//----------------------------------------------------------------------------
void get_uvbwlist_addr (uint64_t *ibuf_start_addr, uint64_t *size)
{
    struct dt_node *node, *hb_reserved_mem;

        hb_reserved_mem = dt_find_by_path(dt_root, "/ibm,hostboot/reserved-memory");
        if (!hb_reserved_mem) {
		pr_error("/ibm,hostboot/reserved-memory node not found\n");
                return;
        }

        dt_for_each_node(hb_reserved_mem, node) {
                const char *prd_label;
                prd_label = dt_prop_get(node, "ibm,prd-label");
                if ((prd_label) && !strcmp(prd_label, "ibm,uvbwlist")) {
		    *ibuf_start_addr = dt_get_address(node, 0, size);
#ifdef XSCOM_UV_BWLIST_DEBUG
		    pr_error("Janani - UVBWLIST MEM start = %016llx %016llx\n",
			     *ibuf_start_addr, *size);
#endif
		    return;
		}
        }
        return;
}

//----------------------------------------------------------------------------
//  @brief Public function used for init all white, black and grey list table
//  data, WhiteList/ BalckList Tables [T1, T2 and T3] and GreyList [T1]
//----------------------------------------------------------------------------
bool securityAccessTablesInit(void)
{
    bool ret = false;
    sec_header_dump_t* l_table_sizes;
    uint8_t *l_buf;
    size_t l_size;
    uint32_t uvbwlist_actual; 
    uint64_t i_buf = 0;
    uint64_t size = 0;

#ifndef __PPE__
    get_uvbwlist_addr (&i_buf, &size);
    if (i_buf == 0) {
	// Could not find the address of the uvbwlist reserved memory section
	pr_error("Could not retrieve the UVBWLIST memory address \n");
	return ret;
    }

    do
    {
        // uint8_t * l_buf = reinterpret_cast<uint8_t*>(const_cast<void*>(i_buf));
        l_buf = (uint8_t*)(i_buf);
        if(isSecurityListInitDone)
        {
            break; // Table Init was already done
        }

        // Read header
        // sec_header_dump_t* l_table_sizes =
        //              reinterpret_cast<sec_header_dump_t*>(l_buf);
        l_table_sizes = (sec_header_dump_t*)(l_buf);


	// BE to LE conversion
#undef BE2LE
#define BE2LE(x) do { (x) = be16_to_cpu((beint16_t)(x)); } while(0)

	BE2LE(l_table_sizes->wl_t1_count);
	BE2LE(l_table_sizes->wl_t2_count);
	BE2LE(l_table_sizes->wl_t3_count);
	BE2LE(l_table_sizes->bl_t1_count);
	BE2LE(l_table_sizes->bl_t2_count);
	BE2LE(l_table_sizes->bl_t3_count);
	BE2LE(l_table_sizes->gl_t1_count);

#undef BE2LE

        pr_error("Table Sizes: White: T1 %d, T2 %d, T3 %d \n",
		 l_table_sizes->wl_t1_count,
		 l_table_sizes->wl_t2_count,
		 l_table_sizes->wl_t3_count);

        pr_error("Table Sizes: Black : T1 %d, T2 %d, T3 %d \n",
		 l_table_sizes->bl_t1_count,
		 l_table_sizes->bl_t2_count,
		 l_table_sizes->bl_t3_count);

        pr_error("Table Sizes: Grey : T1 %d \n",
		 l_table_sizes->gl_t1_count);

	// Make sure the size of the data is not more than the allocated
	// space for the UVBWLIST
	uvbwlist_actual = SEC_LIST_TABLE_HDR_SIZE +
                            (sizeof(_t1_t))*(l_table_sizes->wl_t1_count) +
                            (sizeof(_t2_t))*(l_table_sizes->wl_t2_count) +
                            (sizeof(_t3_t))*(l_table_sizes->wl_t3_count) +
                            (sizeof(_t1_t))*(l_table_sizes->bl_t1_count) +
                            (sizeof(_t2_t))*(l_table_sizes->bl_t2_count) +
                            (sizeof(_t3_t))*(l_table_sizes->bl_t3_count) +
                            (sizeof(_gl_t1_t))*(l_table_sizes->gl_t1_count);

	if ( uvbwlist_actual > size) {
		pr_error("error in UVBW Lists size. Actual = %u, "
			 "Max allowed size: %llu \n", uvbwlist_actual, size);
		break;
	}

        // Read and Update whitelist tables1
        l_size = SEC_LIST_TABLE_HDR_SIZE;
        secListTableSupport.wl_t1.size = l_table_sizes->wl_t1_count;
        secListTableSupport.wl_t1.mask = WHITELIST_TABLE1_MASK;

        secListTableSupport.wl_t1.table = (_t1_t*) malloc((sizeof(_t1_t))*(l_table_sizes->wl_t1_count));
        memcpy( secListTableSupport.wl_t1.table, l_buf+SEC_LIST_TABLE_HDR_SIZE, (sizeof(_t1_t))*((l_table_sizes->wl_t1_count)) );

        // Read and Update whitelist tables2
        l_size += (sizeof (_t1_t))*(l_table_sizes->wl_t1_count) ;
        secListTableSupport.wl_t2.size = l_table_sizes->wl_t2_count;
        secListTableSupport.wl_t2.mask = WHITELIST_TABLE2_MASK;
        secListTableSupport.wl_t2.table = (_t2_t*)malloc((sizeof(_t2_t))*(l_table_sizes->wl_t2_count));
        memcpy( secListTableSupport.wl_t2.table, l_buf+l_size, (sizeof(_t2_t))*(l_table_sizes->wl_t2_count) );

        // BE to LE conversion of the value
        for (int k = 0; k <  l_table_sizes->wl_t2_count; k++) {
		(secListTableSupport.wl_t2.table + k)->value = be16_to_cpu((beint16_t)((secListTableSupport.wl_t2.table+k)->value));
	}

        // Read and Update whitelist tables3
        l_size += (sizeof (_t2_t))*(l_table_sizes->wl_t2_count) ;
        secListTableSupport.wl_t3.size = l_table_sizes->wl_t3_count;
        secListTableSupport.wl_t3.mask = WHITELIST_TABLE3_MASK;
        secListTableSupport.wl_t3.table = (_t3_t*)malloc((sizeof(_t3_t))*(l_table_sizes->wl_t3_count));
        memcpy( secListTableSupport.wl_t3.table, l_buf+l_size, (sizeof(_t3_t))*(l_table_sizes->wl_t3_count) );

        // BE to LE conversion of the value
        for (int k = 0; k <  l_table_sizes->wl_t3_count; k++) {
		(secListTableSupport.wl_t3.table + k)->value = be16_to_cpu((beint16_t)((secListTableSupport.wl_t3.table+k)->value));
	}

        // Read and Update blacklist tables1
        l_size += (sizeof (_t3_t))*(l_table_sizes->wl_t3_count) ;
        secListTableSupport.bl_t1.size = l_table_sizes->bl_t1_count;
        secListTableSupport.bl_t1.mask = BLACKLIST_TABLE1_MASK;
        secListTableSupport.bl_t1.table = (_t1_t*)malloc((sizeof(_t1_t))*(l_table_sizes->bl_t1_count));
        memcpy( secListTableSupport.bl_t1.table, l_buf+l_size,(sizeof(_t1_t))*(l_table_sizes->bl_t1_count) );

        // Read and Update blacklist tables2
        l_size += (sizeof (_t1_t))*(l_table_sizes->bl_t1_count) ;
        secListTableSupport.bl_t2.size = l_table_sizes->bl_t2_count;
        secListTableSupport.bl_t2.mask = BLACKLIST_TABLE2_MASK;
        secListTableSupport.bl_t2.table = (_t2_t*)malloc((sizeof(_t2_t))*(l_table_sizes->bl_t2_count));
        memcpy( secListTableSupport.bl_t2.table, l_buf+l_size,(sizeof(_t2_t))*(l_table_sizes->bl_t2_count) );

        // BE to LE conversion of the value
        for (int k = 0; k <  l_table_sizes->bl_t2_count; k++) {
		(secListTableSupport.bl_t2.table + k)->value = be16_to_cpu((beint16_t)((secListTableSupport.bl_t2.table+k)->value));
	}


        // Read and Update blacklist tables3
        l_size += (sizeof (_t2_t))*(l_table_sizes->bl_t2_count) ;
        secListTableSupport.bl_t3.size = l_table_sizes->bl_t3_count;
        secListTableSupport.bl_t3.mask = BLACKLIST_TABLE3_MASK;
        secListTableSupport.bl_t3.table = (_t3_t*)malloc((sizeof(_t3_t))*(l_table_sizes->bl_t3_count));
        memcpy( secListTableSupport.bl_t3.table, l_buf+l_size,(sizeof(_t3_t))*(l_table_sizes->bl_t3_count) );

        // BE to LE conversion of the value
        for (int k = 0; k <  l_table_sizes->bl_t3_count; k++) {
		(secListTableSupport.bl_t3.table + k)->value = be16_to_cpu((beint16_t)((secListTableSupport.bl_t3.table+k)->value));
	}

        // Read and Update greylist tables1
        l_size += (sizeof (_t3_t))*(l_table_sizes->bl_t3_count) ;

        secListTableSupport.gl_t1.size = l_table_sizes->gl_t1_count;
        secListTableSupport.gl_t1.mask = GREYLIST_TABLE1_MASK;
        secListTableSupport.gl_t1.table = (_gl_t1_t*)malloc((sizeof(_gl_t1_t))*(l_table_sizes->gl_t1_count));
        memcpy( secListTableSupport.gl_t1.table, l_buf+l_size,(sizeof(_gl_t1_t))*(l_table_sizes->gl_t1_count));

        // BE to LE conversion of the value
        for (int k = 0; k <  l_table_sizes->gl_t1_count; k++) {
		(secListTableSupport.gl_t1.table + k)->key= be32_to_cpu((beint32_t)((secListTableSupport.gl_t1.table+k)->key));
		(secListTableSupport.gl_t1.table + k)->value = be64_to_cpu((beint64_t)((secListTableSupport.gl_t1.table+k)->value));
	}

        isSecurityListInitDone = true;
        ret = true;
    }
    while(0);

#ifdef XSCOM_UV_BWLIST_DEBUG
    printSecurityAccessTables ();
#endif

    // Load the UV Exceptions to the SBEBWList
    UVsecListTableSupport.wl_t1 = wl_table1;
    UVsecListTableSupport.wl_t2 = wl_table2;
    UVsecListTableSupport.wl_t3 = wl_table3;

    UVsecListTableSupport.bl_t1 = bl_table1;
    UVsecListTableSupport.bl_t2 = bl_table2;
    UVsecListTableSupport.bl_t3 = bl_table3;

    UVsecListTableSupport.gl_t1 = gl_table1;

    pr_notice("UVBWLIST Load done \n");
   
#endif
    return ret;
}
