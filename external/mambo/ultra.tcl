# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
#
# Derived in part from:
# github.com/open-power/skiboot/external/mambo/skiboot.tcl
#

# need to get images path defined early
source $env(LIB_DIR)/ppc/util.tcl

proc mconfig { name env_name def } {
    global mconf
    global env

    if { [info exists env($env_name)] } { set mconf($name) $env($env_name) }
    if { ![info exists mconf($name)] } { set mconf($name) $def }
}

proc Fmt64 { val } {
    return [format "0x%016X" $val]
}

mconfig cpus CPUS 1
mconfig threads THREADS 1
mconfig memory MEM_SIZE 16G

# Should we stop on an illeagal instruction
mconfig stop_on_ill MAMBO_STOP_ON_ILL false

# Base directory path for images
mconfig img_dir MAMBO_IMG_DIR ""

# Location of application binary to load
mconfig skiboot_image SKIBOOT "./skiboot.lid"

mconfig kernel ULTRA_VMLINUX "./vmlinux"

mconfig ultra_image ULTRA_IMG "./ultra.lid"

# Disk: Location of file to use a bogus disk 0
mconfig rootdisk ROOTDISK none

# TPM Wrapping Directory for key files.
mconfig wrapkey_dir WRAPKEY_DIR none

##
# SMF / Ultra
##

mconfig enable_smf MAMBO_ENABLE_SMF none

puts "enable_smf: $mconf(enable_smf)"

mconfig enable_ultra MAMBO_ENABLE_ULTRA none

mconfig linux_cmdline LINUX_CMDLINE "root=/dev/mtdblock0 rw console=hvc0 powersave=off elevator=noop"

mconfig enable_bogus_net MAMBO_ENABLE_BOGUS_NET none

##
# Addresses
##

# Boot: Memory location to load boot_image, for binary or vmlinux
mconfig skiboot_addr MAMBO_SKIBOOT_LOAD 0x30000000

# Boot: Value of PC after loading, for binary or vmlinux
mconfig skiboot_pc MAMBO_SKIBOOT_PC 0x30000010

# Paylod: Memory location for a Linux style ramdisk/initrd
mconfig kernel_addr VMLINUX_ADDR 0x20000000

# FW: Where should ePAPR Flat Devtree Binary be loaded
mconfig epapr_dt_addr EPAPR_DT_ADDR 0x1f00000;# place at 31M

##
# COW
##

# Disk: File to use for re COW file: none or <file>
mconfig rootdisk_cow MAMBO_ROOTDISK_COW none

# Disk: COW method to use
mconfig rootdisk_cow_method MAMBO_ROOTDISK_COW_METHOD newcow

# Disk: COW hash size
mconfig rootdisk_cow_hash MAMBO_ROOTDISK_COW_HASH 1024

# Increasing the number of hardware threads per processor or the number of
# CPUs in the simulated system will slow down your boot time because the
# underlying simulator is running on only a single thread on the host system

proc config_hook { conf } {
    global mconf

    $conf config cpus $mconf(cpus)
    $conf config processor/number_of_threads $mconf(threads)
    $conf config memory_size $mconf(memory)

    # Stop on attn instructions
    $conf config processor_option/ATTN_STOP true
    $conf config processor_option/stop_on_illegal_instruction $mconf(stop_on_ill)

    # We don't need these when we run with skiboot
    $conf config UART/0/enabled false
    $conf config SimpleUART/enabled false
    $conf config enable_rtas_support false
    $conf config enable_pseries_nvram false

    # We don't need the embedded-style RAM/ROM models
    $conf config machine_option/NO_RAM TRUE
    $conf config machine_option/NO_ROM TRUE

    # Have turbo mode handle mftb instructions
    $conf config turbo/mftb TRUE

    # Use an SMT4-style PIR with 2 bits for thread ID
    $conf config processor/PIR_bits_for_thread 2
    $conf config processor/PIR_bits_for_process or 9

    # set ourselves up to be P9 DD2.0
    if { $mconf(enable_smf) != "none" } {
        $conf config processor/chip_version "DD2.0"
        $conf config processor/initial/PVR 0x004E0200
        $conf config processor/initial/SIM_CTRL1 0x4228100404004000
        $conf config processor/initial/SMFCTRL 0x8000000000000002
    } else {
        $conf config processor/chip_version "DD2.0"
        $conf config processor/initial/PVR 0x004E0200
        $conf config processor/initial/SIM_CTRL1 0x4228100400000000
        $conf config processor/initial/SMFCTRL 0x0000000000000000
    }
}

#simdebug set UP 1

source $env(LIB_DIR)/p9/systemsim.tcl
source $env(RUN_DIR)/p9/p9-devtree-skiboot-mtd.tcl

# Only source mambo_utils.tcl if it exists in the current directory. That
# allows running mambo in another directory to the one skiboot.tcl is in.
if { [file exists mambo_utils.tcl] } then {
        source mambo_utils.tcl

        if { [info exists env(VMLINUX_MAP)] } {
                global linux_symbol_map

                set fp [open $env(VMLINUX_MAP) r]
                set linux_symbol_map [read $fp]
                close $fp
        }

        if { [info exists env(SKIBOOT_MAP)] } {
                global skiboot_symbol_map

                set fp [open $env(SKIBOOT_MAP) r]
                set skiboot_symbol_map [read $fp]
                close $fp
        }
}

source $env(LIB_DIR)/common/epapr.tcl
if {![info exists of::encode_compat]} {
    source $env(LIB_DIR)/common/openfirmware_utils.tcl
}

# Make sure the skiboot can be found, then load
if {[file exists $mconf(skiboot_image)]} {
    puts "Using skiboot from $mconf(skiboot_image)"
    set skiboot_file $mconf(skiboot_image)
} elseif {[file exists $mconf(img_dir)/$mconf(skiboot_image)]} {
    puts "Using skiboot $mconf(skiboot_image) from $mconf(img_dir)"
    set skiboot_file $mconf(img_dir)/$mconf(skiboot_image)
} else {
    puts "ERROR: Could not find skiboot: $mconf(skiboot_image)"
    exit
}

set skiboot_size [file size $skiboot_file]
mysim memory fread $mconf(skiboot_addr) $skiboot_size $skiboot_file

# top half of memory
mconfig spr_urmor ULTRA_URMOR [format "0x%016X" [expr [mysim display memory_size] / 2]]

if {$mconf(enable_ultra) != "none"} {
    set uv_node [ mysim of addchild $root_node "ibm,ultravisor" "" ]
    mysim of addprop $uv_node string "compatible" "ibm,ultravisor"

    set uv_fw_node [ mysim of addchild $uv_node "firmware" "" ]
    mysim of addprop $uv_fw_node string "compatible" "ibm,uv-firmware"
    mysim of addprop $uv_fw_node int "#address-cells" 2
    mysim of addprop $uv_fw_node int "#size-cells" 2

    set reg [list]
    lappend reg $mconf(spr_urmor)
    mysim of addprop $uv_fw_node array64 "reg" reg

    set range [list]
    lappend range $mconf(spr_urmor)
    lappend range [expr  [mysim display memory_size] - $mconf(spr_urmor)]
    mysim of addprop  $uv_fw_node array64 "secure-memory-ranges" range

    # Make sure the ultra can be found, then load
    if {[file exists $mconf(ultra_image)]} {
        puts "Using ultra from $mconf(ultra_image)"
        set ultra_file $mconf(ultra_image)
    } elseif {[file exists ../../$mconf(ultra_image)]} {
        puts "Using ultra $mconf(ultra_image) from build directory"
        set ultra_file ../../$mconf(ultra_image)
    } elseif {[file exists $mconf(img_dir)/$mconf(ultra_image)]} {
        puts "Using ultra $mconf(ultra_image) from $mconf(img_dir)"
        set ultra_file $mconf(img_dir)/$mconf(ultra_image)
    } else {
        puts "ERROR: Could not find ultra: $mconf(ultra_image)"
        exit
    }

    set ultra_size [file size $ultra_file]
    mysim memory fread $mconf(spr_urmor) $ultra_size $ultra_file
}

# Make sure the kernel can be found, then load
if {[file exists $mconf(kernel)]} {
    puts "Using kernel from $mconf(kernel)"
    set kernel_file $mconf(kernel)
} elseif {[file exists $mconf(img_dir)/$mconf(kernel)]} {
    puts "Using kernel $mconf(kernel) from $mconf(img_dir)"
    set kernel_file $mconf(img_dir)/$mconf(kernel)
} else {
    puts "ERROR: Could not find kernel: $mconf(kernel)"
    exit
}

set kernel_size [file size $kernel_file]
mysim memory fread $mconf(kernel_addr) $kernel_size $kernel_file

# Make sure the rootdisk image can be found
if { $mconf(rootdisk) != "none" } {
    if {[file exists $mconf(rootdisk)]} {
        puts "Using disk image from $mconf(rootdisk)"
        set diskimg_file $mconf(rootdisk)
    } elseif {[file exists $mconf(img_dir)/$mconf(rootdisk)]} {
        puts "Using disk image $mconf(rootdisk) in $mconf(img_dir)"
        set diskimg_file $mconf(img_dir)/$mconf(rootdisk)
    } else {
        puts "ERROR: Could not find disk image: $mconf(rootdisk)"
        exit
    }
}

#
# Setup bogus IO

if { $mconf(rootdisk) != "none" } {
    # Now load the bogus disk image
    switch $mconf(rootdisk_cow) {
	none {
	    mysim bogus disk init 0 $diskimg_file rw
	    puts "bogusdisk initialized for $diskimg_file"
	}
	default {
	    mysim bogus disk init 0 $diskimg_file \
		$mconf(rootdisk_cow_method) \
		$mconf(rootdisk_cow) $mconf(rootdisk_cow_hash)
	}
    }
}

# Map persistent memory disks
proc pmem_node_add { root start size } {
    set start_hex [format %x $start]
    set node [mysim of addchild $root "pmem@$start_hex" ""]
    set reg [list [expr $start >> 32] [expr $start & 0xffffffff] [expr $size >> 32] [expr $size & 0xffffffff] ]
    mysim of addprop $node array "reg" reg
    mysim of addprop $node string "compatible" "pmem-region"
    mysim of addprop $node empty "volatile" "1"
    return [expr $start + $size]
}

# Reserve the secure memory region
set reserved_mem_root [mysim of addchild $root_node "reserved-memory" ""]
mysim of addprop $reserved_mem_root int "#address-cells" 2
mysim of addprop $reserved_mem_root int "#size-cells" 2
set secure_mem_node [mysim of addchild $reserved_mem_root "ibm,secure-memory0" ""]
mysim of addprop $secure_mem_node string "name" "ibm,secure-memory0"
set start $mconf(spr_urmor)
set size [expr [mysim display memory_size] - $mconf(spr_urmor)]
set reg [list [expr $start >> 32] [expr $start & 0xfffffff] [expr $size >> 32] [expr $size & 0xffffffff]]
mysim of addprop $secure_mem_node array "reg" reg

# Secure-memory node
set start_hex [format %x $start]
set secure_mem_node [mysim of addchild $root_node "secure-memory@$start_hex" ""]
mysim of addprop $secure_mem_node string "compatible" "ibm,secure-memory"
mysim of addprop $secure_mem_node array "reg" reg
mysim of addprop $secure_mem_node string "device_type" "secure-memory"
set associativity [list 4 0 0 0 0]
mysim of addprop $secure_mem_node "array" "ibm,associativity" associativity


set pmem_files ""
if { [info exists env(PMEM_DISK)] } {
    set pmem_files [split $env(PMEM_DISK) ","]
}
set pmem_sizes ""
if { [info exists env(PMEM_VOLATILE)] } {
    set pmem_sizes [split $env(PMEM_VOLATILE) ","]
}
set pmem_root [mysim of addchild $root_node "pmem" ""]
mysim of addprop $pmem_root int "#address-cells" 2
mysim of addprop $pmem_root int "#size-cells" 2
mysim of addprop $pmem_root empty "ranges" ""
# Start above where XICS normally is at 0x1A0000000000
set pmem_start [expr 0x20000000000]
foreach pmem_file $pmem_files { # PMEM_DISK
    set pmem_file [string trim $pmem_file]
    set pmem_size [file size $pmem_file]
    if {[catch {mysim memory mmap $pmem_start $pmem_size $pmem_file rw}]} {
	puts "ERROR: pmem: 'mysim mmap' command needs newer mambo"
	exit
    }
    set pmem_start [pmem_node_add $pmem_root $pmem_start $pmem_size]
}
foreach pmem_size $pmem_sizes { # PMEM_VOLATILE
    set pmem_start [pmem_node_add $pmem_root $pmem_start $pmem_size]
}

#
# Add files to simulate TPM wrapping keys.
# wrapping-key-policy-a
# wrapping-key-policy-b
# wrapping-key-passwd
# wrapping-key-publicname
# 

proc add_key_prop { k_file node p_name } {
    set key_list [list]
    set f [open $k_file r]

    while {1} {
        set key_byte [read $f 2]
        if {[eof $f]} {
            close $f
            break
        }
        lappend key_list $key_byte
    }

    mysim of addprop $node byte_array $p_name $key_list
}

if { $mconf(wrapkey_dir) != "none" } {
  set tpm_node [ mysim of addchild $root_node "tpm_sim" "" ]
  mysim of addprop $tpm_node string "compatible" "uv,tpm_sim"

  # policy-a.txt
  if {[file exists $mconf(wrapkey_dir)/policy-a.txt]} {
    puts "Using policy-a.txt"
    add_key_prop $mconf(wrapkey_dir)/policy-a.txt $tpm_node "wrapping-key-policy-a"
  } else {
    puts "ERROR: Could not find policy-a.txt in : $mconf(wrapkey_dir)"
    exit
  }
  
  # policy-b.txt
  if {[file exists $mconf(wrapkey_dir)/policy-b.txt]} {
    puts "Using policy-b.txt"
    add_key_prop $mconf(wrapkey_dir)/policy-b.txt $tpm_node "wrapping-key-policy-b"
  } else {
    puts "ERROR: Could not find policy-b.txt in : $mconf(wrapkey_dir)"
    exit
  }
  
  # wrapping-key-passwd
  if {[file exists $mconf(wrapkey_dir)/wrapping-key-passwd.txt]} {
    puts "Using wrapping-key-passwd.txt"
    add_key_prop $mconf(wrapkey_dir)/wrapping-key-passwd.txt $tpm_node "wrapping-key-passwd"
  } else {
    puts "ERROR: Could not find wrapping-key-passwd.txt in : $mconf(wrapkey_dir)"
    exit
  }

  # wrapping-key-publicname
  if {[file exists $mconf(wrapkey_dir)/wrapping-key-publicname.txt]} {
    puts "Using wrapping-key-publicname.txt"
    add_key_prop $mconf(wrapkey_dir)/wrapping-key-publicname.txt $tpm_node "wrapping-key-publicname"
  } else {
    puts "ERROR: Could not find wrapping-key-publicname.txt in : $mconf(wrapkey_dir)"
    exit
  }

  # wrapping-key-handle
  if {[file exists $mconf(wrapkey_dir)/wrapping-key-handle.txt]} {
    puts "Using wrapping-key-handle.txt"
    add_key_prop $mconf(wrapkey_dir)/wrapping-key-handle.txt $tpm_node "wrapping-key-handle"
  } else {
    puts "ERROR: Could not find wrapping-key-handle.txt in : $mconf(wrapkey_dir)"
    exit
  }

}

# Kernel command line args, appended to any from the device tree
# e.g.: of::set_bootargs "xmon"
#
# Can be set from the environment by setting LINUX_CMDLINE.
of::set_bootargs $mconf(linux_cmdline)

# init CPUs
set curr_pir 0
set num_cores [ mysim mcm 0 display number_of_cpus ]
set num_threads_per_core [ expr [ mysim mcm 0 display number_of_threads ] / $num_cores ]
for { set coren 0 } { $coren < $num_cores } { incr coren } {
    set cpu_node [mysim of find_device "/cpus/PowerPC@$curr_pir"] 

    set irqreg [list]
    for { set threadn 0 } { $threadn < $num_threads_per_core} { incr threadn } {
        if {$mconf(enable_ultra) != "none"} {
            mysim mcm 0 cpu $coren thread $threadn set spr msr 0x9000000000400000
        } else {
            mysim mcm 0 cpu $coren thread $threadn set spr msr 0x9000000000000000
	}
        mysim mcm 0 cpu $coren thread $threadn set spr pc $mconf(skiboot_pc)
        mysim mcm 0 cpu $coren thread $threadn set gpr 3 $mconf(epapr_dt_addr)
        mysim mcm 0 cpu $coren thread $threadn config_on
	mysim mcm 0 cpu $coren thread $threadn set spr pir $curr_pir
	lappend irqreg $curr_pir
	incr curr_pir

    }
    mysim of addprop $cpu_node array "ibm,ppc-interrupt-server#s" irqreg
}

if { $mconf(enable_bogus_net) != "none" } {
    mysim bogus net init 0 d0:d0:d0:da:da:da tap0 0 0
}

#
# flatten the device tree
epapr::of2dtb mysim $mconf(epapr_dt_addr)

puts "\nStarting Values:\n"
puts "[Fmt64 [p pvr]],(pvr)"
puts "[Fmt64 [p smfctrl]],(smfctrl)"
puts "[Fmt64 [p r3]],(fdt)"
puts "[Fmt64 [p urmor]],(urmor)"
puts "[Fmt64 [p msr]],(msr)"
puts "[Fmt64 [mysim display memory_size]],(topmem)"
puts "[Fmt64 [p pc]],(pc)"
puts "\n"

# Set run speed
mysim mode fastest

if { [info exists env(ULTRA_AUTORUN)] } {
    mysim go
}
