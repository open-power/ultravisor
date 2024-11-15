

"IBM Legacy Public Repository Disclosure: All content in this repository including code has been provided by IBM under the associated open source software license and IBM is under no obligation to provide enhancements, updates, or support. IBM developers produced this code as an open source project (not as an IBM product), and IBM makes no assertions as to the level of quality nor security, and will not be maintaining this code going forward."


# Ultravisor 

Firmware for OpenPower systems.

Source: https://github.com/open-power/ultravisor

Mailing list: linuxppc-uv@lists.ozlabs.org

Info/subscribe: https://lists.ozlabs.org/listinfo/linuxppc-uv

## Building

Any host OS can build and test Ultravisor provided it has a C cross compiler
for *big endian* powerpc64. 

(The little-endian powerpc64le compilers in Ubuntu and Fedora are actually
bi-endian and can compile Ultravisor even though it's big-endian. We recommend
installing a little-endian toolchain if you plan on building other projects.)


### Define CROSS environment variable if needed

```
export CROSS=powerpc64le-linux-gnu-
```

### Make ultra.lid

```
$ make
```

## Hacking

Ultravisor follows the Linux kernel coding style. Ultravisor source tree
contains a `.clang-format` file based on the Linux kernel provided one.

    * (coding-style)[https://www.kernel.org/doc/html/latest/process/coding-style.html]

    * (clang-format)[https://www.kernel.org/doc/html/latest/process/clang-format.html]

## License

See LICENSE

