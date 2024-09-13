Just works for detecting Stegpy yet.

To compile the module your self you need to add the module to the _module_list_ file.

Example usage:

```
import "lsb"

rule Stegpy
{
    condition:
        lsb.stegv2 == "true" or lsb.stegv3 == "true"
}
```
