
# Save the current database as a packed .i64 file.
#
# run with `headless-ida /path/to/idat /bin/ls save_idb.py`
# or     `headless-ida server:18000 /bin/ls save_idb.py`
#
# Or simply use the -o flag:
#   headless-ida /path/to/idat /bin/ls -o /tmp/ls.i64

import ida_loader

ida_loader.save_database("/tmp/saved.i64", 0)
print("Saved to /tmp/saved.i64")
