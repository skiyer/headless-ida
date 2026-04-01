
# run with `headless-ida /path/to/idat /bin/ls list_functions.py`
# or     `headless-ida server:18000 /bin/ls list_functions.py`

import idautils, ida_name

for func in idautils.Functions():
    print(f"{hex(func)} {ida_name.get_ea_name(func)}")
