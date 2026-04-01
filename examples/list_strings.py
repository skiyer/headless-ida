
# run with `headless-ida /path/to/idat /bin/ls list_strings.py`
# or     `headless-ida server:18000 /bin/ls list_strings.py`

import idautils

for s in idautils.Strings():
    print(f"{hex(s.ea)} {s.length:4d} {str(s)}")
