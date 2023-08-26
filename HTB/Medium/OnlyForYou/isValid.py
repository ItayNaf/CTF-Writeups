import re
import sys

if re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", sys.argv[1]):
    print("Valid email!")
    print(sys.argv[1].split("@", 1)[1])
else:
    print("NonValid email")

