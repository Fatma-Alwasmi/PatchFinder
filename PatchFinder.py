#take txt file of cves 
#look for input keyword
#look for all corresponding hash with that keyword
#save them in keyword.txt
#loop through every hash in keyword.txt
    #for each hash:
        #if |deletions| + insertions <= 3:
            #add the cve:hash:description in keywordFinal.txt

import urllib
import requests
import re

################ find cve related to keyword BEGIN ###################
keyword = input("BUG: ")

if " " in keyword:
    final_file_name =keyword.replace(" ", "_")
else:
    final_file_name = keyword

input_file = input("FILE: ")
temp_file = "temp_" + input_file
final_file = final_file_name + "_" + input_file 
with open(input_file, "r") as cve_file:
    for line in cve_file:
        if "CVEs fixed in" in line:
            version = line.strip()
        elif keyword in line:
            with open(temp_file, "a") as the_file:
                format_line = f"{version}{line}"
                the_file.write(format_line)
################ find cve related to keyword END ###################  

hash_pattern = r'CVE-\d{4}-\d{4,5}:\s+([a-f0-9]{40})'
linux_commit = "https://github.com/torvalds/linux/commit/"

with open(temp_file, "r") as the_file: 
    for line in the_file:
        match = re.search(hash_pattern, line)
        if match:
            hash = ''.join(match.group(1)) 
            url = linux_commit+hash
            response = requests.get(url)
            content = response.text
            #check if patch is <= 3 lines of code
            if " 1 change:" in content:
                with open(final_file, "a") as the_file1:
                    print("1 change")
                    the_file1.write(line)

            elif " 2 changes:" in content:
                with open(final_file, "a") as the_file1:
                    print("2 changes")
                    the_file1.write(line)

            elif " 3 changes:" in content:
                with open(final_file, "a") as the_file1:
                    print("3 changes")
                    the_file1.write(line)
            
