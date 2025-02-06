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
import json

keyword = input("BUG: ")

if " " in keyword:
    final_file_name =keyword.replace(" ", "_")
else:
    final_file_name = keyword

input_file = "kernel_cves.json"
final_file = final_file_name + ".txt"   
linux_commit = "https://github.com/torvalds/linux/commit/"
count = 0

with open(input_file, "r") as cve_file:
    data = json.load(cve_file)

for cve in data.keys():
    if 'fixes' in data[cve] and 'nvd_text' in data[cve]:
        if data[cve]['fixes'] != "" and data[cve]['nvd_text'] != "":
            hash = data[cve]['fixes']
            description = data[cve]['nvd_text'] 
            if keyword.lower() in description.lower():
                url = linux_commit+hash
                if requests.get(url).status_code == 200:
                    response = requests.get(url)
                    content = response.text
                    #check if patch is <= 3 lines of code
                    #modify to check if one file changed only '>1 changed file'
                    if (" 1 change:" in content or " 2 changes:" in content or " 3 changes:" in content) and ">1 changed file" in content:
                        format_line = f"{cve}:{url}\n"
                        with open(final_file, "a") as the_file:
                            print(format_line)
                            the_file.write(format_line)
                            count+=1

print(f"Found {count} {keyword} bug patches")
