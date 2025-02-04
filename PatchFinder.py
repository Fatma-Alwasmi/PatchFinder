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
import os

################ find cve related to keyword BEGIN ###################
keyword = input("BUG: ")

if " " in keyword:
    final_file_name =keyword.replace(" ", "_")
else:
    final_file_name = keyword

input_file = "kernel_cves.json"
final_file = final_file_name + ".txt"   
linux_commit = "https://github.com/torvalds/linux/commit/"


with open(input_file, "r") as cve_file:
    data = json.load(cve_file)

for cve in data.keys():
    if 'fixes' in data[cve] and 'nvd_text' in data[cve]:
        if data[cve]['fixes'] != "" and data[cve]['nvd_text'] != "":
            hash = data[cve]['fixes']
            description = data[cve]['nvd_text'] 
            if keyword in description:
                url = linux_commit+hash
                response = requests.get(url)
                content = response.text
                #check if patch is <= 3 lines of code
                if " 1 change:" in content:
                    format_line = f"{cve}:{url}\n"
                    with open(final_file, "a") as the_file:
                        print("1 change")
                        the_file.write(format_line)

                elif " 2 changes:" in content:
                    format_line = f"{cve}:{url}\n"
                    with open(final_file, "a") as the_file:
                        print("2 changes")
                        the_file.write(format_line)

                elif " 3 changes:" in content:
                    format_line = f"{cve}:{url}\n"
                    with open(final_file, "a") as the_file:
                        print("3 changes")
                        the_file.write(format_line)
            
