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
import subprocess
import os

os.chdir("/home/falwasmi/linux-kernel")

keyword = input("BUG: ")

if " " in keyword:
    final_file_name =keyword.replace(" ", "_")
else:
    final_file_name = keyword

input_file = "/home/falwasmi/kernel_cves.json"
final_file = "/home/falwasmi/" + final_file_name + ".txt"   
linux_commit = "https://github.com/gregkh/linux/commit/"
count = 0

with open(input_file, "r") as cve_file:
    data = json.load(cve_file)

for cve in data.keys():
    if 'fixes' in data[cve] and 'nvd_text' in data[cve]:
        if data[cve]['fixes'] != "" and data[cve]['nvd_text'] != "":
            hash = data[cve]['fixes']
            description = data[cve]['nvd_text'] 
            if keyword.lower() in description.lower():
                    
                result = subprocess.run(
                ["git", "show", "--stat", hash],
                capture_output=True,
                text=True,
                check=True
                )

                output_lines = result.stdout.strip().splitlines()
                last_two_lines = output_lines[-2:] if len(output_lines) >= 2 else output_lines
        
                        
                line1 = last_two_lines[0].strip()  # ex "fs/jfs/jfs_dmap.c | 3 ++-"
                line2 = last_two_lines[1].strip()  # ex "1 file changed, 2 insertions(+), 1 deletion(-)"
        
                three_or_less = False
                if " 1 " in line1 or " 2 " in line1 or " 3 " in line1:
                    three_or_less = True
        
                one_file_changed = False
                if "1 file changed" in line2:
                    one_file_changed = True


                if three_or_less and one_file_changed:
                    url = linux_commit+hash 
                    format_line = f"{url}.diff\n"
                    with open(final_file, "a") as the_file:
                        print(format_line)
                        the_file.write(format_line)
                        count+=1

print(f"Found {count} {keyword} bug patches")
