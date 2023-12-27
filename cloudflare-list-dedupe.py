#!/usr/bin/python3

cloudflare_domain_list_raw=open("cloudflare_domain_list.txt").read()
cloudflare_domain_list=[]

# Remove empty lines

for i in cloudflare_domain_list_raw.split('\n'):

    if not i:
        continue

    cloudflare_domain_list.append(i)

# Now for the magic

cloudflare_domain_list=list(dict.fromkeys(cloudflare_domain_list))

open("cloudflare_domain_list.txt","w").write("\n".join(cloudflare_domain_list))