# Cloudflare detector

This is a simple script that downloads the top 10 million most popular website and does a lookup to check if its a part of cloudflare network.

After looking up the domain, the script will then try to connect to port 443 and try to get the document root `/`.

if the connection succeeded, the domain will be written to file

## Special files

Create a file named `/.always-fresh-cloudflare-lists` for the script to automatically delete generated accessible and unaccessible cloudflare domains

Script will always look for a file `cloudflare_domain_list.txt` and loads that to check instead of the top10milliondomains list