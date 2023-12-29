# Cloudflare detector

This is a simple script that downloads the top 10 million most popular website and does a lookup to check if its a part of cloudflare network. Results will be written to `cloudflare_protected_domains.txt`

After looking up the domain, the script will then try to connect to port 443 and make a HEAD request

If the server replies with headers found in cloudflare protected sites, the domain will be written to `accessible_cloudflare_protected_domains.txt`

If the domain resolves to a ip address on cloudflare's network but the connection fails for some reason, the domain will be written to `unaccessible_cloudflare_protected_domains.txt`

## Why this project?

Cloudflare is a useful service to hide behind as ip blocks generally don't apply to Cloudflare. To bypass firewall solutions (like the GFW) you will need to know which domains are blocked and which aren't.

## Special files

Create a file named `.always-fresh-cloudflare-lists` for the script to automatically delete generated accessible and unaccessible cloudflare domains

Script will always look for a file `cloudflare_domain_list.txt` and loads that to check instead of the top10milliondomains list