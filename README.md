# Cloudflare detector

This is a simple script that downloads the top 10 million most popular website and does a lookup to check if its a part of cloudflare network.

After looking up the domain, the script will then try to connect to port 443 and try to get the document root `/`.

if the connection succeeded, the domain will be written to file

## TOFIX

script errors out sometimes with `Temporary failure in name resolution`