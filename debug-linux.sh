#!/usr/bin/bash

git pull
python3 -u cloudflare-crawler.py | tee crawl.log

echo "Archiving files"

cd ..
rm -f cfd.tar.gz
tar -czf cfd.tar.gz cloudflare-detector

echo "Done"