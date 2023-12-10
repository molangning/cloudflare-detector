#!/usr/bin/python3

import json
import time
import socket
import requests
import time
from datetime import datetime
import os
import zipfile
import pandas as pd
import ipaddress
import threading
import queue
import concurrent.futures

print("[+] Cloudflare crawler")

TOP10MILLIONDOMAINSURL="https://www.domcop.com/files/top/top10milliondomains.csv.zip"
CLOUDFLARE_IPV4_SOURCE="https://www.cloudflare.com/ips-v4/"

def request_wrapper(url):

    for i in range(1,4):
        r=requests.get(url)
        if r.status_code==200:
            # print("[+] Got %s successfully!"%(url))
            break
        if i==3:
            print("[!] Failed to get %s."%(url))
            exit(2)
        print("[!] Getting %s failed(%i/3)"%(url,i))

    return r.text

def request_chunked_download_file(url,file):

    for i in range(1,4):
        r=requests.get(url,stream=True)

        if r.status_code==200:

            f=open(file,"wb")

            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
            break

        if i==3:
            print("[!] Failed to get %s."%(url))
            exit(2)

        print("[!] Getting %s failed(%i/3)"%(url,i))

    return

cloudflare_ipv4=request_wrapper(CLOUDFLARE_IPV4_SOURCE).split('\n')
cloudflare_ipv4=list(dict.fromkeys(cloudflare_ipv4))

temp=[]
for ip_range in cloudflare_ipv4:
    temp.append(ipaddress.ip_network(ip_range))

cloudflare_ipv4=temp

print("[+] Got a list of %i IPv4 ranges"%(len(cloudflare_ipv4)))

print("[+] Checking for local copy of Top 10 million domains")
fresh_top10million=True

if os.path.isfile("top10milliondomains.csv"):
    print("[+] top10milliondomains.csv found in local directory")
else:
    print("[!] top10milliondomains.csv not found in local directory!")
    fresh_top10million=False

if os.path.isfile("top10million-last-download-date.txt"):
    date=open("top10million-last-download-date.txt").read()
    last_download_date=datetime.strptime(date, "%Y-%m-%d").date()
    
    if datetime.now().date() > last_download_date:
        print("[!] Local file has expired! Updating now...")
        fresh_top10million=False

if not fresh_top10million:

    print("[+] Downloading a fresh copy of top10milliondomains.csv")
    request_chunked_download_file(TOP10MILLIONDOMAINSURL,"top10milliondomains.csv.zip")
    open("top10million-last-download-date.txt","w").write(datetime.today().strftime('%Y-%m-%d'))
    print("[+] Downloaded a fresh copy of top10milliondomains.csv!")

zipped_file=zipfile.ZipFile('top10milliondomains.csv.zip', 'r')
zipped_file.extract('top10milliondomains.csv', '.')

top10milliondomains_raw=pd.read_csv("top10milliondomains.csv").values.tolist()
top10milliondomains=queue.Queue()

for i in top10milliondomains_raw:
    top10milliondomains.put([i[0],i[1],1])

print("[+] Loaded a list of %i domains from the list"%(top10milliondomains).qsize())

# For those asyncio fanboys, I don't need to use asyncio as a dns request is fast enough
# and threads are easier to implement. If you want, you can open a pull request to change that.

processed_domains=queue.Queue()
accessible_domains=queue.Queue()

def status_check():
    while True:

        if top10milliondomains.empty() and processed_domains.empty():
            return
            
        print("[+] %s domains left to be checked for cloudflare protection."%(top10milliondomains.qsize()))
        time.sleep(5)

def lookup_domain():
    while True:

        if top10milliondomains.empty():
            return

        domain=top10milliondomains.get()

        time.sleep(0.5)

        try:
            domain_ip_address=socket.gethostbyname(domain[1])
        except socket.gaierror:
            print("[!] Failed to resolve %s(%i/3)"%(domain[1],domain[2]))
            
            if domain[2]==3:
                top10milliondomains.task_done()
                continue

            time.sleep(1)
            domain[2]+=1
            top10milliondomains.put(domain)
            top10milliondomains.task_done()

        for cloudflare_range in cloudflare_ipv4:
            if ipaddress.ip_address(domain_ip_address) in cloudflare_range:
                # print("[+] %s in in cloudflare range %s"%(domain[1],cloudflare_range))
                processed_domains.put(domain)
                top10milliondomains.task_done()

def test_domains():
    while True:

        if top10milliondomains.empty() and processed_domains.empty():
            return

        domain=processed_domains.get()
        time.sleep(0.5)

        try:
            res_headers=requests.get("https://%s:443/"%(domain[1]),timeout=15).headers
        except requests.exceptions.Timeout:
            print("[!] Connect to %s timed out!"%(domain[1]))
            processed_domains.task_done()
            continue

        if "Server" not in res_headers.keys():
            processed_domains.task_done()
            continue

        if res_headers["Server"]!="cloudflare":
            processed_domains.task_done()
            continue

        print("[+] %s is reachable by us."%(domain[1]))
        accessible_domains.put([domain[0],domain[1]])
        processed_domains.task_done()

print("[+] Starting dns lookup process")

threading.Thread(target=status_check).start()
dns_check_pool=[]
reachability_check_pool=[]

for i in range(16):
    dns_check_pool.append(threading.Thread(target=lookup_domain))

for i in range(8):
    reachability_check_pool.append(threading.Thread(target=test_domains))

for thread in dns_check_pool:
    thread.start()

for thread in reachability_check_pool:
    thread.start()

while True:

    if top10milliondomains.empty() and processed_domains.empty():
        break

    domain=accessible_domains.get()
    open("accessible_domains.txt","a").write(domain[1]+"\n")

    accessible_domains.task_done()

# print("aaaAAAaAAaAAaAaaAAaa")
