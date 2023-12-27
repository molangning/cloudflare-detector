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

## Create file .always-fresh-cloudflare-lists for the program to regenerate the domain lists

def silent_remove(path):
    try:
        os.remove(path)

    except FileNotFoundError:
        pass

    except Exception as e:
        print("[!] Unknown exception when trying to remove %s"%(path))

if os.path.isfile(".always-fresh-cloudflare-lists"):

    silent_remove("accessible_cloudflare_domains.txt")
    silent_remove("unaccessible_cloudflare_domains.txt")

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

            print("[+] %s bytes to download"%(r.headers['Content-Length']))

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

def load_top10million():

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

    return top10milliondomains_raw

def load_domains():
    
    if os.path.isfile("cloudflare_domain_list.txt"):

        print("[+] Found a local list of cloudflare domains, using that instead.")
        domains=open("cloudflare_domain_list.txt","r").read().split("\n")

        return domains
        
    else:

        print("[+] Using top10million list as cloudflare_domain_list.txt is not found")

        return load_top10million()

print("[+] Parsing domain list")
domain_list=queue.Queue()
domain_list_raw=load_domains()

print("[+] Loaded a list of %i domains from the domain list"%(len(domain_list_raw)))

for i in domain_list_raw:

    if not i:
        continue

    domain=i[1]

    if domain.count(".")==1:
        domain_list.put("www."+domain)

    domain_list.put(domain)

print("[+] Generated a list of %i domains from the domain list"%(domain_list.qsize()))

# For those asyncio fanboys, I don't need to use asyncio as a dns request is fast enough
# and threads are easier to implement. If you want, you can open a pull request to change that.

processed_domains=queue.Queue()
accessible_cloudflare_domains=queue.Queue()
unaccessible_cloudflare_domains=queue.Queue()

def status_check():
    while True:

        if domain_list.empty() and processed_domains.empty():
            return
            
        print("[+] %s domains left to be checked for cloudflare protection."%(domain_list.qsize()))
        time.sleep(5)

def check_domain():
    while True:
        lookup_domain()

def lookup_domain():
    
    if domain_list.empty():
        return

    domain=domain_list.get()

    for i in range(1,4):
        
        try:
            domain_ip_address=socket.gethostbyname(domain)

            for cloudflare_range in cloudflare_ipv4:

                if ipaddress.ip_address(domain_ip_address) in cloudflare_range:
                    
                    # Uncomment for more verbose log
                    # print("[+] %s in in cloudflare range %s"%(domain,cloudflare_range))

                    processed_domains.put(domain)
                    domain_list.task_done()

            break

        except socket.gaierror as e:
            
            # -2 is unknown name or service
            # -5 is no address associated with hostname

            if e.errno == -5 or e.errno == -2:
                print("[!] %s has no available ip addresses!"%(domain))
                domain_list.task_done()
                break

            elif e.errno == -3:
                print("[!] Temporarily failed to resolve %s (%i/3)"%(domain,i))

                # Exponential back off
                time.sleep(i**2)

            else:
                print("[!] Unhandled error while trying to resolve %s: %s"%(domain,e))
                domain_list.task_done()
                break

        except Exception as e:

            print("[!] Unknown error occurred while trying to resolve %s"%(domain))
            print("[!] Error: %s"%(e))

    time.sleep(0.1)

def test_domains():

    while True:

        if domain_list.empty() and processed_domains.empty():
            return

        domain=processed_domains.get()

        try:
            res_headers=requests.head("https://%s:443/"%(domain),timeout=60).headers

        except requests.exceptions.Timeout:
            print("[!] Connection to %s timed out!"%(domain))

            unaccessible_cloudflare_domains.put(domain)
            processed_domains.task_done()
            continue

        except requests.exceptions.SSLError:

            print("[!] SSL error while trying to connect to %s!"%(domain))

            unaccessible_cloudflare_domains.put(domain)
            processed_domains.task_done()
            continue

        if "Server" not in res_headers.keys():
            # print("[+] Response is missing the Server header!")

            unaccessible_cloudflare_domains.put(domain)
            processed_domains.task_done()
            continue

        if "CF-RAY" not in res_headers.keys():
            # print("[+] Response is missing the CF-RAY header!")

            unaccessible_cloudflare_domains.put(domain)
            processed_domains.task_done()
            continue

        if res_headers["Server"]!="cloudflare":
            # print("[+] Response is not cloudflare!")

            unaccessible_cloudflare_domains.put(domain)
            processed_domains.task_done()
            continue

        print("[+] %s is protected by cloudflare and reachable by us."%(domain))
        accessible_cloudflare_domains.put(domain)
        processed_domains.task_done()

        time.sleep(0.2)

print("[+] Starting dns lookup process")

threading.Thread(target=status_check).start()
dns_check_pool=[]
reachability_check_pool=[]

for i in range(16):
    dns_check_pool.append(threading.Thread(target=check_domain))

for i in range(8):
    reachability_check_pool.append(threading.Thread(target=test_domains))

for thread in dns_check_pool:
    thread.start()

for thread in reachability_check_pool:
    thread.start()

def dump_domains(target_queue, file_name):

    while True:

        if domain_list.empty() and processed_domains.empty() and target_queue.empty():
            break
    
        try:

            domain=target_queue.get(block=False)
            open(file_name,"a").write(domain+"\n")
            target_queue.task_done()
    
        except queue.Empty:

            time.sleep(0.1)


threading.Thread(target=dump_domains, args=[accessible_cloudflare_domains, "accessible_cloudflare_domains.txt"]).start()
threading.Thread(target=dump_domains, args=[unaccessible_cloudflare_domains, "unaccessible_cloudflare_domains.txt"]).start()