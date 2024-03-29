#!/usr/bin/python3

import shutil
import time
import socket
import requests
from datetime import datetime
import os
import zipfile
import ipaddress
import threading
import queue
import random
import csv

## Create file .always-fresh-cloudflare-lists for the program to regenerate the domain lists

if os.path.isfile(".always-fresh-cloudflare-lists"):

    shutil.rmtree("lists/",ignore_errors=True)

if not os.path.isdir("lists/"): 

    os.mkdir("lists/") 

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

def parse_csv(file):

    contents=csv.DictReader(open(file))
    csv_data={}

    for i in contents.fieldnames:
        csv_data[i]=[]

    for row in contents:
        for key, value in row.items():

            csv_data[key].append(value)

    return csv_data

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

    top10milliondomains_raw=parse_csv("top10milliondomains.csv")["Domain"]
    top10milliondomains_mutated=[]

    for domain in top10milliondomains_raw:

        if domain.count(".")==1:
            top10milliondomains_mutated.append("www."+domain)

        top10milliondomains_mutated.append(domain)

    print("[+] Generated a list of %i domains from the top10million list"%(len(top10milliondomains_mutated)))

    return top10milliondomains_mutated


is_using_cloudflare_list=False
domain_list_raw=[]
    
if os.path.isfile("cloudflare_domain_list.txt"):

    is_using_cloudflare_list=True

    print("[+] Found a local list of cloudflare domains, using that instead.")
    domains_raw=open("cloudflare_domain_list.txt","r").read()
    
    for i in domains_raw.split("\n"):

        if not i:
            continue

        domain_list_raw.append(i)

    print("[+] Got a list of %i domains from the domain list"%(len(domain_list_raw)))
    
else:

    print("[+] Using top10million list as cloudflare_domain_list.txt is not found")

    domain_list_raw=load_top10million()

print("[+] Parsing domain list")

domain_list=queue.Queue()

for domain in domain_list_raw:

    domain_list.put(domain)

print("[+] Queued %i domains from the domain list"%(domain_list.qsize()))

# For those asyncio fanboys, I don't need to use asyncio as a dns request is fast enough
# and threads are easier to implement. If you want, you can open a pull request to change that.

processed_domains=queue.Queue()
resolved_failed_domains=queue.Queue()
not_cloudflare_protected_domains=queue.Queue()
ssl_failed_domains=queue.Queue()
connection_failed_domains=queue.Queue()
unknown_fail_check_domains=queue.Queue()
cloudflare_protected_domains=queue.Queue()
unaccessible_domains=queue.Queue()
accessible_cloudflare_protected_domains=queue.Queue()
unaccessible_cloudflare_protected_domains=queue.Queue()

def status_check():

    last_leftover_domains=domain_list.qsize()
    delay=5

    while True:

        if domain_list.empty() and processed_domains.empty():
            print("[+] Domain list and cloudflare protected list have been exhausted")
            return
            
        print("[+] %s domains left to be resolved, %s domains left to check for cloudflare, resolved %i domains in the last %i seconds"%(domain_list.qsize(), processed_domains.qsize(), last_leftover_domains - domain_list.qsize(), delay))
        last_leftover_domains=domain_list.qsize()

        time.sleep(delay)

def check_domain():

    while True:

        if domain_list.empty():
            return

        # Queue may not be empty when we check, but may be empty when we try to retrieve values

        try:
            domain=domain_list.get(block=False)
            lookup_domain(domain)
            domain_list.task_done()
    
        except queue.Empty:
            pass

def optional_log_all_error(target_queue, domain):
    if is_using_cloudflare_list:
        target_queue.put(domain)

def lookup_domain(domain):
    
    for i in range(1,8):
        
        try:
            domain_ip_address=socket.gethostbyname(domain)

            for cloudflare_range in cloudflare_ipv4:

                if ipaddress.ip_address(domain_ip_address) in cloudflare_range:
                    
                    # Uncomment for more verbose log
                    # print("[+] %s in in cloudflare range %s"%(domain,cloudflare_range))

                    cloudflare_protected_domains.put(domain)
                    processed_domains.put(domain)

                    time.sleep(random.uniform(0.1, 0.2))
                    return

            optional_log_all_error(not_cloudflare_protected_domains,domain)
            return

        except socket.gaierror as e:
            
            # -2 is unknown name or service
            # -5 is no address associated with hostname

            if e.errno == -5 or e.errno == -2:
                print("[!] %s has no available ip addresses!"%(domain))
                break

            elif e.errno == -3:
                print("[!] Temporarily failed to resolve %s (%i/7)"%(domain,i))

                # Exponential back off
                time.sleep((i ** 1.5) + random.uniform(1,5))

            else:
                print("[!] Unhandled error while trying to resolve %s: %s"%(domain,e))
                break

        except Exception as e:
            print("[!] Unknown error occurred while trying to resolve %s"%(domain))
            print("[!] Error: %s"%(e))
            break

    optional_log_all_error(resolved_failed_domains, domain)

def test_domains():

    while True:

        try:
            domain=processed_domains.get(block=False)
            tcping_domains(domain)
            print(domain)
            processed_domains.task_done()
    
        except queue.Empty:
            pass

def tcping_domains(domain):

    for i in range(1,8):

        try:
            res_headers=requests.head("https://%s:443/"%(domain),timeout=60).headers

            if "Server" not in res_headers.keys():
                print("[+] Response from %s is missing the Server header!"%(domain))
                optional_log_all_error(not_cloudflare_protected_domains,domain)
                return

            elif "CF-RAY" not in res_headers.keys():
                print("[+] Response from %s is missing the CF-RAY header!"%(domain))
                optional_log_all_error(not_cloudflare_protected_domains,domain)
                return

            elif res_headers["Server"]!="cloudflare":
                print("[+] Response from %s is not cloudflare!"%(domain))
                optional_log_all_error(not_cloudflare_protected_domains,domain)
                return

            # print("[+] %s is protected by cloudflare and reachable by us."%(domain))
            accessible_cloudflare_protected_domains.put(domain)
            time.sleep(random.uniform(0.1, 0.2))
            return

        except requests.exceptions.Timeout:
            print("[!] Connection to %s timed out! (%i/7)"%(domain, i))
            time.sleep(i ** 1.5)

        except requests.exceptions.SSLError:
            print("[!] SSL error while trying to connect to %s!"%(domain))
            optional_log_all_error(ssl_failed_domains,domain)
            break

        except requests.exceptions.ConnectionError:
            print("[!] Error with connection while trying to connect to %s! (%i/7)"%(domain, i))
            time.sleep((i ** 1.5) + random.uniform(1,5))

        except Exception as e:
            print("[!] Unhandled error: %s"%(e))
            optional_log_all_error(unknown_fail_check_domains, domain)
            return

    unaccessible_cloudflare_protected_domains.put(connection_failed_domains,domain)
    return

print("[+] Starting dns lookup process")

threading.Thread(target=status_check).start()
dns_check_pool=[]
reachability_check_pool=[]

for i in range(64):
    dns_check_pool.append(threading.Thread(target=check_domain))

for i in range(32):
    reachability_check_pool.append(threading.Thread(target=test_domains, daemon=True))

for thread in dns_check_pool:
    thread.start()

for thread in reachability_check_pool:
    thread.start()

def dump_domains(target_queue, file_name):

    while True:
    
        try:
            domain=target_queue.get(block=False)
            open(file_name,"a").write(domain+"\n")
            target_queue.task_done()
    
        except queue.Empty:
            time.sleep(0.1)

dump_domains_pool=[]

resolved_failed_domains=queue.Queue()
not_cloudflare_protected_domains=queue.Queue()
ssl_failed_domains=queue.Queue()
connection_failed_domains=queue.Queue()
unknown_fail_check_domains=queue.Queue()

target_dump=[
    [cloudflare_protected_domains, "lists/cloudflare_protected_domains.txt"],
    [unaccessible_domains, "lists/unaccessible_domains.txt"],
    [accessible_cloudflare_protected_domains, "lists/accessible_cloudflare_protected_domains.txt"],
    [unaccessible_cloudflare_protected_domains, "lists/unaccessible_cloudflare_protected_domains.txt"],
    [unknown_fail_check_domains, "lists/unknown_failures_while_checking_domains.txt"],
    [connection_failed_domains,"lists/connection_failed_domains.txt"],
    [ssl_failed_domains,"lists/ssl_failed_while_connecting_domains.txt"],
    [not_cloudflare_protected_domains,"lists/not_cloudflare_protected_domains.txt"],
    [resolved_failed_domains,"lists/resolving_failed_domains.txt"]
]

for i in target_dump:
    dump_domains_pool.append(threading.Thread(target=dump_domains, args=i, daemon=True))

for thread in dump_domains_pool:
    thread.start()

for thread in dns_check_pool:
    thread.join()

domain_list.join()

print("[+] Domain list queue drained")

processed_domains.join()

print("[+] Processed domains queue drained")

for target_queue in target_dump:
    target_queue[0].join()

print("[+] Finished checks")