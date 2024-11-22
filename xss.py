import requests
import random
import logging
import os
import sys
from urllib.parse import urlparse, parse_qs, urlencode
from argparse import ArgumentParser, FileType
from queue import Queue
from threading import Thread, Lock
from time import sleep, time
from requests.exceptions import RequestException
from colorama import Fore, Style, init

# Initialize colorama and logging
init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(message)s')

# Constants
MAX_RETRIES = 3
HARDCODED_EXTENSIONS = [
    ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".svg", ".json",
    ".css", ".js", ".webp", ".woff", ".woff2", ".eot", ".ttf", ".otf", ".mp4", ".txt"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/603.3.8 Safari/603.3.8",
]

# Globals for multithreading
subdomain = []
processed_count = 0
lock = Lock()

# Utility Functions
def fetch_url_content(url, proxy=None):
    session = requests.Session()
    proxies = {'http': proxy, 'https': proxy} if proxy else None

    for attempt in range(1, MAX_RETRIES + 1):
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        try:
            response = session.get(url, headers=headers, proxies=proxies, timeout=10)
            response.raise_for_status()
            return response
        except RequestException as e:
            logging.warning(f"Attempt {attempt}/{MAX_RETRIES} failed: {e}. Retrying...")
            sleep(3)  # Ensure this is the correct time.sleep
    logging.error(f"Failed to fetch URL {url} after {MAX_RETRIES} attempts.")
    return None

def has_extension(url, extensions=HARDCODED_EXTENSIONS):
    extension = os.path.splitext(urlparse(url).path)[1].lower()
    return extension in extensions

def clean_url(url):
    parsed_url = urlparse(url)
    if (parsed_url.port == 80 and parsed_url.scheme == "http") or (parsed_url.port == 443 and parsed_url.scheme == "https"):
        parsed_url = parsed_url._replace(netloc=parsed_url.netloc.rsplit(":", 1)[0])
    return parsed_url.geturl()

def clean_urls(urls, extensions, placeholder):
    cleaned_urls = set()
    for url in urls:
        if has_extension(url, extensions):
            continue
        cleaned_url = clean_url(url)
        parsed_url = urlparse(cleaned_url)
        query_params = parse_qs(parsed_url.query)
        cleaned_params = {key: placeholder for key in query_params}
        cleaned_query = urlencode(cleaned_params, doseq=True)
        final_url = parsed_url._replace(query=cleaned_query).geturl()
        cleaned_urls.add(final_url)
    return list(cleaned_urls)

def fetch_and_clean_urls(domain, extensions, stream_output, proxy, placeholder):
    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Fetching URLs for {Fore.CYAN + domain + Style.RESET_ALL}")
    wayback_uri = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&collapse=urlkey&fl=original&page=/"
    response = fetch_url_content(wayback_uri, proxy)
    if not response:
        return []
    urls = response.text.split()

    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Found {Fore.GREEN + str(len(urls)) + Style.RESET_ALL} URLs.")
    cleaned_urls = clean_urls(urls, extensions, placeholder)
    logging.info(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Cleaned URLs: {Fore.GREEN + str(len(cleaned_urls)) + Style.RESET_ALL}")

    if stream_output:
        for url in cleaned_urls:
            print(url)
    return cleaned_urls

def scan_xss_worker(queue, output_file):
    global processed_count
    while not queue.empty():
        url = queue.get()
        try:
            response = requests.get(url, timeout=10)
            if "xss<>" in response.text:
                print(f"{Fore.RED}[Vulnerable]    {Style.RESET_ALL}{url}")
                with lock:
                    if url not in subdomain:
                        subdomain.append(url)
                        if output_file:
                            output_file.write(url + "\n")
            else:
                print(f"{Fore.GREEN}[Not Vulnerable] {Style.RESET_ALL}{url}")
        except RequestException as e:
            logging.error(f"Error scanning {url}: {e}")
        finally:
            with lock:
                processed_count += 1
                print_progress(processed_count, queue.qsize() + processed_count)
            queue.task_done()

def scan_xss(urls, output_file, threads=10):
    global processed_count
    processed_count = 0

    param_urls = [url for url in urls if urlparse(url).query]
    if not param_urls:
        print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} No URLs with parameters to scan.")
        return

    queue = Queue()
    for url in param_urls:
        queue.put(url)

    print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Starting scan on {len(param_urls)} URLs with query parameters...")

    threads_list = []
    for _ in range(min(threads, len(param_urls))):
        t = Thread(target=scan_xss_worker, args=(queue, output_file))
        t.daemon = True
        t.start()
        threads_list.append(t)

    queue.join()
    for t in threads_list:
        t.join()

    print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Scanning complete. Processed {len(param_urls)} URLs.")

def print_progress(processed, total):
    percentage = (processed / total) * 100
    spinner = ['|', '/', '-', '\\']
    sys.stdout.write(f"\rProgress: {percentage:.2f}% {spinner[int(processed) % 4]} ")
    sys.stdout.flush()

def main():
    parser = ArgumentParser(description="Mine URLs and test for vulnerabilities.")
    parser.add_argument("-d", "--domain", help="Domain name to fetch related URLs for.")
    parser.add_argument("-l", "--list", help="File containing a list of domain names.")
    parser.add_argument("-s", "--stream", action="store_true", help="Stream URLs on the terminal.")
    parser.add_argument("--proxy", help="Proxy address for web requests.", default=None)
    parser.add_argument("-p", "--placeholder", help="Placeholder for parameter values", default="xss<>")
    parser.add_argument("-o", "--output", help="Directory to save vulnerable URLs.", default="xss")
    args = parser.parse_args()

    domains = []
    if args.domain:
        domains = [args.domain]
    elif args.list:
        with open(args.list, "r") as f:
            domains = [line.strip().lower() for line in f if line.strip()]

    if not domains:
        parser.error("Please provide either the -d option or the -l option.")

    os.makedirs(args.output, exist_ok=True)

    for domain in domains:
        output_file_path = os.path.join(args.output, f"{domain}.txt")
        with open(output_file_path, "w") as output_file:
            urls = fetch_and_clean_urls(domain, HARDCODED_EXTENSIONS, args.stream, args.proxy, args.placeholder)
            if urls:
                scan_xss(urls, output_file, threads=10)

    if subdomain:
        print("\nVulnerable URL(s) found:")
        for url in subdomain:
            print(url)
    else:
        print("\nNo vulnerable URLs found.")

if __name__ == "__main__":
    start_time = time()
    main()
    end_time = time()
    print(f"\nTime elapsed: {round(end_time - start_time, 2)} seconds")
