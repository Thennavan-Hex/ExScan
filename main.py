import nmap
import socket
import requests
from colorama import init, Fore, Style
import pyfiglet

init(autoreset=True)

def banner():
    return pyfiglet.figlet_format("ExScan", font="standard")

def reverse_dns_lookup(ip_address):
    try:
        domain_name = socket.gethostbyaddr(ip_address)
        return domain_name[0]
    except socket.herror:
        return "Reverse DNS lookup failed"

def detect_os(target_ip):
    nm = nmap.PortScanner()
    result = nm.scan(target_ip, arguments='-O')

    if target_ip in result['scan']:
        if 'osclass' in result['scan'][target_ip]:
            os_details = result['scan'][target_ip]['osclass'][0]
            return f"{Fore.GREEN}OS Details: {os_details['osfamily']} {os_details['osgen']} ({os_details['accuracy']}%)"
        else:
            return f"{Fore.RED}OS Details not found"
    else:
        return f"{Fore.RED}No information available for the target IP: {target_ip}"


def fetch_subdomains(domain):
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                subdomain = entry['name_value'].split('\n')
                for sub in subdomain:
                    subdomains.add(sub)
        else:
            print(f"{Fore.RED}Failed to fetch subdomains. Status Code: {response.status_code}")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {e}")

    return subdomains

def scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV')

    for host in nm.all_hosts():
        print(f"{Fore.BLUE}Nmap scan report for {host}")
        print(f"{Fore.YELLOW}Host is up ({nm[host].hostname()})")
        print(f"{Style.RESET_ALL}-----------")
        print(f"{Fore.CYAN}Protocol: tcp")
        print(f"PORT     STATE     SERVICE     VERSION")

        ports = nm[host]['tcp'].keys()
        sorted_ports = sorted(ports)

        for port in sorted_ports:
            state = nm[host]['tcp'][port]['state']
            service = nm[host]['tcp'][port]['name']
            version = nm[host]['tcp'][port].get('product', 'Unknown Version')
            print(f"{port}/tcp   {state}      {service}     {version}")

if __name__ == "__main__":
    print(banner())

    try:
        target = input("Enter target to scan (e.g., example.com): ")

        ip_addresses = socket.getaddrinfo(target, None)
        ipv4_address = [addr[4][0] for addr in ip_addresses if addr[0] == socket.AF_INET][0]

        print(f"\n{Fore.MAGENTA}IPv4 Address for {target}: {ipv4_address}")

        scan(target)

        domain_name = reverse_dns_lookup(ipv4_address)
        print(f"\n{Fore.GREEN}The associated domain for IP {ipv4_address} is: {domain_name}")

        print(detect_os(ipv4_address))
        
        subdomains = fetch_subdomains(target)
        if subdomains:
            print(f"\n{Fore.GREEN}Subdomains for {target}:")
            for subdomain in subdomains:
                print(subdomain)
        else:
            print(f"\n{Fore.RED}No subdomains found for {target}.")

    except KeyboardInterrupt:
        print(f"\n{Fore.RED}User interrupted the scanning process. Exiting...")
