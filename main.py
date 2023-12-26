[200~import nmap
  import socket
  from colorama import init, Fore, Style

  init(autoreset=True)

  def reverse_dns_lookup(ip_address):
      try:
          domain_name = socket.gethostbyaddr(ip_address)
          return domain_name[0]
      except socket.herror:
          return "Reverse DNS lookup failed"


  def detect_os(target_ip):
      nm = nmap.PortScanner()
      nm.scan(target_ip, arguments='-O')

      if 'osclass' in nm[target_ip]:
          os_details = nm[target_ip]['osclass'][0]
          return f"{Fore.GREEN}OS Details: {os_details['osfamily']} {os_details['osgen']} ({os_details['accuracy']}%)"
      else:
          return f"{Fore.RED}OS Details not found"


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
      target = input("Enter target to scan (e.g., thennavan.tech): ")

      ip_addresses = socket.getaddrinfo(target, None)
      ipv4_address = [addr[4][0] for addr in ip_addresses if addr[0] == socket.AF_INET][0]
    ipv6_address = [addr[4][0] for addr in ip_addresses if addr[0] == socket.AF_INET6]

        print(f"\n{Fore.MAGENTA}IPv4 Address for {target}: {ipv4_address}")
            if ipv6_address:
                        print(f"IPv6 Addresses for {target}: {', '.join(ipv6_address)}")

                            scan(target)

                                domain_name = reverse_dns_lookup(ipv4_address)
                                    print(f"\n{Fore.GREEN}The associated domain for IP {ipv4_address} is: {domain_name}")

                                        print(detect_os(ipv4_address))

