import nmap
import requests
import pyfiglet

def scan_network(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sP')
    scan_results = {}
    for host in nm.all_hosts():
        host_info = {
            'hostname': nm[host].hostname(),
            'state': nm[host].state(),
            'open_ports': []
        }
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                host_info['open_ports'].append(port)
        scan_results[host] = host_info
    return scan_results

def get_http_headers(url):
    try:
        response = requests.get(url)
        return response.headers
    except requests.RequestException as e:
        return str(e)

def main():
    print(pyfiglet.figlet_format("LexasZ", font="slant"))
    
    ip_range = input("Lütfen taranacak IP aralığını girin (örneğin, 192.168.1.0/24): ")
    url = input("HTTP başlık bilgilerini almak için bir URL girin (opsiyonel): ")

    print("Ağ taraması yapılıyor...")
    scan_results = scan_network(ip_range)
    
    for host, info in scan_results.items():
        print(f"Host: {host}")
        print(f"Hostname: {info['hostname']}")
        print(f"State: {info['state']}")
        print(f"Açık Portlar: {', '.join(map(str, info['open_ports']))}")
        print("-" * 40)
    
    if url:
        print(f"{url} için HTTP başlık bilgileri alınıyor...")
        headers = get_http_headers(url)
        for header, value in headers.items():
            print(f"{header}: {value}")

if __name__ == "__main__":
    main()
