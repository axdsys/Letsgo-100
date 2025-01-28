import socket
from concurrent.futures import ThreadPoolExecutor
import requests
import sys

def animated_banner():
    banner_lines = [
        r"  ______  __    __        ________  ______  __    __  _______  ",
        r" /      |/  \  /  |      /        |/      |/  \  /  |/       \ ",
        r" $$$$$$/ $$  \ $$ |      $$$$$$$$/ $$$$$$/ $$  \ $$ |$$$$$$$  |",
        r"   $$ |  $$$  \$$ |      $$ |__      $$ |  $$$  \$$ |$$ |  $$ |",
        r"   $$ |  $$$$  $$ |      $$    |     $$ |  $$$$  $$ |$$ |  $$ |",
        r"   $$ |  $$ $$ $$ |      $$$$$/      $$ |  $$ $$ $$ |$$ |  $$ |",
        r"  _$$ |_ $$ |$$$$ |      $$ |       _$$ |_ $$ |$$$$ |$$ |__$$ |",
        r" / $$   |$$ | $$$ |      $$ |      / $$   |$$ | $$$ |$$    $$/ ",
        r" $$$$$$/ $$/   $$/       $$/       $$$$$$/ $$/   $$/ $$$$$$$/  ",
        r"                                                              ",
    ]
    bold_blue = "\033[1;34m"  # Bold blue color for text
    bold_red_box = "\033[1;91m"  # Bold red color for the box
    reset_color = "\033[0m"      # Reset color
    box_width = max(len(line) for line in banner_lines) + 4  # Adjust box width

    print(f"{bold_red_box}+{'-' * (box_width - 2)}+{reset_color}")
    for line in banner_lines:
        print(f"{bold_red_box}|{reset_color} {bold_blue}{line.ljust(box_width - 4)}{reset_color} {bold_red_box}|{reset_color}")
    print(f"{bold_red_box}+{'-' * (box_width - 2)}+{reset_color}\n")

def fetch_subdomains(domain):
    url = f"https://crt.sh/json?q={domain}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            subdomains = {entry['name_value'].replace("*.", "") for entry in data}
            return list(subdomains)
    except:
        return []

def scan_port(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((target, port)) == 0:
                return port
    except:
        pass
    return None

def display_loading_bar(current, total, bar_length=40):
    red_bold = "\033[1;31m"
    reset_color = "\033[0m"
    progress = current / total
    bar = f"[{red_bold}{'█' * int(progress * bar_length)}{'-' * (bar_length - int(progress * bar_length))}{reset_color}]"
    sys.stdout.write(f"\r{bar} {current}/{total} subdomains checked")
    sys.stdout.flush()

def main():
    animated_banner()
    yellow_bold = "\033[1;33m"
    reset_color = "\033[0m"
    print(f"{yellow_bold}<-------Welcome to Infind - Find Active Subdomain and Port Scanner------->{reset_color}")
    print(f"{yellow_bold}<-------Author: Arshad (axd)------->{reset_color}\n")

    target = input("Enter the target domain: ").strip()
    subdomains = fetch_subdomains(target)

    if not subdomains:
        print("No subdomains found.")
        return

    print(f"\nFound {len(subdomains)} subdomains. Checking active subdomains...\n")
    active_subdomains = []

    for index, subdomain in enumerate(subdomains, start=1):
        try:
            socket.gethostbyname(subdomain)
            active_subdomains.append(subdomain)
            print(f"\n[ACTIVE] {subdomain}")
        except:
            print(f"\n[INACTIVE] {subdomain}")
        display_loading_bar(index, len(subdomains))

    print("\n\n")
    if not active_subdomains:
        print("No active subdomains found.")
        return

    # Save active subdomains to a file before port scanning
    with open("active_subdomains.txt", "w") as file:
        file.write("\n".join(active_subdomains))

    print("Active subdomains have been saved to active_subdomains.txt.")

    port_results = {}
    start_port = 1
    end_port = 1024

    for subdomain in active_subdomains:
        print(f"\nScanning {subdomain}...")
        open_ports = []

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, subdomain, port) for port in range(start_port, end_port + 1)]
            for future in futures:
                port = future.result()
                if port:
                    open_ports.append(port)

        port_results[subdomain] = open_ports
        if open_ports:
            print(f"Open ports on {subdomain}: {', '.join(map(str, open_ports))}")
        else:
            print(f"No open ports on {subdomain}.")

    print("\nThank you for using Infind.")

if __name__ == "__main__":
    main()
