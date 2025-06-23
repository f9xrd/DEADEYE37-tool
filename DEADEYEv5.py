import socket
import requests
import whois
import webbrowser
import instaloader
import shodan
from colorama import Fore, Style, init
from getpass import getpass

init(autoreset=True)

def banner():
    lines = [
        "██████╗ ███████╗ █████╗ ██████╗ ███████╗██╗   ██╗███████╗              ██████╗ ███████╗",
        "██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝              ╚════██╗╚════██║",
        "██║  ██║█████╗  ███████║██║  ██║█████╗   ╚████╔╝ █████╗      █████╗     █████╔╝    ██╔╝",
        "██║  ██║██╔══╝  ██╔══██║██║  ██║██╔══╝    ╚██╔╝  ██╔══╝      ╚════╝     ╚═══██╗   ██╔╝ ",
        "██████╔╝███████╗██║  ██║██████╔╝███████╗   ██║   ███████╗              ██████╔╝   ██║  ",
        "╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝   ╚═╝   ╚══════╝              ╚═════╝    ╚═╝  "
    ]
    width = 80
    print()
    for line in lines:
        print(Fore.LIGHTRED_EX + line.center(width) + Style.RESET_ALL)
    print()

def menu():
    print(Fore.LIGHTRED_EX + "Select an option from the menu below:\n")
    print(Fore.LIGHTRED_EX + """
[1] Whois Lookup
[2] DNS Lookup
[3] IP Geolocation
[4] Website Screenshot
[5] Instagram Info
[6] Pastebin Search
[7] Real IP Bypass (Cloudflare)
[8] VirusTotal IP Scan
[9] Shodan Search
[10] Google Dork Search
[11] Explain Tool Options
[12] About Me
[0] Exit
""" + Style.RESET_ALL)

def explain_options():
    explanation = f"""
{Fore.LIGHTBLUE_EX}Tool Options Explanation:

1) Whois Lookup:
   Retrieves domain registration details such as registrar, creation and expiry dates, contact info, etc.

2) DNS Lookup:
   Finds the IP addresses linked to a given domain name.

3) IP Geolocation:
   Provides the geographical location (country, city, ISP) of an IP address.

4) Website Screenshot:
   Opens a live screenshot preview of the given website in your default browser.

5) Instagram Info:
   Allows you to log in with your Instagram account and extract public information from a target username such as full name, bio, followers count, and more.

6) Pastebin Search:
   Opens a web search on Pastebin.com to find pastes containing a specific keyword.

7) Real IP Bypass (Cloudflare):
   Attempts to find the real IP address of a website protected by Cloudflare by querying DNS records.

8) VirusTotal IP Scan:
   Retrieves scan reports for a given IP from VirusTotal, showing if the IP is malicious or suspicious.

9) Shodan Search:
   Uses the Shodan API to search for internet-connected devices based on a query.

10) Google Dork Search:
    Opens a Google search using advanced operators (dorks) to find sensitive or hidden information.

11) Explain Tool Options:
    Displays this detailed explanation of all available tool options.

12) About Me:
    Shows information about the programmer: name, Instagram, Telegram, GitHub links.

"""
    print(explanation)

def about_me():
    info = f"""
{Fore.LIGHTBLUE_EX}About Me:

Name: shadow - 37
Instagram: 7.o_6z
Telegram: https://t.me/f9xrd 
GitHub: https://github.com/f9xrd
"""
    print(info)

def whois_lookup():
    domain = input(Fore.LIGHTBLUE_EX + "Enter domain (e.g. example.com): ").strip()
    try:
        w = whois.whois(domain)
        print(Fore.LIGHTBLUE_EX + f"\nWHOIS Data for {domain}:\n")
        for key, value in w.items():
            print(f"{key}: {value}")
    except Exception as e:
        print(Fore.LIGHTBLUE_EX + f"Error: {e}")

def dns_lookup():
    domain = input(Fore.LIGHTBLUE_EX + "Enter domain (e.g. example.com): ").strip()
    try:
        ips = socket.gethostbyname_ex(domain)[2]
        print(Fore.LIGHTBLUE_EX + f"\nIP addresses for {domain}:")
        for ip in ips:
            print(f" - {ip}")
    except Exception as e:
        print(Fore.LIGHTBLUE_EX + f"Error: {e}")

def ip_geolocation():
    ip = input(Fore.LIGHTBLUE_EX + "Enter IP address: ").strip()
    url = f"http://ip-api.com/json/{ip}"
    try:
        res = requests.get(url, timeout=10).json()
        if res['status'] == 'success':
            print(Fore.LIGHTBLUE_EX + f"\nLocation info for {ip}:\n")
            for k, v in res.items():
                print(f"{k}: {v}")
        else:
            print(Fore.LIGHTBLUE_EX + f"Failed: {res.get('message')}")
    except Exception as e:
        print(Fore.LIGHTBLUE_EX + f"Error: {e}")

def website_screenshot():
    url = input(Fore.LIGHTBLUE_EX + "Enter full URL (https://...): ").strip()
    api_key = "YOUR_API_KEY"
    shot_url = f"https://api.screenshotmachine.com?key={api_key}&url={url}&dimension=1024x768"
    print(Fore.LIGHTBLUE_EX + "Opening screenshot in browser...")
    try:
        webbrowser.open(shot_url)
    except Exception as e:
        print(Fore.LIGHTBLUE_EX + f"Error: {e}")

def pastebin_search():
    keyword = input(Fore.LIGHTBLUE_EX + "Enter keyword to search in Pastebin: ").strip()
    url = f"https://pastebin.com/search?q={keyword.replace(' ', '+')}"
    print(Fore.LIGHTBLUE_EX + f"Opening Pastebin search for '{keyword}'...")
    webbrowser.open(url)

def real_ip_bypass():
    domain = input(Fore.LIGHTBLUE_EX + "Enter domain to find real IP: ").strip()
    try:
        url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            print(Fore.LIGHTBLUE_EX + f"DNS Lookup result for {domain}:\n")
            print(res.text)
        else:
            print(Fore.LIGHTBLUE_EX + "Failed to get data from service.")
    except Exception as e:
        print(Fore.LIGHTBLUE_EX + f"Error: {e}")

def virustotal_ip_scan():
    api_key = "YOUR_VIRUSTOTAL_API_KEY"
    ip = input(Fore.LIGHTBLUE_EX + "Enter IP to scan on VirusTotal: ").strip()
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            print(Fore.LIGHTBLUE_EX + f"VirusTotal Report for {ip}:")
            last_analysis_stats = data['data']['attributes']['last_analysis_stats']
            print(f"Harmless: {last_analysis_stats['harmless']}")
            print(f"Malicious: {last_analysis_stats['malicious']}")
            print(f"Suspicious: {last_analysis_stats['suspicious']}")
            print(f"Undetected: {last_analysis_stats['undetected']}")
        else:
            print(Fore.LIGHTBLUE_EX + f"Failed to fetch data, status code: {response.status_code}")
    except Exception as e:
        print(Fore.LIGHTBLUE_EX + f"Error: {e}")

def google_dork_search():
    query = input(Fore.LIGHTBLUE_EX + "Enter Google Dork query: ").strip()
    url = f"https://www.google.com/search?q={query.replace(' ', '+')}"
    print(Fore.LIGHTBLUE_EX + f"Opening Google search for: {query}")
    webbrowser.open(url)

def shodan_search():
    API_KEY = "YOUR_SHODAN_API_KEY"
    api = shodan.Shodan(API_KEY)
    query = input(Fore.LIGHTBLUE_EX + "Enter Shodan search query: ").strip()
    try:
        results = api.search(query)
        print(Fore.LIGHTBLUE_EX + f"Results found: {results['total']}\n")
        for result in results['matches'][:5]:
            print(f"IP: {result['ip_str']}")
            print(f"Data: {result['data']}")
            print("-"*40)
    except shodan.APIError as e:
        print(Fore.LIGHTBLUE_EX + f"Error: {e}")

def instagram_info():
    print(Fore.LIGHTBLUE_EX + "\nInstagram Login Required\n")
    inst_user = input(Fore.LIGHTBLUE_EX + "Enter your Instagram username: ").strip()
    inst_pass = getpass("Enter your Instagram password (input hidden): ")
    target = input(Fore.LIGHTBLUE_EX + "Enter target Instagram username: ").strip()

    L = instaloader.Instaloader()
    try:
        print(Fore.LIGHTBLUE_EX + "Logging in...")
        L.login(inst_user, inst_pass)
    except Exception as e:
        print(Fore.LIGHTBLUE_EX + f"Login failed: {e}")
        return

    try:
        profile = instaloader.Profile.from_username(L.context, target)
    except instaloader.exceptions.ProfileNotExistsException:
        print(Fore.LIGHTBLUE_EX + "Error: Profile does not exist.")
        return
    except Exception as e:
        print(Fore.LIGHTBLUE_EX + f"Error: {e}")
        return

    while True:
        print(Fore.LIGHTBLUE_EX + f"""
What do you want to extract from {target}?

1) Full Name
2) Bio
3) Followers Count
4) Following Count
5) Posts Count
6) All Information
0) Back to Main Menu
""")

        choice = input(Fore.LIGHTBLUE_EX + "Choose an option: ").strip()
        if choice == '1':
            print(f"Full Name: {profile.full_name}")
        elif choice == '2':
            print(f"Bio: {profile.biography}")
        elif choice == '3':
            print(f"Followers: {profile.followers}")
        elif choice == '4':
            print(f"Following: {profile.followees}")
        elif choice == '5':
            print(f"Posts: {profile.mediacount}")
        elif choice == '6':
            print(f"""
Full Name: {profile.full_name}
Bio: {profile.biography}
Followers: {profile.followers}
Following: {profile.followees}
Posts: {profile.mediacount}
Is Private: {'Yes' if profile.is_private else 'No'}
""")
        elif choice == '0':
            break
        else:
            print("Invalid option.")

def main():
    print(Fore.LIGHTBLUE_EX + "\nWelcome to DEADEYE - 37 Tool!\n")
    while True:
        banner()
        menu()
        choice = input(Fore.LIGHTBLUE_EX + "Choose an option: ").strip()

        if choice == '1': whois_lookup()
        elif choice == '2': dns_lookup()
        elif choice == '3': ip_geolocation()
        elif choice == '4': website_screenshot()
        elif choice == '5': instagram_info()
        elif choice == '6': pastebin_search()
        elif choice == '7': real_ip_bypass()
        elif choice == '8': virustotal_ip_scan()
        elif choice == '9': shodan_search()
        elif choice == '10': google_dork_search()
        elif choice == '11': explain_options()
        elif choice == '12': about_me()
        elif choice == '0':
            print(Fore.LIGHTBLUE_EX + "thx for using DEADEYE-37!")
            break
        else:
            print(Fore.LIGHTBLUE_EX + "Invalid choice.")

        input(Fore.LIGHTBLUE_EX + "\nPress Enter to return to menu...")

if __name__ == "__main__":
    main()
