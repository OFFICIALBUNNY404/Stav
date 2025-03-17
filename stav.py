import os
from colorama import Fore, Style, init

init(autoreset=True)

class STAV:
    def __init__(self):
        self.banner()

    def banner(self):
        print(Fore.CYAN + "=" * 60)
        print(Fore.YELLOW + Style.BRIGHT)
        print("                           .       .")
        print("               ..    ......  .... .. ..  ..")
        print("            ..    ......          . .....   ..")
        print("          ..   ...                     .....  ..")
        print("        ..  ....                          .  .  ..")
        print("       .   ...                               ..   .")
        print("      .  ...     ','.               '..       ...  .")
        print("     .  ....     ::';;            ,,  ,.       ...  .")
        print("       ....      ;d;';l.        .o; .,o         ...")
        print("    .             do:;cc'      .ol .;d;              .")
        print("    .             .dodlo'.     :c..;d;               .")
        print("                    'lxl:;....'c,.,;.")
        print("                      .:ccllc:;;,'.")
        print("  .      .           ,,oddol;c..                   .")
        print("  .  .,loo           ',.:xxl'. ..              ,'  .")
        print("   .:kNk,.c        .;;;,lO0d,.....          ,OxKOl,")
        print("    .ckNXx;c      .;c:ok0ddl;o:....         ,''d,")
        print("     ,;..cX0o,     ...coxc..;;'.          ;OcdXo")
        print("       ,oX;ol.;,   ..                  ;, .ckxol")
        print("        .c.   'kk::,...                .NoXk")
        print("            .lKKK: k;:,,'.....'';;.k,   :O..")
        print("            .kdoX kx X dK d 0o.0.K,MK")
        print("                . 0,xx 0oxN kxdM..X00;")
        print("                   o ck ;,.,")
        print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)

    def analyze_command(self, command):
        if "rm -rf" in command:
            return Fore.RED + "[WARNING] Detected potential misuse of 'rm -rf'!"
        elif "curl" in command and "telegram" in command:
            return Fore.RED + "[WARNING] Suspicious 'curl' command detected, possibly assembling a RAT."
        elif "termux-setup-storage" in command:
            return Fore.RED + "[WARNING] Unauthorized attempt to access internal storage detected!"
        else:
            return Fore.GREEN + "[INFO] Command appears safe."

    def analyze_requests(self, url):
        suspicious_keywords = ["malware", "rat", "phishing"]
        for keyword in suspicious_keywords:
            if keyword in url:
                return Fore.RED + f"[WARNING] Suspicious URL detected: {url}"
        return Fore.GREEN + f"[INFO] URL {url} appears safe."

def scan_file(filepath, mode, stav):
    try:
        with open(filepath, 'r') as file:
            print(Fore.CYAN + f"\n[INFO] Scanning {mode} from file: {filepath}")
            print(Fore.MAGENTA + "-" * 60)
            for line in file:
                item = line.strip()
                if item:
                    if mode == "commands":
                        result = stav.analyze_command(item)
                    elif mode == "URLs":
                        result = stav.analyze_requests(item)
                    print(result)
            print(Fore.MAGENTA + "-" * 60)
            print(Fore.CYAN + "\n[INFO] Scan complete.")
    except FileNotFoundError:
        print(Fore.RED + f"[ERROR] File not found: {filepath}")
    except Exception as e:
        print(Fore.RED + f"[ERROR] An error occurred: {str(e)}")

def main():
    stav = STAV()
    while True:
        print(Fore.MAGENTA + "\n" + "=" * 60)
        print(Fore.YELLOW + "        Choose an option:")
        print(Fore.GREEN + "        1. Analyze a single command")
        print(Fore.GREEN + "        2. Analyze a single URL")
        print(Fore.GREEN + "        3. Scan multiple commands from a file")
        print(Fore.GREEN + "        4. Scan multiple URLs from a file")
        print(Fore.RED + "        5. Exit")
        print(Fore.MAGENTA + "=" * 60)
        choice = input(Fore.CYAN + "        Enter your choice: ").strip()

        if choice == "1":
            command = input(Fore.CYAN + "Enter the command to analyze: ").strip()
            if command:
                print(stav.analyze_command(command))
            else:
                print(Fore.RED + "[ERROR] Command cannot be empty!")
        elif choice == "2":
            url = input(Fore.CYAN + "Enter the URL to analyze: ").strip()
            if url:
                print(stav.analyze_requests(url))
            else:
                print(Fore.RED + "[ERROR] URL cannot be empty!")
        elif choice == "3":
            filepath = input(Fore.CYAN + "Enter the file path for commands: ").strip()
            scan_file(filepath, "commands", stav)
        elif choice == "4":
            filepath = input(Fore.CYAN + "Enter the file path for URLs: ").strip()
            scan_file(filepath, "URLs", stav)
        elif choice == "5":
            print(Fore.YELLOW + "\n[INFO] Exiting STAV Protection. Stay safe!")
            break
        else:
            print(Fore.RED + "[ERROR] Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
