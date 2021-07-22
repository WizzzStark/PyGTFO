import os
from colorama import Fore, Back, Style
import time
import argparse
from dict import binaries

parser = argparse.ArgumentParser(description='CLI for GTFObins')
parser.add_argument('-m', '--menu', action='store_true', required=False, help='Show usage menu')
parser.add_argument('-b', '--binary', type=str, metavar='', required=False, help='Search for a specific binary')
parser.add_argument('-p', '--privilege', type=str, metavar='', required=False, help='Search for a specific privilege')
group = parser.add_mutually_exclusive_group()
group.add_argument('-lb', '--listbinaries', action='store_true', required=False, help='List all available binaries to exloit')
group.add_argument('-lp', '--listpriv', action='store_true', required=False, help='List all available privileges por a specific binary')
group.add_argument('-ap', '--allpriv', action='store_true', required=False, help='Scan all privileges for a specific binary')
args = parser.parse_args()

def logo():
    print(f"""{Fore.CYAN}{Style.BRIGHT}
    ____        ______________________ 
   / __ \__  __/ ____/_  __/ ____/ __ \     
  / /_/ / / / / / __  / / / /_  / / / /     {Fore.WHITE}PyGTFO - GTFOBins Offline Terminal{Fore.CYAN}
 {Fore.BLUE}/ ____/ /_/ / /_/ / / / / __/ / /_/ /                   {Fore.BLUE}By WizzzStark
/_/    \__, /\____/ /_/ /_/    \____/  
      /____/

                              """) 

def main():
    try:
        os.system('cls')
        logo()
        print('\n\n')

        print(Fore.GREEN + Style.NORMAL + '[!] Searching in GTFOBins...\n')

        if args.listpriv:
            if not args.binary:
                print(f'{Fore.RED}{Style.BRIGHT}[!] You need to specify a binary with [-b/--binary] in order to list privileges{Style.NORMAL}\n')
            elif args.binary:
                print(f'{Fore.CYAN}{Style.BRIGHT}[+] Binary: {Style.NORMAL}{args.binary}\n')
                for priv in binaries[args.binary].keys():
                    print(f'\t{Fore.RED}{Style.BRIGHT}[+] Privilege: {Fore.YELLOW}{Style.NORMAL}{priv}')
                print(Style.RESET_ALL + '\n')

        elif args.allpriv:
            if args.binary:
                print ('-------------------------------------------------------------------------------')
                for priv in binaries[args.binary].keys():
                    print(f'{Fore.RED}{Style.BRIGHT}[+] Privilege: {priv}')
                    print(Style.NORMAL + Fore.GREEN + '-------------------------------------------------------------------------------')
                    for exploit in binaries[args.binary][priv]['exploits'].values():
                        print(f'{Fore.YELLOW}{exploit}')
                        print(Style.NORMAL + Fore.GREEN + '-------------------------------------------------------------------------------')
        
        elif args.privilege:
            if args.binary:
                print ('-------------------------------------------------------------------------------')
                print(f'{Fore.RED}{Style.BRIGHT}[+] Privilege: {args.privilege}')
                print(Style.NORMAL + Fore.GREEN + '-------------------------------------------------------------------------------')
                for exploit in binaries[args.binary][args.privilege]['exploits'].values():
                    print(f'{Fore.YELLOW}{exploit}')
                    print(Style.NORMAL + Fore.GREEN + '-------------------------------------------------------------------------------')
        

    except KeyError:
        print(f'{Fore.RED}{Style.BRIGHT}[!] Binary not found in Database, you can use [-lb/--listbinaries] to list available binaries, restarting in 3 seconds ...')
        time.sleep(3)

    except AttributeError:
        print(f'{Fore.RED}{Style.BRIGHT}[!] Binary not found in Database, you can use [-lb/--listbinaries] to list available binaries, restarting in 3 seconds ...')
        time.sleep(3)

def usage():
    os.system('cls')
    print(Fore.CYAN + Style.BRIGHT)
    logo()

    print(f'{Fore.RED}-------------------------------------------------------------------------------------------------')
    print(f'[!] Usage: python main.py <Args>')
    print(f'-------------------------------------------------------------------------------------------------\n\n')
    print(f'\t{Fore.WHITE}[-b/--binary] {Fore.YELLOW}Select a specific binary')
    print(f'\t\t{Fore.WHITE}[-p]{Fore.LIGHTMAGENTA_EX} Search how to exploit a specific privilege for the binary')
    print(f'\t\t{Fore.WHITE}[-ap]{Fore.LIGHTMAGENTA_EX} Search how to exploit all the privileges available for the binary\n\n')
    print(f'\t{Fore.WHITE}[+] Help flags')
    print(f'\t\t{Fore.WHITE}[-lb]{Fore.LIGHTMAGENTA_EX} List all available binaries in GTFObins')
    print(f'\t\t{Fore.WHITE}[-lp]{Fore.LIGHTMAGENTA_EX} List all exploitable privileges for a binary{Fore.WHITE} (You need to specify it with -b)\n\n\n{Fore.RED}')

def listbin():
    if args.listbinaries:
        os.system('cls')
        logo()
        print(f'{Fore.CYAN}{Style.BRIGHT}[!] This is the list of all available binaries:')
        for binary in binaries.keys():
            print(f'\t{Fore.RED}{Style.BRIGHT}[+] {Fore.YELLOW}{Style.NORMAL}{binary}{Style.RESET_ALL}')

if __name__ == '__main__':
    if args.binary:
        args.binary = args.binary.lower()
    if args.privilege:
        args.privilege = args.privilege.lower()
        
    if args.menu:
        usage()

    elif args.listbinaries:
        listbin()

    elif args.binary:
        if args.privilege or args.allpriv or args.listpriv:
            main()
        else:
            os.system('cls')
            logo()
            print(f'{Fore.RED}{Style.BRIGHT}[!] You need to specify privileges, you can use [-lp/--listpriv] to show all available exploits with that binary or [-m/--manual] to show instructions.{Style.RESET_ALL}')
    else:
        usage()
    

    print(f'\n{Fore.RED}{Style.BRIGHT}[!] Closing PyGTFO ...' + Style.RESET_ALL)
