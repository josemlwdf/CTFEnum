from colorama import init, Fore, Back, Style

# Initialize colorama
init()

YELLOW = 'YELLOW'
BLACK = 'BLACK'
RED = 'RED'
GREEN = 'GREEN'
BLUE = 'BLUE'
MAGENTA = 'MAGENTA'
CYAN = 'CYAN'
WHITE = 'WHITE'

max_subprocess = 200


def printc(text, color=None, back_color=None):
    if color is not None:
        colored_text = getattr(Fore, color.upper(), Fore.RESET) + Style.BRIGHT + text
    else:
        colored_text = Style.RESET_ALL + text

    if back_color is not None:
        colored_text = getattr(Back, back_color.upper(), Back.RESET) + colored_text

    print(colored_text + Style.RESET_ALL)


# Prints a command output separator
def print_separator():
    printc('=' * 70, YELLOW)


# Starts a list of subprocesses and then wait for them to finish
def launch_procs(procs):
    while procs:
        try:
            running_procs = []

            # Launch subprocesses up to the maximum limit or until the end of the list
        
            for proc in procs[:max_subprocess]:
                proc.start()
                running_procs.append(proc)
        
            # Wait for the running subprocesses to finish
            for proc in running_procs:
                proc.join()

            # Remove finished subprocesses from the list
            procs = procs[max_subprocess:]
        except:
            continue
    return []


# Returns from a given username: an empty value, the same value, the reversed value
def get_usernames_esr(username):
    return ['', username, ''.join(reversed(username))]