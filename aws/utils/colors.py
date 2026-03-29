class C:
    RED    = '\033[91m'
    ORANGE = '\033[33m'
    YELLOW = '\033[93m'
    GREEN  = '\033[92m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    GREY   = '\033[90m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'

LEVEL_COLORS = {
    'Critical': C.RED, 'High': C.ORANGE,
    'Medium': C.YELLOW, 'Low': C.GREEN, 'Clean': C.GREEN,
}

def lc(level): return LEVEL_COLORS.get(level, C.WHITE)

def print_finding(level, resource, finding, risk, fix, note=None):
    col = lc(level)
    print(f"\n  {col}{C.BOLD}[{level.upper()}]{C.RESET}  {C.WHITE}{resource}{C.RESET}")
    print(f"  {C.GREY}Finding{C.RESET}  : {finding}")
    print(f"  {C.GREY}Risk{C.RESET}     : {risk}")
    print(f"  {C.GREY}Fix{C.RESET}      : {C.CYAN}{fix}{C.RESET}")
    if note: print(f"  {C.GREY}Note{C.RESET}     : {note}")

def print_header(title, sub=None):
    print(f"\n{C.GREY}{'═'*64}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}{title}{C.RESET}")
    if sub: print(f"  {C.GREY}{sub}{C.RESET}")
    print(f"{C.GREY}{'═'*64}{C.RESET}")

def print_section(title, icon="▶"):
    print(f"\n{C.BOLD}{C.ORANGE}{icon} {title}{C.RESET}")
    print(f"{C.GREY}{'─'*64}{C.RESET}")

def print_clean(resource):
    print(f"  {C.GREEN}[CLEAN]{C.RESET}   {resource}")

def print_summary(issues):
    c = sum(1 for i in issues if i.get('level')=='Critical')
    h = sum(1 for i in issues if i.get('level')=='High')
    m = sum(1 for i in issues if i.get('level')=='Medium')
    print(f"\n{C.GREY}{'═'*64}{C.RESET}")
    print(f"  {C.BOLD}{C.WHITE}SUMMARY{C.RESET}  {len(issues)} issue(s) found")
    print(f"{C.GREY}{'─'*64}{C.RESET}")
    if c: print(f"  {C.RED}{C.BOLD}Critical : {c}{C.RESET}")
    if h: print(f"  {C.ORANGE}High     : {h}{C.RESET}")
    if m: print(f"  {C.YELLOW}Medium   : {m}{C.RESET}")
    print(f"{C.GREY}{'═'*64}{C.RESET}\n")
