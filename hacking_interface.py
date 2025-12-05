from __future__ import annotations

import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


# ===========================
# Helper data structures
# ===========================

@dataclass
class ToolAction:
    """
    Represents a single action (sub-command) for a tool.

    Attributes:
        key: Menu key for this action (e.g., "1", "2", "a").
        name: Display name of the action.
        description: Short description of what it does.
        handler: Function that implements the action. It receives the Tool instance.
    """
    key: str
    name: str
    description: str
    handler: Callable[['Tool'], None]


@dataclass
class Tool:
    """
    Represents an external command-line tool wrapped by the interface.

    Attributes:
        key: Menu key for this tool in the main menu.
        name: Display name of the tool.
        binary_names: List of possible binary names (e.g., ["nmap"] or ["nc", "ncat"]).
        description: Short description of what the tool is used for.
        actions: Mapping of menu key -> ToolAction for this tool.
        binary_path: Resolved path to the binary actually found on the system.
    """
    key: str
    name: str
    binary_names: List[str]
    description: str
    actions: Dict[str, ToolAction] = field(default_factory=dict)
    binary_path: Optional[str] = None

    def is_available(self) -> bool:
        """
        Checks if the tool is installed and can be executed.
        """
        if self.binary_path:
            return True
        for candidate in self.binary_names:
            path = shutil.which(candidate)
            if path:
                self.binary_path = path
                return True
        return False

    def run(self, args: List[str]) -> None:
        """
        Runs the tool with the given command-line arguments.

        Parameters:
            args: List of arguments to pass to the binary (excluding the binary itself).
        """
        if not self.is_available():
            print(f"\n[!] Tool '{self.name}' is not installed or not found in PATH.")
            print(f"    Tried binaries: {', '.join(self.binary_names)}\n")
            return
        print(f"\n[+] Executing: {self.binary_path} {' '.join(args)}\n")
        try:
            # Inherit stdin/stdout/stderr so you can interact with the tool if it is interactive
            subprocess.run([self.binary_path] + args, check=False)
        except KeyboardInterrupt:
            print("\n[!] Command interrupted by user.\n")
        except Exception as exc:
            print(f"\n[!] Error running tool: {exc}\n")


# ===========================
# Generic input helpers
# ===========================

def print_banner() -> None:
    banner = r"""
============================================================
   ETHICAL NETWORK TOOLKIT (for authorized testing only)
============================================================
"""
    print(banner)


def print_warning() -> None:
    warning = """
This interface is intended for lawful security auditing and network
troubleshooting on systems and networks that you own or are explicitly
authorized to test. Misuse may be illegal and against your organization's
policies.
"""
    print(textwrap.dedent(warning))


def prompt_non_empty(prompt: str) -> str:
    """
    Prompts the user until they provide a non-empty string.
    """
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("[!] Please enter a non-empty value.")


def prompt_int(
    prompt: str,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None
) -> int:
    """
    Prompts the user for an integer, optionally enforcing bounds.
    """
    while True:
        raw = input(prompt).strip()
        try:
            value = int(raw)
        except ValueError:
            print("[!] Please enter a valid integer.")
            continue

        if min_value is not None and value < min_value:
            print(f"[!] Value must be >= {min_value}.")
            continue
        if max_value is not None and value > max_value:
            print(f"[!] Value must be <= {max_value}.")
            continue
        return value


def wait_for_enter() -> None:
    """
    Pauses execution until the user presses Enter. Used between actions.
    """
    input("\nPress Enter to continue...")


# ===========================
# Nmap actions
# ===========================

def nmap_ping_sweep(tool: Tool) -> None:
    """
    Performs an nmap ping sweep (host discovery) over a network range.
    """
    print("\n[ Nmap - Ping Sweep / Host Discovery ]")
    print("Example network range: 192.168.1.0/24")
    network = prompt_non_empty("Target network (CIDR): ")
    print("\n[!] Note: Host discovery may require appropriate permissions.")
    tool.run(["-sn", network])
    wait_for_enter()


def nmap_quick_scan(tool: Tool) -> None:
    """
    Performs a quick nmap scan of common ports on a single host or domain.
    """
    print("\n[ Nmap - Quick Scan (Common Ports) ]")
    target = prompt_non_empty("Target host or IP: ")
    print("\n[+] Running a quick scan of common ports with basic service detection.")
    # -T4: faster timing; -F: fast (common ports); -sV: service version detection
    tool.run(["-T4", "-F", "-sV", target])
    wait_for_enter()


def nmap_full_scan(tool: Tool) -> None:
    """
    Performs a more thorough nmap scan of all ports with service and OS detection.
    """
    print("\n[ Nmap - Full Scan (All Ports, Service & OS Detection) ]")
    target = prompt_non_empty("Target host or IP: ")
    print(
        "\n[!] This scan can take a while and may be noisy on the network.\n"
        "    Some features (like OS detection) may require elevated privileges."
    )
    # -p-: all ports; -sV: service versions; -O: OS detection; -T4: higher speed (use with care)
    tool.run(["-p-", "-sV", "-O", "-T4", target])
    wait_for_enter()


def nmap_custom(tool: Tool) -> None:
    """
    Allows the user to specify custom nmap arguments for advanced use.
    """
    import shlex

    print("\n[ Nmap - Custom Arguments ]")
    print("Examples:")
    print("  -sU -p 53,123           # UDP ports 53 and 123")
    print("  -sS -Pn -p 80,443       # SYN scan, skip host discovery")
    print("  -A                      # Aggressive scan (use with care)")
    print("\nUse this only on systems you are authorized to test.\n")

    arg_str = input("Additional nmap arguments (leave empty for none): ").strip()
    target = prompt_non_empty("Target host or network: ")

    args: List[str] = []
    if arg_str:
        try:
            args.extend(shlex.split(arg_str))
        except ValueError as exc:
            print(f"[!] Could not parse arguments: {exc}")
            wait_for_enter()
            return

    args.append(target)
    tool.run(args)
    wait_for_enter()


# ===========================
# Netdiscover actions
# ===========================

def netdiscover_active(tool: Tool) -> None:
    """
    Runs netdiscover in active mode on a given network range.
    """
    print("\n[ Netdiscover - Active Scan ]")
    print("Example range: 192.168.1.0/24")
    network = prompt_non_empty("Target network range (CIDR): ")
    print(
        "\n[!] Active ARP scanning can be noisy. Use only on authorized local networks."
    )
    tool.run(["-r", network])
    wait_for_enter()


def netdiscover_passive(tool: Tool) -> None:
    """
    Runs netdiscover in passive mode, listening for ARP traffic.
    """
    print("\n[ Netdiscover - Passive Mode ]")
    print(
        "Netdiscover will listen passively for ARP traffic on the local network "
        "and report discovered hosts."
    )
    print("\nPress Ctrl+C to stop passive discovery.\n")
    tool.run(["-p"])
    wait_for_enter()


# ===========================
# Netcat (nc) actions
# ===========================

def netcat_client(tool: Tool) -> None:
    """
    Opens a netcat TCP client to connect to a host and port.
    """
    print("\n[ Netcat - TCP Client ]")
    host = prompt_non_empty("Target host or IP: ")
    port = prompt_int("Target port (1-65535): ", min_value=1, max_value=65535)

    print(
        "\n[+] Opening TCP connection using netcat.\n"
        "    Type data and press Enter to send. Press Ctrl+C to exit.\n"
        "    Use only to test services you are authorized to access."
    )
    tool.run([host, str(port)])
    wait_for_enter()


def netcat_listener(tool: Tool) -> None:
    """
    Starts a simple netcat TCP listener on a port for testing connectivity.
    """
    print("\n[ Netcat - Simple TCP Listener ]")
    port = prompt_int("Listen port (1-65535): ", min_value=1, max_value=65535)
    print(
        "\n[!] This listener will accept raw TCP connections on the chosen port.\n"
        "    Use strictly for testing between systems you control/own.\n"
        "    Do NOT use to receive or provide unauthorized access or shells.\n"
        "Press Ctrl+C to stop the listener.\n"
    )

    # -l: listen; -v: verbose
    tool.run(["-l", "-v", str(port)])
    wait_for_enter()


# ===========================
# Ping actions
# ===========================

def ping_host(tool: Tool) -> None:
    """
    Sends ICMP echo requests to a host to check reachability.
    """
    print("\n[ Ping - Host Reachability ]")
    host = prompt_non_empty("Host or IP to ping: ")
    count = prompt_int("Number of echo requests to send (default 4): ", min_value=1)
    tool.run(["-c", str(count), host])
    wait_for_enter()


# ===========================
# Traceroute actions
# ===========================

def traceroute_host(tool: Tool) -> None:
    """
    Traces the network path to a host.
    """
    print("\n[ Traceroute - Route to Host ]")
    host = prompt_non_empty("Host or IP to trace route to: ")
    print(
        "\n[!] Route tracing generates packets across multiple networks; "
        "ensure you are allowed to perform this test."
    )
    tool.run([host])
    wait_for_enter()


# ===========================
# Whois actions
# ===========================

def whois_lookup(tool: Tool) -> None:
    """
    Performs a WHOIS lookup on a domain or IP address.
    """
    print("\n[ Whois - Lookup ]")
    target = prompt_non_empty("Domain or IP: ")
    tool.run([target])
    wait_for_enter()


# ===========================
# DNS lookup actions
# ===========================

def dns_simple_lookup(tool: Tool) -> None:
    """
    Performs a simple DNS A record lookup.
    """
    print("\n[ DNS - Simple A Record Lookup ]")
    name = prompt_non_empty("Hostname or domain: ")

    # If the tool is dig-like, use 'dig +short <name>'.
    # If it's nslookup, use 'nslookup <name>'.
    if "dig" in (tool.binary_path or ""):
        tool.run(["+short", name])
    else:
        # Assume nslookup-style syntax
        tool.run([name])
    wait_for_enter()


def dns_full_query(tool: Tool) -> None:
    """
    Performs a more detailed DNS query for multiple record types.
    """
    print("\n[ DNS - Detailed Query ]")
    name = prompt_non_empty("Hostname or domain: ")
    print("Common types: A, AAAA, MX, NS, TXT, CNAME, ANY")
    record_type = prompt_non_empty("Record type (default A): ").upper() or "A"

    if "dig" in (tool.binary_path or ""):
        tool.run([name, record_type])
    else:
        # nslookup doesn't use explicit type argument in the same way;
        # we can still run a simple query and let the tool interactively display info.
        print("\n[!] Detailed record type selection may be limited with nslookup.")
        tool.run([name])
    wait_for_enter()


# ===========================
# Tool construction
# ===========================

def build_tools() -> List[Tool]:
    """
    Constructs and returns the list of supported tools with their actions.
    """
    tools: List[Tool] = []

    # Nmap
    nmap_tool = Tool(
        key="1",
        name="nmap",
        binary_names=["nmap"],
        description="Port scanning and host discovery"
    )
    nmap_tool.actions = {
        "1": ToolAction(
            key="1",
            name="Ping sweep (host discovery)",
            description="Discover live hosts on a network range",
            handler=nmap_ping_sweep
        ),
        "2": ToolAction(
            key="2",
            name="Quick scan (common ports)",
            description="Fast scan of common ports with basic service detection",
            handler=nmap_quick_scan
        ),
        "3": ToolAction(
            key="3",
            name="Full scan (all ports, OS & service detection)",
            description="Thorough scan of all ports with OS & service detection",
            handler=nmap_full_scan
        ),
        "4": ToolAction(
            key="4",
            name="Custom nmap arguments",
            description="Advanced usage with manually specified nmap options",
            handler=nmap_custom
        ),
    }
    tools.append(nmap_tool)

    # Netdiscover
    netdiscover_tool = Tool(
        key="2",
        name="netdiscover",
        binary_names=["netdiscover"],
        description="ARP-based host discovery on local networks"
    )
    netdiscover_tool.actions = {
        "1": ToolAction(
            key="1",
            name="Active scan on network",
            description="Actively discover hosts on a given network range",
            handler=netdiscover_active
        ),
        "2": ToolAction(
            key="2",
            name="Passive listening",
            description="Passively listen for ARP traffic to discover hosts",
            handler=netdiscover_passive
        ),
    }
    tools.append(netdiscover_tool)

    # Netcat
    netcat_tool = Tool(
        key="3",
        name="netcat (nc)",
        binary_names=["nc", "ncat", "netcat"],
        description="Simple TCP connectivity tests (client / listener)"
    )
    netcat_tool.actions = {
        "1": ToolAction(
            key="1",
            name="TCP client",
            description="Connect to a host and port to test a service",
            handler=netcat_client
        ),
        "2": ToolAction(
            key="2",
            name="TCP listener",
            description="Start a basic TCP listener on a port for testing",
            handler=netcat_listener
        ),
    }
    tools.append(netcat_tool)

    # Ping
    ping_tool = Tool(
        key="4",
        name="ping",
        binary_names=["ping"],
        description="Host reachability tests via ICMP echo"
    )
    ping_tool.actions = {
        "1": ToolAction(
            key="1",
            name="Ping host",
            description="Send ICMP echo requests to a host",
            handler=ping_host
        ),
    }
    tools.append(ping_tool)

    # Traceroute (Linux/Unix) / tracert (Windows)
    traceroute_tool = Tool(
        key="5",
        name="traceroute / tracert",
        binary_names=["traceroute", "tracert"],
        description="Trace network path to a host"
    )
    traceroute_tool.actions = {
        "1": ToolAction(
            key="1",
            name="Trace route to host",
            description="Show the path packets take to a host",
            handler=traceroute_host
        ),
    }
    tools.append(traceroute_tool)

    # Whois
    whois_tool = Tool(
        key="6",
        name="whois",
        binary_names=["whois"],
        description="WHOIS lookups for domains and IPs"
    )
    whois_tool.actions = {
        "1": ToolAction(
            key="1",
            name="WHOIS lookup",
            description="Retrieve registration info for a domain or IP",
            handler=whois_lookup
        ),
    }
    tools.append(whois_tool)

    # DNS (dig / nslookup)
    dns_tool = Tool(
        key="7",
        name="DNS (dig / nslookup)",
        binary_names=["dig", "nslookup"],
        description="DNS record lookups"
    )
    dns_tool.actions = {
        "1": ToolAction(
            key="1",
            name="Simple A record lookup",
            description="Resolve a hostname to its IP address(es)",
            handler=dns_simple_lookup
        ),
        "2": ToolAction(
            key="2",
            name="Detailed DNS query",
            description="Query specific DNS record types (A, MX, NS, etc.)",
            handler=dns_full_query
        ),
    }
    tools.append(dns_tool)

    return tools


# ===========================
# Menu rendering
# ===========================

def print_main_menu(tools: List[Tool]) -> None:
    """
    Displays the main menu listing available tools.
    """
    print_banner()
    print_warning()

    print("Available tools:\n")
    for tool in tools:
        status = "available" if tool.is_available() else "not installed"
        print(f"  {tool.key}) {tool.name:<22} - {tool.description} [{status}]")
    print("\n  q) Quit")
    print("------------------------------------------------------------")


def print_tool_menu(tool: Tool) -> None:
    """
    Displays the submenu for a specific tool.
    """
    print(f"\n============================================================")
    print(f"[ {tool.name} ] - {tool.description}")
    print("============================================================\n")

    if not tool.is_available():
        print(f"[!] Tool '{tool.name}' is not installed or not in PATH.")
        print(f"    Tried binaries: {', '.join(tool.binary_names)}")
        print("\nInstall it using your package manager, then try again.")
        return

    print("Available actions:\n")
    for key, action in sorted(tool.actions.items(), key=lambda kv: kv[0]):
        print(f"  {key}) {action.name} - {action.description}")
    print("\n  b) Back to main menu")
    print("------------------------------------------------------------")


# ===========================
# Main program loop
# ===========================

def main() -> None:
    tools = build_tools()
    tool_map: Dict[str, Tool] = {tool.key: tool for tool in tools}

    while True:
        print_main_menu(tools)
        choice = input("Select a tool (or 'q' to quit): ").strip().lower()

        if choice in {"q", "quit", "exit"}:
            print("\nGoodbye. Use your skills responsibly.\n")
            break

        tool = tool_map.get(choice)
        if tool is None:
            print("\n[!] Invalid selection. Please choose a valid tool.\n")
            continue

        # Tool submenu loop
        while True:
            print_tool_menu(tool)
            if not tool.is_available():
                wait_for_enter()
                break

            sub_choice = input("Select an action (or 'b' to go back): ").strip().lower()

            if sub_choice in {"b", "back"}:
                break

            action = tool.actions.get(sub_choice)
            if action is None:
                print("\n[!] Invalid action. Please select a valid option.\n")
                continue

            # Execute the selected action
            action.handler(tool)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting.\n")
        sys.exit(1)

