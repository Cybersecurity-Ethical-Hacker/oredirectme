#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import asyncio
import time
import subprocess
import platform
import logging
import argparse
import random
import json
import re
import warnings
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any, Set, Union
from urllib.parse import urlparse, parse_qs, urlencode

import tldextract
from playwright.async_api import async_playwright, Error as PlaywrightError, Browser, Page, BrowserContext
from importlib.metadata import version as get_version, PackageNotFoundError
from packaging.version import parse as parse_version
from colorama import init, Fore, Style
from tqdm import tqdm

init(autoreset=True)

# ------------------------------------------------------------
# Default Configuration Constants
# ------------------------------------------------------------
MAX_CONCURRENT_CONNECTIONS: int = 20
DEFAULT_RATE_LIMIT: int = 100
MAX_URL_LENGTH: int = 2083
MAX_PARAM_LENGTH: int = 1000
DEFAULT_TIMEOUT: int = 5
VERSION: str = "0.0.1"
GITHUB_REPOSITORY: str = "Cybersecurity-Ethical-Hacker/oredirectme"
GITHUB_URL: str = f"https://github.com/{GITHUB_REPOSITORY}"

# ------------------------------------------------------------
# Version and Dependency Checks
# ------------------------------------------------------------
def get_playwright_version() -> str:
    try:
        import playwright
        version = getattr(playwright, '__version__', None)
        if not version:
            version = get_version('playwright')
        if version == "0.0.0":
            version = "0.0.0 (Normal on some Linux distributions)"
        return version
    except ImportError:
        print(f"{Fore.RED}Error: Playwright is not installed")
        print("Please install: pip install playwright>=1.35.0")
        print(f"Then run: playwright install chromium{Style.RESET_ALL}")
        sys.exit(1)
    except PackageNotFoundError:
        return "unknown"
    except Exception as e:
        return f"error retrieving version: {e}"

def check_playwright_version_installed() -> None:
    try:
        playwright_version = get_playwright_version()
        required_version = '1.35.0'
        if playwright_version.startswith("0.0.0"):
            logging.info(f"Playwright version {playwright_version} detected. Normal on some Linux distributions.")
            return
        if playwright_version.startswith("error") or playwright_version == "unknown":
            print(f"{Fore.RED}Error: Unable to determine Playwright version")
            sys.exit(1)
        if parse_version(playwright_version) < parse_version(required_version):
            print(f"{Fore.RED}Error: This tool requires Playwright >= {required_version}")
            print(f"Current version: {playwright_version}")
            print("Please upgrade: pip install -U playwright")
            print(f"{Style.RESET_ALL}")
            sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error during Playwright version check: {e}{Style.RESET_ALL}")
        sys.exit(1)

# ------------------------------------------------------------
# Logging Filters
# ------------------------------------------------------------
class TimeoutFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        timeout_patterns = [
            "Timeout 8000ms exceeded",
            "Page.goto: Timeout",
            "Call log:",
            "navigating to"
        ]
        return not any(pattern in record.msg for pattern in timeout_patterns)

class GitAuthErrorFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        git_auth_error_patterns = [
            "could not read Username for 'https://github.com': terminal prompts disabled",
            "authentication failed",
            "fatal: Authentication failed",
        ]
        return not any(pattern.lower() in record.msg.lower() for pattern in git_auth_error_patterns)

# ------------------------------------------------------------
# Git Handler and Update Logic
# ------------------------------------------------------------
class GitHandler:
    @staticmethod
    def check_git() -> Tuple[bool, str]:
        try:
            result = subprocess.run(
                ['git', '--version'],
                capture_output=True,
                text=True,
                check=True,
                env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},
                stdin=subprocess.DEVNULL
            )
            return True, result.stdout.strip()
        except FileNotFoundError:
            return False, "Git is not installed"
        except subprocess.CalledProcessError as e:
            return False, f"Git error: {e.stderr.strip()}"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def check_repo_status() -> Tuple[bool, str]:
        try:
            subprocess.run(
                ['git', 'rev-parse', '--git-dir'],
                capture_output=True,
                check=True,
                env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},
                stdin=subprocess.DEVNULL
            )
            return True, "Repository OK"
        except subprocess.CalledProcessError:
            logging.info("Repository status: Not initialized")
            return False, "Update: Repository not initialized"
        except Exception as e:
            logging.info(f"Repository status: Connection error - {str(e)}")
            return False, f"Update: Repository connection error"

    @staticmethod
    def get_installation_instructions() -> str:
        system = platform.system().lower()
        if system == "windows":
            return """
Git is not installed. To install Git on Windows:
1. Download the official Git installer:
   https://git-scm.com/download/windows
2. Or install with winget:
   winget install --id Git.Git -e --source winget
3. Or install with Chocolatey:
   choco install git
After installation, restart your terminal/command prompt.
"""
        elif system == "darwin":
            return """
Git is not installed. To install Git on macOS:
1. Install with Homebrew (recommended):
   brew install git
2. Install Xcode Command Line Tools (alternative):
   xcode-select --install
After installation, restart your terminal.
"""
        elif system == "linux":
            try:
                with open('/etc/os-release') as f:
                    distro = f.read().lower()
                if 'ubuntu' in distro or 'debian' in distro or 'kali' in distro:
                    return """
Git is not installed. To install Git:
1. Update package list:
   sudo apt update
2. Install git:
   sudo apt install git
After installation, restart your terminal.
"""
                elif 'fedora' in distro or 'rhel' in distro or 'centos' in distro:
                    return """
Git is not installed. To install Git:
1. Install git:
   sudo dnf install git  (Fedora)
   sudo yum install git  (RHEL/CentOS)
After installation, restart your terminal.
"""
                elif 'arch' in distro:
                    return """
Git is not installed. To install Git:
1. Install git:
   sudo pacman -S git
After installation, restart your terminal.
"""
            except:
                pass
            return """
Git is not installed. Please install using your distro's package manager:
- Ubuntu/Debian/Kali: sudo apt install git
- Fedora: sudo dnf install git
- Arch: sudo pacman -S git
After installation, restart your terminal.
"""
        return """
Git is not installed. Please install Git for your operating system:
https://git-scm.com/downloads
"""

    def ensure_git_available(self) -> bool:
        is_installed, message = self.check_git()
        if not is_installed:
            print(f"\n{Fore.RED}Error: {message}{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Installation Instructions:{Style.RESET_ALL}")
            print(self.get_installation_instructions())
            return False
        return True

@dataclass
class VersionInfo:
    current: str
    update_available: str

# ------------------------------------------------------------
# URL Validation and Normalization
# ------------------------------------------------------------
class URLValidator:
    @staticmethod
    def validate_url(url: str) -> Tuple[bool, Optional[str]]:
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ['http', 'https']:
                return False, "URL must start with http:// or https://"
            if not parsed.netloc:
                return False, "Invalid URL structure - missing domain"
            if len(url) > MAX_URL_LENGTH:
                return False, f"URL exceeds maximum length of {MAX_URL_LENGTH} characters"
            return True, None
        except Exception as e:
            return False, f"URL validation error: {str(e)}"

    @staticmethod
    def normalize_url(url: str) -> str:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        path = parsed.path.lower().rstrip('/')
        if not path:
            path = '/'
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            sorted_params: List[Tuple[str, str]] = []
            for key in sorted(params.keys()):
                for value in params[key]:
                    sorted_params.append((key, value))
            normalized_query = urlencode(sorted_params)
        else:
            normalized_query = ''
        normalized = f"{parsed.scheme}://{netloc}{path}"
        if normalized_query:
            normalized += f"?{normalized_query}"
        return normalized

def normalize_url_structure(url: str) -> str:
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        normalized_params = []
        for key in sorted(params.keys()):
            normalized_params.append((key, ""))
        normalized_query = urlencode(normalized_params, doseq=True)
        return parsed._replace(query=normalized_query).geturl()
    except Exception:
        return url

def filter_urls(urls: Union[str, List[str]]) -> List[str]:
    if isinstance(urls, str):
        urls = [urls]
    filtered: List[str] = []
    seen_normalized: Set[str] = set()
    seen_structures: Set[str] = set()
    for url in urls:
        if not ParameterHandler.has_parameters(url):
            continue
        is_valid, error = URLValidator.validate_url(url)
        if not is_valid:
            logging.error(f"Invalid URL skipped - {url}: {error}")
            continue
        url_structure = normalize_url_structure(url)
        if url_structure in seen_structures:
            continue
        normalized_url = URLValidator.normalize_url(url)
        if normalized_url not in seen_normalized:
            seen_normalized.add(normalized_url)
            seen_structures.add(url_structure)
            filtered.append(url)
    return filtered

# ------------------------------------------------------------
# Async File Loading
# ------------------------------------------------------------
async def load_file_async(file_path: str) -> List[str]:
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return [line.strip() for line in content.split('\n') if line.strip()]
    except FileNotFoundError:
        print(f"\n{Fore.RED}Error: File not found - {file_path}{Style.RESET_ALL}")
        sys.exit(1)

def extract_domain_info(url: str) -> Tuple[str, str]:
    try:
        parsed = urlparse(url)
        domain_info = tldextract.extract(parsed.netloc)
        registered_domain = f"{domain_info.domain}.{domain_info.suffix}"
        full_domain = parsed.netloc
        return registered_domain.lower(), full_domain.lower()
    except Exception as e:
        logging.error(f"Error extracting domain info from {url}: {str(e)}")
        return "", ""

# ------------------------------------------------------------
# Custom Argument Parsing
# ------------------------------------------------------------
class CustomHelpFormatter(argparse.HelpFormatter):
    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings:
            metavar, = self._metavar_formatter(action, action.dest)(1)
            return metavar
        else:
            parts = []
            if hasattr(self, '_usage_mode'):
                return action.option_strings[0]
            if action.nargs == 0:
                parts.extend(action.option_strings)
            else:
                parts.extend(action.option_strings)
            return ', '.join(parts)

    def _expand_help(self, action: argparse.Action) -> str:
        params = dict(vars(action), prog=self._prog)
        for name in list(params):
            if params[name] is argparse.SUPPRESS:
                del params[name]
            elif hasattr(params[name], '__name__'):
                params[name] = params[name].__name__
        if params.get('help') == 'show this help message and exit':
            return 'Show this help message and exit'
        return self._get_help_string(action) % params

    def _format_usage(self, usage: Optional[str], actions: List[argparse.Action],
                      groups: List[argparse._ArgumentGroup], prefix: Optional[str]) -> str:
        if prefix is None:
            prefix = 'usage: '
        self._usage_mode = True
        action_usage = []
        action_usage.append("[-h HELP]")
        action_usage.append("[-d DOMAIN | -l URL_LIST]")
        for action in actions:
            if action.option_strings:
                if action.option_strings[0] not in ['-h', '-d', '-l']:
                    msg = self._format_action_invocation(action)
                    upper_dest = action.dest.upper()
                    action_usage.append(f"[{msg} {upper_dest}]")
        usage = ' '.join([x for x in action_usage if x])
        delattr(self, '_usage_mode')
        return f"{prefix}{self._prog} {usage}\n\n"

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        args = sys.argv[1:]
        if '-u' in args or '--update' in args:
            if len(args) == 1:
                return
        self.print_help()
        print(f"\n{Fore.RED}Error: {message}{Style.RESET_ALL}")
        sys.exit(2)

def parse_arguments() -> argparse.Namespace:
    parser = CustomArgumentParser(
        formatter_class=lambda prog: CustomHelpFormatter(prog, max_help_position=80),
        description="",
        epilog=(
            "Examples:\n"
            "  python oredirectmegpt.py -d \"https://example.com/page.php?param1=value1&param2=value2\"\n"
            "  python oredirectmegpt.py -l urls.txt"
        )
    )
    parser.add_argument('-u', '--update', action='store_true',
                       help='Check for updates and automatically install the latest version')
    mutex_group = parser.add_mutually_exclusive_group(required=False)
    mutex_group.add_argument('-d', '--domain', 
                           help='Specify the domain with parameter(s) to scan (required unless -l is used)')
    mutex_group.add_argument('-l', '--url-list', 
                           help='Provide a file containing a list of URLs with parameters to scan')
    parser.add_argument('-p', '--payloads', help='Custom file containing payloads')
    parser.add_argument('-o', '--output', help='Specify the output file name (supports .txt or .json)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Maximum number of concurrent workers')
    parser.add_argument('-r', '--rate', type=int, default=DEFAULT_RATE_LIMIT, 
                       help='Request rate limit')
    parser.add_argument('-t', '--timeout', type=int, default=8, help='Total request timeout in seconds')
    parser.add_argument('-j', '--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('-H', '--header', action='append', help='Custom headers, multiple times. Format: "Header: Value"')
    args = parser.parse_args()
    if not args.update and not (args.domain or args.url_list):
        parser.error("one of the arguments -d/--domain -l/--url-list is required")
    if not args.update:
        if args.workers < 1 or args.workers > 50:
            parser.error("Workers must be between 1 and 50")
        if args.rate < 1 or args.rate > 100:
            parser.error("Rate limit must be between 1 and 100 requests per second")
        if args.timeout < 1 or args.timeout > 60:
            parser.error("Timeout must be between 1 and 60 seconds")
    return args

# ------------------------------------------------------------
# Logging Setup
# ------------------------------------------------------------
def setup_logging(config: Config) -> None:
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    timeout_filter = TimeoutFilter()
    git_auth_error_filter = GitAuthErrorFilter()
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    file_handler = logging.FileHandler(logs_dir / 'oredirectme.log')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s:%(message)s'))
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.addFilter(timeout_filter)
    console_handler.addFilter(git_auth_error_filter)
    console_handler.setFormatter(logging.Formatter('%(levelname)s:%(message)s'))
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

# ------------------------------------------------------------
# Headers and Configuration
# ------------------------------------------------------------
class HeaderManager:
    @staticmethod
    def get_default_headers() -> Dict[str, str]:
        chrome_versions = ["122.0.6261.112", "122.0.6261.94", "122.0.6261.69"]
        viewport_widths = [1366, 1440, 1536, 1920, 2560]
        device_memories = [2, 4, 8, 16]
        languages = [
            'en-US,en;q=0.9',
            'en-US,en;q=0.9,es;q=0.8',
            'en-GB,en;q=0.9,en-US;q=0.8',
            'en-US,en;q=0.9,fr;q=0.8'
        ]
        chrome_version = random.choice(chrome_versions)
        viewport = random.choice(viewport_widths)
        memory = random.choice(device_memories)
        language = random.choice(languages)
        base_headers = {
            'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version} Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': language,
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Ch-Ua': f'"Chromium";v="{chrome_version}", "Google Chrome";v="{chrome_version}", "Not(A:Brand";v="24"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Sec-Ch-Ua-Platform-Version': '"15.0.0"',
            'Sec-Ch-Ua-Full-Version-List': f'"Chromium";v="{chrome_version}", "Google Chrome";v="{chrome_version}", "Not(A:Brand";v="24.0.0.0"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'Connection': 'keep-alive',
            'DNT': '1',
            'Viewport-Width': str(viewport),
            'Device-Memory': f'{memory}',
            'Priority': 'u=0, i',
            'Permissions-Policy': 'interest-cohort=()',
        }
        return base_headers

    @staticmethod
    def merge_headers(default_headers: Dict[str, str], custom_headers: Dict[str, str] = None) -> Dict[str, str]:
        if not custom_headers:
            return default_headers
        merged = default_headers.copy()
        custom_headers = {k.title(): v for k, v in custom_headers.items()}
        merged.update(custom_headers)
        return merged

    @staticmethod
    def get_headers(custom_headers: Dict[str, str] = None) -> Dict[str, str]:
        default_headers = HeaderManager.get_default_headers()
        return HeaderManager.merge_headers(default_headers, custom_headers)

class Updater:
    def __init__(self) -> None:
        self.current_version: str = "0.0.1"
        self.repo_path: Path = Path(__file__).parent
        self.is_git_repo: bool = self._check_git_repo()
        self.default_branch: Optional[str] = self._detect_default_branch()

    def _check_git_repo(self) -> bool:
        try:
            subprocess.run(
                ['git', 'rev-parse', '--git-dir'],
                cwd=self.repo_path,
                capture_output=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
        except Exception:
            return False

    def _detect_default_branch(self) -> Optional[str]:
        if not self.is_git_repo:
            return None
        try:
            result = subprocess.run(
                ['git', 'remote', 'show', 'origin'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            for line in result.stdout.split('\n'):
                if 'HEAD branch:' in line:
                    return line.split(':')[1].strip()
            for branch in ['main', 'master']:
                check_branch = subprocess.run(
                    ['git', 'rev-parse', '--verify', f'origin/{branch}'],
                    cwd=self.repo_path,
                    capture_output=True
                )
                if check_branch.returncode == 0:
                    return branch
        except:
            pass
        return 'main'

class AutoUpdater(Updater):
    def _check_git_repo(self) -> bool:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                subprocess.run(
                    ['git', 'rev-parse', '--git-dir'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
            return True
        except:
            return False

    def _get_local_version(self) -> str:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            result = subprocess.run(
                ['git', 'describe', '--tags', '--abbrev=0'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2,
                env=env,
                cwd=self.repo_path
            )
            if result.returncode == 0:
                return result.stdout.strip().lstrip('v')
            return self.current_version
        except:
            return self.current_version

    def _detect_default_branch(self) -> Optional[str]:
        if not self.is_git_repo:
            return None
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
                return result.stdout.strip() or 'main'
        except:
            return 'main'

    def _get_remote_changes(self) -> Tuple[bool, str]:
        if not self.default_branch:
            return False, "Check skipped"
        env = os.environ.copy()
        env["GIT_ASKPASS"] = "echo"
        env["GIT_TERMINAL_PROMPT"] = "0"
        local_version = self._get_local_version()
        try:
            with open(os.devnull, 'w') as devnull:
                fetch_result = subprocess.run(
                    ['git', 'fetch', '--tags', 'origin'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
                if fetch_result.returncode != 0:
                    return False, "Check skipped"
        except:
            return False, "Check skipped"
        try:
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    ['git', 'describe', '--tags', '--abbrev=0', f'origin/{self.default_branch}'],
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
                remote_tag = result.stdout.strip()
                if not remote_tag:
                    return False, "Check skipped"
                remote_version = remote_tag.lstrip('v')
                if self._compare_versions(remote_version, local_version):
                    return True, remote_version
                else:
                    return False, local_version
        except:
            return False, "Check skipped"

    def _run_git_command(self, command: List[str]) -> Optional[str]:
        if not self.is_git_repo:
            return None
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            with open(os.devnull, 'w') as devnull:
                result = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=devnull,
                    text=True,
                    check=True,
                    timeout=2,
                    env=env,
                    cwd=self.repo_path
                )
            return result.stdout.strip()
        except:
            return None

    def _perform_update(self) -> Dict[str, Any]:
        if not self.default_branch:
            return {'status': 'error', 'message': 'No default branch detected'}
        if not self._run_git_command(['git', 'reset', '--hard', f'origin/{self.default_branch}']):
            return {'status': 'error', 'message': 'Update failed'}
        pull_output = self._run_git_command(['git', 'pull', '--force', 'origin', self.default_branch])
        if not pull_output:
            return {'status': 'error', 'message': 'Pull failed'}
        current_tag = self._run_git_command(['git', 'describe', '--tags', '--abbrev=0']) or self.current_version
        return {
            'status': 'success',
            'message': 'Update successful',
            'version': current_tag.lstrip('v'),
            'changes': pull_output,
            'updated': True
        }

    def check_and_update(self) -> Dict[str, Any]:
        if not self.is_git_repo:
            return {'status': 'error', 'message': 'Not a git repository'}
        has_changes, info = self._get_remote_changes()
        if info == "Check skipped":
            return {
                'status': 'success',
                'message': 'Check skipped',
                'version': self.current_version,
                'updated': False
            }
        elif not has_changes:
            return {
                'status': 'success',
                'message': 'Already at latest version',
                'version': self.current_version,
                'updated': False
            }
        update_result = self._perform_update()
        return update_result

    def _compare_versions(self, v1: str, v2: str) -> bool:
        def to_ints(v: str):
            return list(map(int, v.split('.')))
        return to_ints(v1) > to_ints(v2)

# ------------------------------------------------------------
# Main Configuration Class
# ------------------------------------------------------------
@dataclass
class Config:
    def __init__(self, args: argparse.Namespace) -> None:
        self.current_version = self._get_current_version_from_git() or "0.0.1"
        self.domain: Optional[str] = args.domain
        self.url_list: Optional[str] = args.url_list
        self.json_output: bool = args.json
        self.rate_limit: int = args.rate
        self.timeout: int = args.timeout * 1000
        self.max_workers: int = args.workers
        self.custom_headers_present: bool = False
        self.version_info: VersionInfo = self._check_version()
        self.additional_wait_time: int = 2

        custom_headers = {}
        self.custom_headers_present = False
        if args.header:
            self.custom_headers_present = True
            for header in args.header:
                if ':' in header:
                    key, value = header.split(':', 1)
                    custom_headers[key.strip()] = value.strip()
                else:
                    print(f"{Fore.RED}Invalid header format: {header}. Must be 'HeaderName: HeaderValue'{Style.RESET_ALL}")
                    sys.exit(1)
        self.headers = HeaderManager.get_headers(custom_headers)
        self.base_dir: Path = self._setup_base_directory()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.payload_file: Path = self._setup_payload_file(args.payloads)
        if not self.payload_file.exists():
            print(f"\n{Fore.RED}Error: Payload file not found: {self.payload_file}{Style.RESET_ALL}")
            sys.exit(1)
        self.output_file: Path = self._setup_output_file(args.output)

    def _get_current_version_from_git(self) -> Optional[str]:
        try:
            env = os.environ.copy()
            env["GIT_ASKPASS"] = "echo"
            env["GIT_TERMINAL_PROMPT"] = "0"
            result = subprocess.run(
                ['git', 'describe', '--tags', '--abbrev=0'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2,
                env=env,
                cwd=Path(__file__).parent
            )
            if result.returncode == 0:
                return result.stdout.strip().lstrip('v')
        except:
            pass
        return None

    def _check_version(self) -> VersionInfo:
        try:
            updater = AutoUpdater()
            if not updater.is_git_repo:
                return VersionInfo(
                    current=self.current_version,
                    update_available='Unknown (No Repository)'
                )
            has_changes, info = updater._get_remote_changes()
            if info == "Check skipped":
                return VersionInfo(
                    current=self.current_version,
                    update_available='Check skipped'
                )
            elif not has_changes:
                return VersionInfo(
                    current=self.current_version,
                    update_available='No'
                )
            else:
                return VersionInfo(
                    current=self.current_version,
                    update_available='Yes'
                )
        except Exception as e:
            logging.info(f"Update check: {str(e)}")
            return VersionInfo(
                current=self.current_version,
                update_available='Check Failed'
            )

    def _setup_base_directory(self) -> Path:
        if self.domain:
            parsed_domain = urlparse(self.domain).netloc or self.domain
            return Path(f"scans/{parsed_domain}")
        elif self.url_list:
            base_name = Path(self.url_list).stem
            return Path(f"scans/{base_name}")
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            return Path(f"scans/scan_{timestamp}")

    def _setup_payload_file(self, payload_path: Optional[str]) -> Path:
        return Path(payload_path) if payload_path else Path(__file__).parent / "redirect_payloads.txt"

    def _setup_output_file(self, output_path: Optional[str]) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if output_path:
            path = Path(output_path)
            suffix = '.json' if self.json_output else '.txt'
            return path.parent / f"{path.stem}_{timestamp}{suffix}"
        if self.json_output:
            return self.base_dir / f"redirect_results_{timestamp}.json"
        return self.base_dir / f"redirect_results_{timestamp}.txt"

# ------------------------------------------------------------
# Tqdm Wrapper to Safely Display Progress
# ------------------------------------------------------------
class TqdmSafe(tqdm):
    def display(self, msg=None, pos=None):
        try:
            super().display(msg, pos)
        except (BrokenPipeError, EOFError, ValueError):
            pass

    def close(self):
        try:
            super().close()
        except (BrokenPipeError, EOFError, ValueError):
            pass

    def update(self, n=1):
        try:
            super().update(n)
        except (BrokenPipeError, EOFError, ValueError):
            pass

    def write(self, msg, file=None):
        try:
            super().write(msg, file)
        except (BrokenPipeError, EOFError, ValueError):
            pass

# ------------------------------------------------------------
# Page Pool Management
# ------------------------------------------------------------
class PagePool:
    def __init__(self, context: BrowserContext, size: int = 5):
        self.context = context
        self.size = size
        self.pages: asyncio.Queue[Page] = asyncio.Queue(maxsize=size)

    async def initialize(self):
        for _ in range(self.size):
            page = await self.context.new_page()
            await self.pages.put(page)

    async def get_page(self) -> Page:
        return await self.pages.get()

    async def return_page(self, page: Page):
        await self.pages.put(page)

    async def cleanup(self):
        while not self.pages.empty():
            try:
                page = await self.pages.get_nowait()
                await page.close()
            except:
                pass

# ------------------------------------------------------------
# Parameter Handler
# ------------------------------------------------------------
class ParameterHandler:
    @staticmethod
    def has_parameters(url: str) -> bool:
        try:
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query, keep_blank_values=True)
            return bool(params)
        except Exception:
            return False

    @staticmethod
    def validate_parameter_length(param: str, value: str) -> bool:
        return (len(param) + len(value)) <= MAX_PARAM_LENGTH

    @staticmethod
    def get_parameters(url: str) -> Dict[str, List[str]]:
        try:
            parsed = urlparse(url)
            return parse_qs(parsed.query, keep_blank_values=True)
        except Exception:
            return {}

# ------------------------------------------------------------
# Redirect Scanner
# ------------------------------------------------------------
class RedirectScanner:
    def __init__(self, config: Config) -> None:
        self.config: Config = config
        self.stats: Dict[str, int] = {
            'total_urls': 0,
            'total_parameters': 0,
            'total_payloads': 0,
            'successful_payloads': 0,
            'errors': 0,
            'current_test': 0,
            'total_tests': 0
        }
        self.progress_lock: asyncio.Lock = asyncio.Lock()
        self.results_lock: asyncio.Lock = asyncio.Lock()
        self.print_lock: asyncio.Lock = asyncio.Lock()
        self.results: List[str] = []
        self.json_results: List[Dict[str, Any]] = []
        self.discovered_vulnerabilities: Set[Tuple[str, str]] = set()
        self.processed_urls: Set[str] = set()
        self.failed_urls: Set[str] = set()
        self.domain_cache: Dict[str, str] = {}
        self.start_time: Optional[float] = None
        self.running: bool = True
        self.pbar: Optional[TqdmSafe] = None
        self.playwright: Optional[Any] = None
        self.browser: Optional[Browser] = None
        self.rate_limiter: asyncio.Semaphore = asyncio.Semaphore(self.config.rate_limit)
        self.connection_pool: asyncio.Semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)
        self.context_pool: List[BrowserContext] = []
        self.max_contexts: int = min(config.max_workers, 10)
        self.page_pools: List[PagePool] = []
        self.cached_payloads: Optional[List[str]] = None

    def get_cached_domain(self, url: str) -> str:
        if url not in self.domain_cache:
            parsed = urlparse(url)
            self.domain_cache[url] = parsed.hostname or ""
        return self.domain_cache[url]

    async def initialize_browser_pool(self) -> None:
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
        )
        for _ in range(self.max_contexts):
            context = await self.browser.new_context(
                extra_http_headers=self.config.headers,
                viewport={'width': 1280, 'height': 800},
                user_agent=self.config.headers.get('User-Agent'),
                ignore_https_errors=True
            )
            pool = PagePool(context, size=5)
            await pool.initialize()
            self.page_pools.append(pool)
            self.context_pool.append(context)

    async def rate_limit(self) -> None:
        async with self.rate_limiter:
            await asyncio.sleep(1.0 / self.config.rate_limit)

    async def validate_redirection(self, page: Page, url: str) -> Tuple[bool, Optional[str]]:
        if not self.running or url in self.failed_urls:
            return False, None
        try:
            initial_url = url
            initial_registered_domain = self.get_cached_domain(initial_url)
            await page.goto(
                url,
                timeout=self.config.timeout,
                wait_until='networkidle',
                referer=self.config.headers.get('Referer', 'https://www.google.com')
            )
            final_url = page.url
            if final_url != initial_url:
                final_registered_domain = self.get_cached_domain(final_url)
                if initial_registered_domain != final_registered_domain:
                    return True, final_url
        except PlaywrightError:
            self.failed_urls.add(url)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.failed_urls.add(url)
        return False, None

    async def _handle_vulnerability(
        self,
        url: str,
        param: str,
        line_num: int,
        payloaded_url: str,
        final_url: str
    ) -> None:
        hostname = self.get_cached_domain(url)
        output = (
            f"{Fore.GREEN}🎯 Open Redirect Found!{Style.RESET_ALL}  "
            f"Domain: {Fore.YELLOW}{hostname}{Style.RESET_ALL}  |  "
            f"Parameter: {Fore.YELLOW}{param}{Style.RESET_ALL}  |  "
            f"Payload #{Fore.YELLOW}{line_num}{Style.RESET_ALL}"
        )
        async with self.results_lock:
            self.results.append("Open redirect found:")
            self.results.append(f"Domain: {hostname}")
            self.results.append(f"Parameter: {param}")
            self.results.append(f"Payload: #{line_num}")
            self.results.append(f"Redirected to: {final_url}")
            self.results.append(f"Url with payload: {payloaded_url}")
            self.results.append("")
            self.json_results.append({
                "hostname": hostname,
                "parameter": param,
                "payload_number": line_num,
                "redirected_to": final_url,
                "url_with_payload": payloaded_url
            })
            self.stats['successful_payloads'] += 1
            if self.running and self.pbar:
                async with self.print_lock:
                    self.pbar.write(output)

    async def process_url(self, url: str, payloads: List[str]) -> None:
        if not self.running or url in self.processed_urls:
            return
        is_valid, error = URLValidator.validate_url(url)
        if not is_valid:
            logging.error(f"Invalid URL skipped - {url}: {error}")
            return
        url = URLValidator.normalize_url(url)
        hostname = self.get_cached_domain(url)
        await self.connection_pool.acquire()
        try:
            pool = self.page_pools[hash(url) % len(self.page_pools)]
            page = await pool.get_page()
            try:
                payloaded_urls = self.construct_payloaded_urls(url, payloads)
                for param, payloaded_url, line_num in payloaded_urls:
                    if not self.running:
                        break
                    if (hostname, param) in self.discovered_vulnerabilities:
                        async with self.progress_lock:
                            self.stats['current_test'] += 1
                            if self.running and self.pbar:
                                self.pbar.update(1)
                        continue
                    await self.rate_limit()
                    try:
                        is_redirect, final_url = await self.validate_redirection(page, payloaded_url)
                        if is_redirect and final_url:
                            await self._handle_vulnerability(url, param, line_num, payloaded_url, final_url)
                            self.discovered_vulnerabilities.add((hostname, param))
                        async with self.progress_lock:
                            self.stats['current_test'] += 1
                            if self.running and self.pbar:
                                self.pbar.update(1)
                    except asyncio.CancelledError:
                        raise
                    except PlaywrightError as e:
                        async with self.progress_lock:
                            self.stats['errors'] += 1
                        logging.error(f"Playwright error payload {line_num} URL {url}: {str(e)}")
                    except Exception as e:
                        async with self.progress_lock:
                            self.stats['errors'] += 1
                        logging.error(f"Error payload {line_num} URL {url}: {str(e)}")
            finally:
                await pool.return_page(page)
        except asyncio.CancelledError:
            raise
        except PlaywrightError as e:
            logging.error(f"Playwright error URL {url}: {str(e)}")
        except Exception as e:
            logging.error(f"Error URL {url}: {str(e)}")
        finally:
            self.connection_pool.release()
            self.processed_urls.add(url)

    def construct_payloaded_urls(self, base_url: str, payloads: List[str]) -> List[Tuple[str, str, int]]:
        parsed_url = urlparse(base_url)
        query_params = parse_qs(parsed_url.query, keep_blank_values=True)
        if not query_params:
            return []
        payloaded_urls: List[Tuple[str, str, int]] = []
        for line_num, payload in enumerate(payloads, start=1):
            for key in query_params:
                modified_params = query_params.copy()
                modified_params[key] = [payload]
                new_query = urlencode(modified_params, doseq=True, safe='/:?=&%')
                new_url = parsed_url._replace(query=new_query).geturl()
                payloaded_urls.append((key, new_url, line_num))
        return payloaded_urls

    def calculate_total_tests(self, urls: List[str], payloads: List[str]) -> int:
        total_params = 0
        total_tests = 0
        for url in urls:
            try:
                parsed_url = urlparse(url)
                params = parse_qs(parsed_url.query, keep_blank_values=True)
                num_params = len(params)
                if num_params > 0:
                    total_params += num_params
                    total_tests += num_params * len(payloads)
            except Exception:
                continue
        self.stats['total_parameters'] = total_params
        return max(1, total_tests)

    async def process_url_batch(self, urls: List[str], batch_size: int = 5) -> None:
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i + batch_size]
            tasks = []
            for url in batch:
                if not self.running:
                    break
                if self.cached_payloads is None:
                    self.cached_payloads = await load_file_async(str(self.config.payload_file))
                task = asyncio.create_task(self.process_url(url, self.cached_payloads))
                tasks.append(task)
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        logging.error(f"Batch processing error: {str(result)}")

    def stop(self) -> None:
        self.running = False

    def _save_results(self, duration: float, minutes: int, seconds: int) -> None:
        if self.config.json_output and self.json_results:
            output_data = {
                "scan_summary": {
                    "duration_seconds": int(duration),
                    "duration_minutes": minutes,
                    "total_urls_tested": self.stats['total_urls'],
                    "total_parameters_tested": self.stats['total_parameters'],
                    "total_payloads_per_parameter": self.stats['total_payloads'],
                    "total_tests_performed": self.stats['total_tests'],
                    "successful_redirects": self.stats['successful_payloads'],
                },
                "vulnerabilities_found": self.json_results
            }
            try:
                with open(self.config.output_file, "w") as f:
                    json.dump(output_data, f, indent=4)
                print(f"\n{Fore.CYAN}📝 Results saved to:{Style.RESET_ALL} {Fore.GREEN}{os.path.abspath(self.config.output_file)}{Style.RESET_ALL}")
            except Exception as e:
                print(f"\n{Fore.RED}Error saving JSON results: {e}{Style.RESET_ALL}")
        elif not self.config.json_output and self.results:
            try:
                with open(self.config.output_file, "w") as f:
                    f.write("\n".join(self.results))
                print(f"\n{Fore.CYAN}📝 Results saved to:{Style.RESET_ALL} {Fore.GREEN}{os.path.abspath(self.config.output_file)}{Style.RESET_ALL}")
            except Exception as e:
                print(f"\n{Fore.RED}Error saving text results: {e}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}No vulnerabilities found.{Style.RESET_ALL}")

    def print_final_stats(self) -> None:
        if self.start_time:
            duration = time.time() - self.start_time
            minutes, seconds = divmod(int(duration), 60)
            print(f"\n{Fore.CYAN}🏁 Scan Complete! Summary:{Style.RESET_ALL}")
            print("="*30)
            print(f"Duration: {Fore.GREEN}{minutes}m {seconds}s{Style.RESET_ALL}")
            print(f"URLs tested: {Fore.GREEN}{self.stats['total_urls']}{Style.RESET_ALL}")
            print(f"Parameters tested: {Fore.GREEN}{self.stats['total_parameters']}{Style.RESET_ALL}")
            print(f"Payloads/parameter: {Fore.GREEN}{self.stats['total_payloads']}{Style.RESET_ALL}")
            print(f"Tests performed: {Fore.GREEN}{self.stats['total_tests']}{Style.RESET_ALL}")
            print(f"Successful redirects: {Fore.GREEN}{self.stats['successful_payloads']}{Style.RESET_ALL}")
            print("="*30)
            self._save_results(duration, minutes, seconds)

# ------------------------------------------------------------
# Banner Printing
# ------------------------------------------------------------
def print_banner(config: Config, playwright_version: str, urls_count: int = 0, payloads_count: int = 0) -> None:
    logo_width = 86
    author_text = "By Dimitris Chatzidimitris"
    email_text = "Email: dimitris.chatzidimitris@gmail.com"
    features_text = "Async I/O / 100% Valid Results / Bypasses Cloud/WAF"
    centered_author = author_text.center(logo_width)
    centered_email = email_text.center(logo_width)
    centered_features = features_text.center(logo_width)
    headers_display = "Yes" if config.custom_headers_present else "Default"
    banner = f"""
{Fore.YELLOW}██████╗ ██████╗ ███████╗██████╗ ██╗██████╗ ███████╗ ██████╗████████╗███╗   ███╗███████╗
██╔═══██╗██╔══██╗██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔════╝╚══██╔══╝████╗ ████║██╔════╝
██║   ██║██████╔╝█████╗  ██║  ██║██║██████╔╝█████╗  ██║        ██║   ██╔████╔██║█████╗  
██║   ██║██╔══██╗██╔══╝  ██║  ██║██║██╔══██╗██╔══╝  ██║        ██║   ██║╚██╔╝██║██╔══╝  
██████╔╝██║  ██║███████╗██████╔╝██║██║  ██║███████╗╚██████╗   ██║   ██║ ╚═╝ ██║███████╗
╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝   ╚═╝   ╚═╝     ╚═╝╚══════╝{Style.RESET_ALL}

{Fore.YELLOW}{centered_author}
{centered_email}
{centered_features}{Style.RESET_ALL}

{Fore.CYAN}🔧Configuration:{Style.RESET_ALL}
- Version: {Fore.GREEN}{config.current_version}{Style.RESET_ALL}
- Update Available: {Fore.GREEN}{config.version_info.update_available}{Style.RESET_ALL}
- Max Workers: {Fore.GREEN}{config.max_workers}{Style.RESET_ALL}
- Timeout: {Fore.GREEN}{int(config.timeout/1000)}s{Style.RESET_ALL}
- Rate Limit: {Fore.GREEN}{config.rate_limit} req/s{Style.RESET_ALL}
- Playwright Version: {Fore.GREEN}{playwright_version}{Style.RESET_ALL}
- Payloads File: {Fore.GREEN}{config.payload_file}{Style.RESET_ALL}
- Custom Headers: {Fore.GREEN}{headers_display}{Style.RESET_ALL}
- Output Format: {Fore.GREEN}{'JSON' if config.json_output else 'Text'}{Style.RESET_ALL}
- Output File: {Fore.GREEN}{os.path.abspath(config.output_file)}{Style.RESET_ALL}

📦 {Fore.CYAN}Loading URLs...{Style.RESET_ALL}
🔗 {Fore.GREEN}Loaded: {urls_count} URLs and {payloads_count} payloads{Style.RESET_ALL}
🔍 {Fore.YELLOW}Starting scan...{Style.RESET_ALL}
"""
    print(banner)

# ------------------------------------------------------------
# Setup and Cleanup Functions
# ------------------------------------------------------------
async def setup_scanner(scanner: RedirectScanner) -> None:
    try:
        await scanner.initialize_browser_pool()
    except Exception as e:
        logging.error(f"Failed to initialize scanner: {str(e)}")
        raise

async def cleanup_scanner(scanner: RedirectScanner) -> None:
    cleanup_logger = logging.getLogger('cleanup')
    cleanup_logger.addHandler(logging.FileHandler('logs/cleanup.log'))
    cleanup_logger.setLevel(logging.ERROR)
    page_pool_tasks = []
    if scanner.page_pools:
        for pool in scanner.page_pools:
            try:
                page_pool_tasks.append(pool.cleanup())
            except Exception:
                pass
    if page_pool_tasks:
        try:
            await asyncio.wait_for(
                asyncio.gather(*page_pool_tasks, return_exceptions=True),
                timeout=1
            )
        except (asyncio.TimeoutError, PlaywrightError):
            pass
        except Exception as e:
            cleanup_logger.error(f"Page pool cleanup error: {str(e)}")
    context_tasks = []
    if scanner.context_pool:
        for context in scanner.context_pool:
            try:
                context_tasks.append(context.close())
            except Exception:
                pass
    if context_tasks:
        try:
            await asyncio.wait_for(
                asyncio.gather(*context_tasks, return_exceptions=True), 
                timeout=1
            )
        except (asyncio.TimeoutError, PlaywrightError):
            pass
        except Exception as e:
            cleanup_logger.error(f"Context cleanup error: {str(e)}")
    if scanner.browser:
        try:
            await asyncio.wait_for(scanner.browser.close(), timeout=1)
        except (asyncio.TimeoutError, PlaywrightError):
            pass
        except Exception as e:
            cleanup_logger.error(f"Browser cleanup error: {str(e)}")
    if scanner.playwright:
        try:
            await asyncio.wait_for(scanner.playwright.stop(), timeout=1)
        except (asyncio.TimeoutError, PlaywrightError):
            pass
        except Exception as e:
            cleanup_logger.error(f"Playwright cleanup error: {str(e)}")

# ------------------------------------------------------------
# Main Scanning Logic
# ------------------------------------------------------------
async def run_scan(scanner: RedirectScanner, urls: List[str], payloads: List[str]) -> None:
    try:
        urls = filter_urls(urls)
        if not urls:
            print(f"\n{Fore.YELLOW}No valid URLs with parameters found to scan.{Style.RESET_ALL}")
            return
        scanner.stats['total_urls'] = len(urls)
        scanner.stats['total_payloads'] = len(payloads)
        scanner.stats['total_tests'] = scanner.calculate_total_tests(urls, payloads)
        scanner.pbar = TqdmSafe(
            total=scanner.stats['total_tests'],
            desc='Progress',
            unit='Payload',
            unit_scale=False,
            leave=True,
            dynamic_ncols=True,
            colour='yellow',
            bar_format=(
                '{l_bar}{bar}| [{n_fmt}/{total_fmt} Payloads] '
                '[Time:{elapsed} Est:{remaining}] [{rate_fmt}]'
            )
        )
        batch_size = min(scanner.config.max_workers, 5)
        await scanner.process_url_batch(urls, batch_size)
    except asyncio.CancelledError:
        scanner.stop()
        raise
    except Exception as e:
        logging.error(f"Error during scan: {str(e)}")
        scanner.stop()
        raise
    finally:
        if scanner.pbar:
            scanner.pbar.close()
            scanner.pbar = None

def handle_exception(loop, context):
    exception = context.get('exception')
    if isinstance(exception, (PlaywrightError, asyncio.CancelledError)):
        return
    msg = context.get("message")
    if "Target page, context or browser has been closed" in str(msg):
        return
    try:
        logging.error(f"Unhandled exception: {msg}")
    except Exception as e:
        print(f"{Fore.RED}Error in exception handler: {e}{Style.RESET_ALL}")

warnings.filterwarnings("ignore", message="There is no current event loop")
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
loop.set_exception_handler(handle_exception)

# ------------------------------------------------------------
# Main Async Entry Point
# ------------------------------------------------------------
async def main_async() -> None:
    check_playwright_version_installed()
    args = parse_arguments()
    config = Config(args)
    setup_logging(config)
    logging.captureWarnings(True)
    if args.update:
        git_handler = GitHandler()
        if not git_handler.ensure_git_available():
            print(f"\n{Fore.RED}Cannot perform update without Git installed.{Style.RESET_ALL}")
            sys.exit(1)
        print(f"\n{Fore.CYAN}Checking for updates...{Style.RESET_ALL}")
        updater = AutoUpdater()
        update_result = updater.check_and_update()
        if update_result.get('status') == 'error':
            print(f"{Fore.RED}Update failed: {update_result.get('message')}{Style.RESET_ALL}")
            sys.exit(1)
        elif update_result.get('updated'):
            print(f"{Fore.GREEN}Tool updated successfully!{Style.RESET_ALL}")
            print(f"New version: {update_result.get('version')}")
            print(f"{Fore.YELLOW}Please restart the tool...{Style.RESET_ALL}")
            sys.exit(0)
        else:
            if update_result.get('message') == "Check skipped":
                print(f"{Fore.YELLOW}Update check skipped - Repository not accessible{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}Already at latest version{Style.RESET_ALL}")
            sys.exit(0)
    playwright_version = get_playwright_version()
    scanner = RedirectScanner(config)
    try:
        await setup_scanner(scanner)
        if scanner.config.url_list:
            urls = await load_file_async(scanner.config.url_list)
        else:
            urls = [scanner.config.domain]
        payloads = await load_file_async(str(scanner.config.payload_file))
        print_banner(config, playwright_version, urls_count=len(urls), payloads_count=len(payloads))
        scanner.start_time = time.time()
        scan_task = asyncio.create_task(run_scan(scanner, urls, payloads))
        await scan_task
    except asyncio.CancelledError:
        print(f"\n{Fore.YELLOW}🚫 Scan interrupted by user{Style.RESET_ALL}")
        scanner.stop()
        if scanner.pbar:
            scanner.pbar.close()
            scanner.pbar = None
        pending = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
        if pending:
            for task in pending:
                task.cancel()
            try:
                await asyncio.wait(pending, timeout=1)
            except:
                pass
    except Exception as e:
        print(f"\n{Fore.RED}Error during scan: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Error during scan: {str(e)}")
        scanner.stop()
    finally:
        try:
            await asyncio.shield(cleanup_scanner(scanner))
        except:
            pass
        try:
            scanner.print_final_stats()
        except:
            pass

# ------------------------------------------------------------
# Main Entry Point
# ------------------------------------------------------------
def main() -> None:
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.set_exception_handler(handle_exception)
        loop.run_until_complete(main_async())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}🚫 Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")
        logging.error(f"Unexpected error: {str(e)}")
    finally:
        try:
            loop.close()
        except:
            pass
        sys.exit(0)

if __name__ == "__main__":
    main()
