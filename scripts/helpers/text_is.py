from colorama import Fore, Style
from colorama import just_fix_windows_console

just_fix_windows_console()

def notice(message: str) -> str:
  return f'{Fore.YELLOW}{Style.DIM}{message}{Style.RESET_ALL}'


def success(message: str) -> str:
  return f'{Fore.GREEN}{message}{Style.RESET_ALL}'


def warning(message: str) -> str:
  return f'{Fore.YELLOW}{message}{Style.RESET_ALL}'


def error(message: str) -> str:
  return f'{Fore.RED}{message}{Style.RESET_ALL}'
