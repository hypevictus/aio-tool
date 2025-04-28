import datetime, os
from colorama import Fore, Style

os.system("")


def inp(level: str, content: str = "", extra: dict = {}):
    # level = '[?]'
    message = f"\x1b[0m\x1b[38;5;239m{datetime.datetime.now().strftime('%I:%M:%S %p')} \x1b[38;5;14m{level}\u001B[0m {content}\x1b[0m"
    fields = []
    for key, value in extra.items():
        fields.append(f"\u001B[38;5;239m{key}=\u001B[0m{value}")
    if fields:
        message += " " + " ".join(fields)

    print(message, end='')


def info(level: str, content: str = "", extra: dict = {}):
    # level = '[+]'
    message = f"\x1b[0m\x1b[38;5;239m{datetime.datetime.now().strftime('%I:%M:%S %p')} \x1b[38;5;120m{level}\u001B[0m {content}\x1b[0m"
    fields = []
    for key, value in extra.items():
        fields.append(f"\u001B[38;5;239m{key}=\u001B[0m{value}")
    if fields:
        message += " " + " ".join(fields)

    print(message)


def debug(level: str, content: str = "", extra: dict = {}):
    # level = '[-]'
    message = f"\x1b[0m\x1b[38;5;239m{datetime.datetime.now().strftime('%I:%M:%S %p')} \x1b[38;5;221m{level}\u001B[0m {content}\x1b[0m"
    fields = []
    for key, value in extra.items():
        fields.append(f"\u001B[38;5;239m{key}=\u001B[0m{value}")
    if fields:
        message += " " + " ".join(fields)

    print(message)


def error(level: str, content: str = "", extra: dict = {}):
    # level = '[!]'
    message = f"\x1b[0m\x1b[38;5;239m{datetime.datetime.now().strftime('%I:%M:%S %p')} \x1b[38;5;203m{level}\u001B[0m {content}\x1b[0m"
    fields = []
    for key, value in extra.items():
        fields.append(f"\u001B[38;5;239m{key}=\u001B[0m{value}")
    if fields:
        message += " " + " ".join(fields)

    print(message)


def log(color, level: str, content: str = "", extra: dict = {}):
    # level = '[!]'
    message = f"\x1b[0m\x1b[38;5;239m{datetime.datetime.now().strftime('%I:%M:%S %p')} {color}{level}\u001B[0m {content}\x1b[0m"
    fields = []
    for key, value in extra.items():
        fields.append(f"\u001B[38;5;239m{key}=\u001B[0m{value}")
    if fields:
        message += " " + " ".join(fields)

    print(message)
