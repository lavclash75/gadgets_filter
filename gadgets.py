#!/usr/bin/env python3
"""
rop_search.py  -  Standalone ROP gadget searcher (rp++ output)
No external dependencies — stdlib Python 3 only.

By default shows the best gadget (shortest) per category,
same as the original Gadgetizer but without ropper or any other lib.

Quick usage:
    python3 rop_search.py -f gadgets.txt              # best gadget per category
    python3 rop_search.py -f gadgets.txt -A            # ALL gadgets per category
    python3 rop_search.py -f gadgets.txt -s "pop eax"  # free search
    python3 rop_search.py -f gadgets.txt -c pop -c xor # specific categories
    python3 rop_search.py -f gadgets.txt --stats       # statistical summary
"""

import re
import sys
import argparse
import platform
from pathlib import Path


def _setup_colors() -> bool:
    if not sys.stdout.isatty():
        return False

    if platform.system() == 'Windows':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(handle, ctypes.byref(mode))
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
            return True
        except Exception:
            return False

    return True


class C:
    RESET  = "\033[0m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    BLUE   = "\033[94m"
    RED    = "\033[91m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    WHITE  = "\033[97m"

    @classmethod
    def disable(cls):
        for attr in list(vars(cls)):
            if not attr.startswith('_') and isinstance(getattr(cls, attr), str):
                setattr(cls, attr, '')


def _can_unicode() -> bool:
    if platform.system() == 'Windows':
        try:
            import ctypes
            cp = ctypes.windll.kernel32.GetConsoleOutputCP()
            return cp == 65001
        except Exception:
            return False
    enc = getattr(sys.stdout, 'encoding', '') or ''
    return enc.lower().replace('-', '') in ('utf8', 'utf16', 'utf32')


_UNICODE = _can_unicode()


def _B():
    if _UNICODE:
        return '┌', '─', '┐', '│', '└', '┘'
    else:
        return '+', '-', '+', '|', '+', '+'


def banner(title: str, count: int):
    tl, h, tr, v, bl, br = _B()
    label = f"  {title}  "
    bar   = h * len(label)
    cnt   = f"{C.DIM}({count}){C.RESET}" if count else f"{C.RED}(none){C.RESET}"
    print(f"\n{C.YELLOW}{C.BOLD}{tl}{bar}{tr}{C.RESET}")
    print(f"{C.YELLOW}{C.BOLD}{v}{label}{v}{C.RESET}  {cnt}")
    print(f"{C.YELLOW}{C.BOLD}{bl}{bar}{br}{C.RESET}")


def print_gadget(line: str):
    parts = line.split('  #', 1)
    if len(parts) == 2:
        addr, instr = parts
        print(f"  {C.CYAN}{addr}{C.RESET}  #{C.DIM}{instr}{C.RESET}")
    else:
        print(f"  {C.DIM}{line}{C.RESET}")


def no_results():
    print(f"  {C.DIM}  — no gadgets found —{C.RESET}")


_RE_ADDR    = re.compile(r'^(0x[0-9a-fA-F]+)\s*[:|]\s*')
_RE_SPACES  = re.compile(r'[ \t]{2,}')
_RE_SP_SEMI = re.compile(r'[ \t]+;')
_RE_FOUND   = re.compile(r'\s*\(\d+ found\)\s*$')
_RE_RET_BIG = re.compile(r'ret 0x[0-9a-fA-F]{3,};')


def normalize(line: str) -> str:
    line = line.strip()
    if not line:
        return ''

    m = _RE_ADDR.match(line)
    if not m:
        return ''

    addr = m.group(1)
    rest = line[m.end():]

    rest = _RE_FOUND.sub('', rest)
    rest = _RE_SPACES.sub(' ', rest)
    rest = _RE_SP_SEMI.sub(';', rest)
    rest = rest.strip()

    if rest and not rest.endswith(';'):
        rest += ';'

    normalized = f"{addr}  # {rest}"

    if _RE_RET_BIG.search(normalized):
        return ''

    return normalized


def load_gadgets(filepath: str) -> list:
    path = Path(filepath)
    if not path.exists():
        print(f"{C.RED}[!] File not found: {filepath}{C.RESET}", file=sys.stderr)
        sys.exit(1)

    gadgets = []
    with open(path, 'r', errors='replace') as fh:
        for raw in fh:
            n = normalize(raw)
            if n:
                gadgets.append(n)

    return gadgets


def search(gadgets: list, pattern: str) -> list:
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        print(f"{C.RED}[!] Invalid regex '{pattern}': {e}{C.RESET}", file=sys.stderr)
        return []
    return [g for g in gadgets if rx.search(g)]


def best_gadgets(gadgets: list, patterns: list, top: int = 1,
                 exclude: list = None) -> list:
    excl_rx = [re.compile(p, re.IGNORECASE) for p in (exclude or [])]

    seen = set()
    hits = []
    for pat in patterns:
        for g in search(gadgets, pat):
            if g in seen:
                continue
            if any(rx.search(g) for rx in excl_rx):
                continue
            seen.add(g)
            hits.append(g)

    hits.sort(key=lambda x: len(x.split('  #', 1)[-1]))
    return hits[:top] if top > 0 else hits


_SZ  = r'(?:(?:dword|word|byte|qword|tbyte)(?:\s+ptr)?\s+)?(?:[a-z]s:)?'
_MEM = r'\[\s*\w+(?:\s*[\+\-\*]\s*[\w0-9xa-fA-F]+)*\s*\]'


def _mem_dst(size_prefix=True) -> str:
    sz = _SZ if size_prefix else ''
    return fr'{sz}{_MEM}'


def _mem_src(size_prefix=True) -> str:
    sz = _SZ if size_prefix else ''
    return fr'{sz}{_MEM}'


def get_categories(rp: str) -> dict:
    ra   = f'{rp}..'
    sp   = f'{rp}sp'
    regs = [f'{rp}ax', f'{rp}bx', f'{rp}cx', f'{rp}dx', f'{rp}si', f'{rp}di']
    imm  = r'0x[0-9a-fA-F]+'

    zero_pats = []
    for reg in regs:
        zero_pats += [
            fr'xor\s+{reg},\s*{reg};',
            fr'sub\s+{reg},\s*{reg};',
            fr'(?:mov|and|lea)\s+{reg},\s*0x?0*;',
        ]

    eip_esp = [
        fr'(?:jmp|call)\s+{sp};',
        r'leave;',
        fr'mov\s+{sp},\s*{ra};',
        fr'xchg\s+{sp},\s*{ra};',
    ]
    for reg in regs:
        eip_esp += [
            fr'xchg\s+{sp},\s*{reg};\s*(?:jmp|call)\s+{reg};',
        ]

    return {
        "write-what-where": [
            fr'mov\s+{_SZ}{_MEM},\s*{ra};',
            fr'mov\s+{_SZ}{_MEM},\s*[a-z]{{2,3}};',
        ],
        "pointer-deref": [
            fr'mov\s+{ra},\s*{_SZ}{_MEM};',
        ],
        "swap-register": [
            fr'mov\s+{ra},\s*{ra};',
            fr'xchg\s+{ra},\s*{ra};',
            fr'push\s+{ra};\s*pop\s+{ra};',
        ],
        "pop": [
            fr'pop\s+{ra};',
        ],
        "push": [
            fr'push\s+{ra};',
            fr'push\s+{_SZ}{_MEM};',
        ],
        "pushad": [
            r'pushad;',
            r'pusha;',
        ],
        "push-pop chain": [
            fr'push\s+{ra};.*?pop\s+{ra};',
        ],
        "increment": [
            fr'inc\s+{ra};',
            fr'inc\s+{_SZ}{_MEM};',
            fr'add\s+{ra},\s*0x0*1;',
        ],
        "decrement": [
            fr'dec\s+{ra};',
            fr'dec\s+{_SZ}{_MEM};',
            fr'sub\s+{ra},\s*0x0*1;',
        ],
        "add": [
            fr'add\s+{ra},\s*(?:{ra}|{imm});',
            fr'add\s+{_SZ}{_MEM},\s*{ra};',
            fr'lea\s+{ra},\s*\[{ra}\s*\+\s*{ra}\];',
        ],
        "subtract": [
            fr'sub\s+{ra},\s*(?:{ra}|{imm});',
            fr'sbb\s+{ra},\s*(?:{ra}|{imm});',
        ],
        "negate": [
            fr'neg\s+{ra};',
            fr'not\s+{ra};',
            fr'not\s+{_SZ}{_MEM};',
        ],
        "xor": [
            fr'xor\s+{ra},\s*(?:{ra}|{imm});',
            fr'xor\s+{_SZ}{_MEM},\s*(?:{ra}|{imm});',
        ],
        "and": [
            fr'and\s+{ra},\s*(?:{ra}|{imm});',
            fr'and\s+{_SZ}{_MEM},\s*(?:{ra}|{imm});',
            fr'test\s+{ra},\s*{ra};',
        ],
        "or": [
            fr'(?<![a-z])or\s+{ra},\s*(?:{ra}|{imm});',
            fr'(?<![a-z])or\s+{_SZ}{_MEM},\s*(?:{ra}|{imm});',
        ],
        "shift": [
            fr'(?:shl|shr|sar|sal)\s+{ra},\s*(?:cl|{imm});',
            fr'(?:ror|rol)\s+{ra},\s*(?:cl|{imm});',
            fr'(?:rcr|rcl)\s+{ra},\s*(?:cl|{imm});',
        ],
        "zeroize": zero_pats,
        "eip-to-esp": eip_esp,
        "rop-nop": [
            fr'xchg\s+({"|".join(regs)}),\s*\1;',
            r'(?:nop|xchg\s+eax,\s*eax);.*?ret;',
        ],
    }


def get_exclusions() -> dict:
    return {
        "write-what-where": [
            r'mov\s+\w*\s*\[e[sb]p',
        ],
        "pointer-deref": [
            r'mov\s+\w+,\s*\w*\s*\[e[sb]p\b(?!\+0x[0-9a-fA-F]{3,})',
        ],
    }


def show_categorized(gadgets: list, categories: dict, top: int = 1):
    excls = get_exclusions()
    total_with_hits = 0
    total_shown     = 0

    for name, patterns in categories.items():
        exclude = excls.get(name, [])
        hits = best_gadgets(gadgets, patterns, top=top, exclude=exclude)

        if not hits and top > 0:
            hits = best_gadgets(gadgets, patterns, top=top)

        banner(name, len(hits))
        if hits:
            for g in hits:
                print_gadget(g)
            total_with_hits += 1
            total_shown     += len(hits)
        else:
            no_results()

    label_top = "all" if top == 0 else f"top-{top}"
    print(f"\n{C.GREEN}[+]{C.RESET} {total_shown} gadgets ({label_top}) "
          f"in {total_with_hits}/{len(categories)} categories\n")


def show_search(gadgets: list, pattern: str):
    hits = search(gadgets, pattern)
    hits.sort(key=lambda x: len(x.split('  #', 1)[-1]))
    banner(f"search: {pattern}", len(hits))
    if hits:
        for g in hits:
            print_gadget(g)
        print(f"\n{C.GREEN}[+]{C.RESET} {len(hits)} results\n")
    else:
        no_results()
        print()


def show_stats(gadgets: list, categories: dict):
    _, h, *_ = _B()
    line = h * 36
    print(f"\n{C.BOLD}{'Category':<24}  {'Gadgets':>8}{C.RESET}")
    print(line)
    for name, patterns in categories.items():
        hits = best_gadgets(gadgets, patterns, top=0)
        color = C.GREEN if hits else C.DIM
        print(f"  {color}{name:<24}{C.RESET}  {len(hits):>6}")
    print(line)
    print(f"  {'Total gadgets in file':<24}  {len(gadgets):>6}\n")


CATEGORY_FLAGS = {
    'write':    'write-what-where',
    'deref':    'pointer-deref',
    'swap':     'swap-register',
    'pop':      'pop',
    'push':     'push',
    'pushad':   'pushad',
    'pushpop':  'push-pop chain',
    'inc':      'increment',
    'dec':      'decrement',
    'add':      'add',
    'sub':      'subtract',
    'neg':      'negate',
    'xor':      'xor',
    'and':      'and',
    'or':       'or',
    'shift':    'shift',
    'zero':     'zeroize',
    'pivot':    'eip-to-esp',
    'nop':      'rop-nop',
}


def main():
    parser = argparse.ArgumentParser(
        description="Search ROP gadgets in rp++ output files — standalone, no dependencies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
available categories as flags:
  --write   --deref   --swap    --pop     --push    --pushad  --pushpop
  --inc     --dec     --add     --sub     --neg
  --xor     --and     --or      --shift   --zero    --pivot   --nop

examples:
  rop_search.py -f gadgets.txt                   # all categories
  rop_search.py -f gadgets.txt --neg             # neg and not together
  rop_search.py -f gadgets.txt --pop --xor       # pop and xor
  rop_search.py -f gadgets.txt --write --deref   # write-what-where and pointer-deref
  rop_search.py -f gadgets.txt -s "pop eax"      # free search with regex
  rop_search.py -f gadgets.txt -n 3              # top-3 per category
  rop_search.py -f gadgets.txt --stats           # statistical summary
  rop_search.py -f gadgets.txt -a x86_64         # 64-bit mode
        """
    )

    parser.add_argument('-f', '--file', required=True,
                        help='Gadget file generated by rp++')
    parser.add_argument('-s', '--search',
                        help='Free search with regular expression')
    parser.add_argument('-n', '--top', type=int, default=0,
                        help='Gadgets to show per category (default: 0 = all)')
    parser.add_argument('-a', '--arch', choices=['x86', 'x86_64'], default='x86',
                        help='Architecture (default: x86)')
    parser.add_argument('--stats', action='store_true',
                        help='Statistical summary of gadgets per category')
    parser.add_argument('--list', action='store_true',
                        help='List available categories and exit')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable ANSI colors')

    cat_group = parser.add_argument_group('category filters')
    for flag, cat_name in CATEGORY_FLAGS.items():
        cat_group.add_argument(f'--{flag}', action='store_true',
                               help=f'Show category: {cat_name}')

    args = parser.parse_args()

    if args.no_color or not _setup_colors():
        C.disable()

    rp   = 'e' if args.arch == 'x86' else 'r'
    cats = get_categories(rp)

    if args.list:
        _, h, *_ = _B()
        print(f"\n{C.BOLD}{'Flag':<12} {'Category'}{C.RESET}")
        print(h * 40)
        for flag, cat_name in CATEGORY_FLAGS.items():
            print(f"  {C.CYAN}--{flag:<10}{C.RESET} {cat_name}")
        print()
        return

    print(f"{C.GREEN}[+]{C.RESET} loading {C.BLUE}{args.file}{C.RESET} ...", end=' ', flush=True)
    gadgets = load_gadgets(args.file)
    print(f"{C.GREEN}{len(gadgets)} gadgets{C.RESET}")

    if args.stats:
        show_stats(gadgets, cats)
        return

    if args.search:
        show_search(gadgets, args.search)
        return

    selected_flags = [flag for flag in CATEGORY_FLAGS if getattr(args, flag, False)]

    if selected_flags:
        selected = {CATEGORY_FLAGS[f]: cats[CATEGORY_FLAGS[f]]
                    for f in selected_flags
                    if CATEGORY_FLAGS[f] in cats}
        show_categorized(gadgets, selected, top=args.top)
        return

    show_categorized(gadgets, cats, top=args.top)


if __name__ == '__main__':
    main()
