"""Pretty terminal output for scan results.

ANSI color support with graceful fallback for non-TTY output.
"""

from __future__ import annotations

import sys

from gcp_sdk_detector.models import ScanResult

# ANSI escape codes
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_WHITE = "\033[37m"


def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class Formatter:
    """Terminal output formatter with optional ANSI colors."""

    def __init__(self, color: bool | None = None):
        self.color = color if color is not None else _supports_color()

    def _c(self, code: str, text: str) -> str:
        if self.color:
            return f"{code}{text}{_RESET}"
        return text

    def bold(self, text: str) -> str:
        return self._c(_BOLD, text)

    def dim(self, text: str) -> str:
        return self._c(_DIM, text)

    def cyan(self, text: str) -> str:
        return self._c(_CYAN, text)

    def green(self, text: str) -> str:
        return self._c(_GREEN, text)

    def yellow(self, text: str) -> str:
        return self._c(_YELLOW, text)


def _highlight_method_in_line(line: str, method_name: str, fmt: Formatter) -> str:
    """Highlight the method name within the source line."""
    # Find method_name in the line and bold it
    idx = line.find(method_name)
    if idx == -1:
        return line
    before = line[:idx]
    after = line[idx + len(method_name) :]
    return f"{before}{fmt.bold(fmt.cyan(method_name))}{after}"


def _read_source_line(filepath: str, line_num: int) -> str | None:
    """Read a specific line from a file. Returns None if unavailable."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                if i == line_num:
                    return line.rstrip()
    except OSError:
        pass
    return None


def print_scan_results(
    results: list[ScanResult],
    show_all: bool = False,
    file=None,
) -> None:
    """Print scan results with source context and highlighted method calls."""
    if file is None:
        file = sys.stdout

    fmt = Formatter()
    total_findings = 0
    files_with_findings = 0
    all_perms: set[str] = set()
    all_conditional: set[str] = set()
    all_services: set[str] = set()

    for result in results:
        findings = result.findings
        if not show_all:
            findings = [f for f in findings if f.status != "no_api_call"]

        if not findings:
            continue

        files_with_findings += 1
        total_findings += len(findings)

        # File header
        print(f"\n{fmt.bold(result.file)}", file=file)

        for f in findings:
            services = sorted({m.display_name for m in f.matched})
            all_services.update(services)

            # Read and display the actual source line with method highlighted
            source_line = _read_source_line(f.file, f.line)
            line_str = fmt.dim(f"{f.line:>4}")

            if source_line:
                highlighted = _highlight_method_in_line(source_line.strip(), f.method_name, fmt)
                print(f"  {line_str}  {highlighted}", file=file)
            else:
                print(f"  {line_str}  {fmt.bold(f.method_name)}()", file=file)

            # Permissions on the next line, indented
            if f.permissions:
                perm_str = fmt.green(", ".join(f.permissions))
                print(f"        {fmt.dim('→')} {perm_str}", file=file)
                all_perms.update(f.permissions)

                if f.conditional_permissions:
                    cond_str = fmt.yellow(", ".join(f.conditional_permissions))
                    print(f"        {fmt.yellow('⚠')} conditional: {cond_str}", file=file)
                    all_conditional.update(f.conditional_permissions)
            elif f.status == "unmapped":
                print(f"        {fmt.dim('→')} {fmt.dim('unmapped')}", file=file)
            elif f.status == "no_api_call":
                print(f"        {fmt.dim('→')} {fmt.dim('local helper')}", file=file)

    if total_findings == 0:
        print("No GCP SDK calls found.", file=file)
        return

    # Summary
    print(f"\n{fmt.dim('─' * 50)}", file=file)
    print(
        f"{files_with_findings} file(s), {total_findings} finding(s)",
        file=file,
    )
    print(f"Services: {', '.join(sorted(all_services))}", file=file)

    if all_perms or all_conditional:
        print(f"\n{fmt.bold('Required permissions:')}", file=file)
        for p in sorted(all_perms):
            print(f"  {fmt.green('•')} {p}", file=file)
        for p in sorted(all_conditional):
            print(f"  {fmt.yellow('⚠')} {p} {fmt.dim('(conditional)')}", file=file)


def print_progress(current: int, total: int, file=None) -> None:
    """Print a simple progress indicator."""
    if file is None:
        file = sys.stderr
    fmt = Formatter(color=hasattr(file, "isatty") and file.isatty())
    bar_width = 35
    filled = int(bar_width * current / total) if total > 0 else 0
    bar = "━" * filled + " " * (bar_width - filled)
    print(f"\r{fmt.dim('Scanning')} {bar} {current}/{total}", end="", file=file, flush=True)
    if current == total:
        print(file=file)
