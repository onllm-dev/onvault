#!/usr/bin/env python3
import pathlib
import re
import sys


def render_c_string(html_text: str) -> str:
    lines = []
    for line in html_text.splitlines():
        escaped = line.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    "{escaped}\\n"')
    return "static const char *get_menubar_html(void)\n{\n    return\n" + "\n".join(lines) + "\n    ;\n}"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: embed_menubar_html.py <menubar.html> <onvaultd.c>", file=sys.stderr)
        return 1

    html_path = pathlib.Path(sys.argv[1])
    c_path = pathlib.Path(sys.argv[2])

    html_text = html_path.read_text(encoding="utf-8")
    c_text = c_path.read_text(encoding="utf-8")
    replacement = render_c_string(html_text)

    pattern = re.compile(
        r"static const char \*get_menubar_html\(void\)\n\{\n(?:.*\n)*?\}",
        re.MULTILINE,
    )
    new_text, count = pattern.subn(lambda _: replacement, c_text, count=1)
    if count != 1:
        print("failed to locate get_menubar_html() in onvaultd.c", file=sys.stderr)
        return 1

    c_path.write_text(new_text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
