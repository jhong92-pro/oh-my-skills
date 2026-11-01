#!/usr/bin/env python3
"""Bundle the text files of a folder into one docx, to be copied and pasted back into files.

Follows .gitignore through git, so git must be installed. The folder need not be a repository.
Standard library only. A file that a paste could not reproduce is listed, never altered.
"""
import argparse
import datetime
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

MARKER = "source-to-docx"
MAX_FILE_BYTES = 2 * 1024 * 1024
# XML 1.0 cannot hold these, and a lone carriage return would not survive a paste.
UNSAFE_TEXT = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\r\ufffe\uffff]")
SENSITIVE_NAME = re.compile(r"(^|[/._-])(secrets?|credentials?|tokens?|keys?|passwords?|id_rsa)([/._-]|$)|\.(pem|pfx|p12)$|(^|/)\.env", re.I)
SENSITIVE_TEXT = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b"
    r"|\b(?:password|passwd|secret|token|api[_-]?key)\b[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9+/_.=-]{16,}",
    re.I,
)
W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
CONTENT_TYPES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>"""
ROOT_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"""
DOC_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""
APP_PROPS = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>{MARKER}</Application></Properties>"""
STYLES = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles {W}>
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:eastAsia="Malgun Gothic" w:cs="Arial"/><w:sz w:val="20"/></w:rPr></w:rPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:after="120"/></w:pPr><w:rPr><w:b/><w:sz w:val="36"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Code"/><w:qFormat/><w:pPr><w:keepNext/><w:pBdr><w:bottom w:val="single" w:sz="8" w:space="2" w:color="000000"/></w:pBdr><w:spacing w:before="360" w:after="80"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:noProof/><w:sz w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:customStyle="1" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:before="0" w:after="0" w:line="240" w:lineRule="auto"/></w:pPr><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:eastAsia="Malgun Gothic" w:cs="Consolas"/><w:noProof/><w:sz w:val="18"/></w:rPr></w:style>
</w:styles>"""


def die(message):
    sys.exit(f"error: {message}")


def run_git(args, cwd=None):
    try:
        return subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=False)
    except FileNotFoundError:
        die("git is required to follow .gitignore")


def list_files(folder):
    """Return paths relative to folder that .gitignore does not exclude."""
    if run_git(["rev-parse", "--is-inside-work-tree"], folder).stdout.strip() == b"true":
        result = run_git(["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "."], folder)
    else:
        # A throwaway git dir applies the folder's .gitignore files without writing into it.
        with tempfile.TemporaryDirectory() as git_dir:
            run_git(["init", "-q", "--bare", git_dir])
            result = run_git(["--git-dir", git_dir, "--work-tree", str(folder), "ls-files", "-z", "--others",
                              "--exclude-standard"], folder)
    if result.returncode:
        die(f"git failed: {result.stderr.decode(errors='replace').strip()}")
    names = {os.fsdecode(name) for name in result.stdout.split(b"\0") if name}
    return sorted(names, key=lambda name: (name.casefold(), name))


def read_source(path):
    """Return (lines, None) when a paste can reproduce the file, else (None, reason)."""
    if path.is_symlink():
        return None, "symbolic link"
    if path.is_dir():
        return None, "nested git repository"
    if not path.is_file():
        return None, "missing from the working tree"
    if path.stat().st_size > MAX_FILE_BYTES:
        return None, f"larger than {MAX_FILE_BYTES // (1024 * 1024)} MB"
    raw = path.read_bytes()
    if b"\0" in raw:
        return None, "binary"
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None, "not UTF-8"
    text = text.replace("\r\n", "\n")
    if UNSAFE_TEXT.search(text):
        return None, "control characters"
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    return lines, None


def run_xml(text):
    """Keep spaces and tabs exactly, because the pasted text must equal the source."""
    parts = []
    for index, piece in enumerate(text.split("\t")):
        if index:
            parts.append("<w:tab/>")
        if piece:
            parts.append(f'<w:t xml:space="preserve">{escape(piece)}</w:t>')
    return f"<w:r>{''.join(parts)}</w:r>" if parts else ""


def paragraph(text, style=None):
    props = f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ""
    return f"<w:p>{props}{run_xml(text)}</w:p>"


def document_xml(folder_name, included, skipped):
    body = [
        paragraph(f"Source bundle: {folder_name}", "Title"),
        paragraph(f"작성일 {datetime.date.today().isoformat()} · 포함 {len(included)}개 · 제외 {len(skipped)}개"),
        paragraph("굵은 제목은 폴더 기준 파일 경로이고, 그 아래부터 다음 제목 전까지가 파일 내용입니다. "
                  "내용을 복사해 같은 경로의 파일에 일반 텍스트로 붙여 넣습니다. 줄바꿈은 붙여 넣는 환경에 따라 정해집니다."),
        paragraph("파일 목록", "Heading1"),
    ]
    for number, (name, lines) in enumerate(included, 1):
        body.append(f'<w:p><w:pPr><w:pStyle w:val="Code"/></w:pPr><w:hyperlink w:anchor="file{number}" w:history="1">'
                    f'{run_xml(f"{name} ({len(lines)}줄)")}</w:hyperlink></w:p>')
    if skipped:
        body.append(paragraph("포함하지 못한 파일 (별도 반입 필요)", "Heading1"))
        body += [paragraph(f"{name}: {reason}", "Code") for name, reason in skipped]
    for number, (name, lines) in enumerate(included, 1):
        body.append(f'<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:bookmarkStart w:id="{number}" w:name="file{number}"/>'
                    f'{run_xml(name)}<w:bookmarkEnd w:id="{number}"/></w:p>')
        body += [paragraph(line, "Code") for line in lines]
    section = ('<w:sectPr><w:pgSz w:w="11906" w:h="16838"/>'
               '<w:pgMar w:top="850" w:right="850" w:bottom="850" w:left="850" w:header="400" w:footer="400" w:gutter="0"/></w:sectPr>')
    return f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<w:document {W}><w:body>{"".join(body)}{section}</w:body></w:document>'


def write_docx(output, xml):
    """Replace the output in one step, so a failed run leaves the previous file."""
    temporary = output.with_name(output.name + ".tmp")
    with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", CONTENT_TYPES)
        archive.writestr("_rels/.rels", ROOT_RELS)
        archive.writestr("docProps/app.xml", APP_PROPS)
        archive.writestr("word/_rels/document.xml.rels", DOC_RELS)
        archive.writestr("word/styles.xml", STYLES)
        archive.writestr("word/document.xml", xml)
    os.replace(temporary, output)


def made_by_this_tool(path):
    try:
        with zipfile.ZipFile(path) as archive:
            return f"<Application>{MARKER}</Application>" in archive.read("docProps/app.xml").decode("utf-8", "replace")
    except (zipfile.BadZipFile, KeyError):
        return False


def main():
    sys.stdout.reconfigure(errors="backslashreplace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", nargs="?", help="folder to bundle, default is the base folder")
    parser.add_argument("--base", help="folder that relative paths start from, default is the current folder")
    parser.add_argument("--output", help="docx path, default is source-bundle[-FOLDER].docx in the base folder")
    parser.add_argument("--force", action="store_true", help="overwrite a file this tool did not create")
    args = parser.parse_args()

    base = Path(args.base or os.getcwd()).resolve()
    folder = (base / args.folder).resolve() if args.folder else base
    if not folder.is_dir() and args.folder and args.folder.startswith("@"):
        # Claude Code's @ file picker leaves its prefix on the path.
        folder = (base / args.folder[1:]).resolve()
    if not folder.is_dir():
        die(f"not a folder: {folder}")
    default_name = "source-bundle.docx" if folder == base else f"source-bundle-{folder.name}.docx"
    output = (base / (args.output or default_name)).resolve()
    if output.exists() and not args.force and not made_by_this_tool(output):
        die(f"{output} exists and was not made by this tool: pass --force or another --output")

    included, skipped, sensitive = [], [], []
    for name in list_files(folder):
        path = folder / name
        if path.resolve() == output:
            continue
        lines, reason = read_source(path)
        if reason:
            skipped.append((name, reason))
            continue
        included.append((name, lines))
        hit = next((number for number, line in enumerate(lines, 1) if SENSITIVE_TEXT.search(line)), None)
        if hit or SENSITIVE_NAME.search(name):
            sensitive.append(f"{name}:{hit}" if hit else name)
    if not included:
        die(f"no text files to bundle in {folder}")
    write_docx(output, document_xml(folder.name, included, skipped))

    print(f"완료: {output} ({output.stat().st_size / 1024:.0f} KB)")
    print(f"대상 폴더: {folder} (.gitignore 적용)")
    print(f"포함 {len(included)}개, {sum(len(lines) for _, lines in included)}줄")
    largest = sorted(included, key=lambda item: -sum(map(len, item[1])))[:3]
    print("가장 큰 파일: " + ", ".join(f"{name} ({sum(map(len, lines)) // 1024} KB)" for name, lines in largest))
    if skipped:
        print(f"제외 {len(skipped)}개 (내용을 바꾸지 않으면 복사로 재현할 수 없어 뺐습니다):")
        for name, reason in skipped:
            print(f"  {name}: {reason}")
    if sensitive:
        print(f"반입 전 확인 {len(sensitive)}개 (이름이나 내용이 자격 증명처럼 보입니다, 값은 표시하지 않음):")
        for item in sensitive:
            print(f"  {item}")


if __name__ == "__main__":
    main()
