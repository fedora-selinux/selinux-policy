#!/usr/bin/env python3
"""Fix whitespace issues in SELinux policy source files (.te, .if, .fc).

Fixes:
  1. Spaces used for indentation -> tabs (based on parsed block depth)
  2. Trailing whitespace
  3. Whitespace-only lines -> empty lines
  4. Wrong indentation depth (over/under-indented lines)
  5. ## doc comment indentation with XML nesting awareness
  6. Consecutive blank lines -> single blank line
  7. Mid-line double spaces in code -> single space (.te/.if only; comments
     and .fc files are left alone since they use spaces deliberately)

Block depth is determined by parsing M4 block structure:
  - interface/template/define blocks (in .if files)
  - optional_policy, tunable_policy, ifdef/ifndef, gen_require blocks
  - if() {} C-style conditional blocks
  - ifelse() M4 blocks

The parser strips comments before counting M4 backtick/singlequote
nesting to avoid false matches from quotes in comment text.

Usage:
  Fix a single file:
    python3 scripts/fix_whitespace.py policy/modules/contrib/kerberos.if

  Fix the whole repository:
    python3 scripts/fix_whitespace.py policy/modules/

  Verify without modifying (exit code 1 if issues found):
    python3 scripts/fix_whitespace.py --verify policy/modules/

  Dry-run with verbose output:
    python3 scripts/fix_whitespace.py -n -v policy/modules/kernel/kernel.te

"""

import argparse
import difflib
import os
import re
import sys


def strip_comment(line):
    """Remove # comment from a line, preserving M4 quoting context.

    Returns the code portion of the line (everything before the comment).
    Note: ## documentation comments in .if files are handled separately.
    """
    stripped = line.lstrip()

    # Lines starting with # are pure comments (including ## doc comments)
    if stripped.startswith('#'):
        return ''

    # For lines with inline comments, find the # that starts the comment.
    # Must not be inside M4 quotes. Simple approach: scan character by character.
    depth = 0
    for i, ch in enumerate(stripped):
        if ch == '`':
            depth += 1
        elif ch == "'":
            if depth > 0:
                depth -= 1
        elif ch == '#' and depth == 0:
            return stripped[:i]

    return stripped


def find_comment_pos(code_line):
    """Find the index of the comment-starting '#' in an already-stripped line.

    Returns -1 if there is no comment. Ignores '#' inside M4 backtick/
    singlequote strings, matching the quoting logic in strip_comment().
    """
    depth = 0
    for i, ch in enumerate(code_line):
        if ch == '`':
            depth += 1
        elif ch == "'":
            if depth > 0:
                depth -= 1
        elif ch == '#' and depth == 0:
            return i
    return -1


def collapse_double_spaces(stripped):
    """Collapse runs of 2+ spaces to a single space in the code portion of a line.

    Only the code portion (before any inline comment) is touched; comment
    text is left untouched since it may deliberately use double spaces
    (e.g. two spaces after a sentence-ending period).

    Returns (new_stripped, changed).
    """
    comment_pos = find_comment_pos(stripped)
    if comment_pos == -1:
        code, comment = stripped, ''
    else:
        code, comment = stripped[:comment_pos], stripped[comment_pos:]

    new_code = re.sub(r' {2,}', ' ', code)
    new_stripped = new_code + comment
    return new_stripped, new_stripped != stripped


def parse_block_depth(lines, file_type):
    """Parse block structure and return expected indentation depth for each line.

    Uses M4 backtick/singlequote counting on code portions only (comments stripped).
    Tracks nesting depth through:
      - M4 quoted blocks: backtick (`) opens, singlequote (') closes
      - C-style blocks: { opens, } closes

    For each line, the depth is the nesting level AT which that line should appear.
    Block openers (lines ending with ` or {) are at the CURRENT depth, and increase
    depth for subsequent lines. Block closers (lines starting with ') or }) are at
    the REDUCED depth (same as their opener).

    Args:
        lines: list of line strings (without trailing newline)
        file_type: 'te', 'if', or 'fc'

    Returns:
        list of int, one per line, giving the expected tab depth
    """
    depths = []
    depth = 0

    for line in lines:
        stripped = line.strip()

        # Empty lines get current depth (will become empty anyway)
        if not stripped:
            depths.append(depth)
            continue

        # Pure comment lines: get current depth
        if stripped.startswith('#'):
            depths.append(depth)
            continue

        # Get code portion (strip inline comments)
        code = strip_comment(line).strip()
        if not code:
            # Line was entirely a comment
            depths.append(depth)
            continue

        # Special case: `` opens a doubly-quoted deferred macro body, e.g.
        #   define(`create_netif_interfaces',``
        #       ...body written flush-left, meant to read as top-level...
        #   '') dnl end create_netif_interfaces
        # (used by corenetwork.if.m4's create_*_interfaces generators). The
        # extra backtick/quote pair there is a quoting mechanism to defer
        # expansion, not a nesting level, so treat it as depth-neutral
        # rather than opening/closing two levels.
        if re.match(r"^define\(`[A-Za-z_][A-Za-z0-9_]*',``$", code):
            depths.append(depth)
            continue
        if re.match(r"^''\)", code):
            depths.append(depth)
            continue

        # Count M4 quotes and braces in code portion only
        ticks = code.count('`')
        squotes = code.count("'")
        open_braces = code.count('{')
        close_braces = code.count('}')

        # Net depth change from this line
        net = (ticks + open_braces) - (squotes + close_braces)

        # Determine if this line starts with a closer
        # Closers should be at the OUTER (reduced) depth
        is_leading_closer = (
            code.startswith("')") or
            code.startswith("}") or
            code.startswith("',")  # else branch closer
        )

        if is_leading_closer:
            # Count how many closers are at the start of the line
            # These reduce depth BEFORE this line
            leading_closes = 0
            s = code
            while True:
                if s.startswith("')"):
                    leading_closes += 1
                    s = s[2:].strip()
                    # Skip optional semicolons
                    while s.startswith(';'):
                        s = s[1:].strip()
                elif s.startswith("}"):
                    leading_closes += 1
                    s = s[1:].strip()
                elif s.startswith("',"):
                    leading_closes += 1
                    s = s[2:].strip()
                    if s.startswith('`'):
                        # ',` is close-old-open-new (else branch)
                        # The ` is already counted in ticks
                        pass
                    break
                else:
                    break

            # This line's depth = depth - leading_closes
            line_depth = max(0, depth - leading_closes)
            depths.append(line_depth)
        else:
            # Normal line or opener: at current depth
            depths.append(depth)

        # Update depth for next line
        depth = max(0, depth + net)

    return depths


def fix_if_doc_comment(stripped, doc_state, base_depth=0):
    """Fix ## documentation comment indentation.

    Tracks XML nesting to determine indentation. doc_state is a tuple
    (xml_depth, visual_depth) tracking structural and visual nesting:
      - xml_depth: counts all opening/closing tags (determines space vs tab)
      - visual_depth: counts only <desc> and <p> tags (determines tab count)
      - Depth-0 tags: "## <tag>" (space before tag)
      - Depth > 0: "##" + tabs matching visual_depth

    base_depth is the surrounding code's block-nesting depth (as used for
    regular code lines). Doc comments almost always precede a top-level
    interface(...) (base_depth 0), but occasionally document something
    nested inside a block (e.g. a gen_bool() inside an ifdef()); in that
    case the whole comment shifts right by base_depth tabs so it lines up
    with the code it documents, on top of its own XML-nesting indent.

    Returns (fixed_line, new_doc_state).
    """
    xml_depth, visual_depth = doc_state

    after_hashes = stripped[2:]

    if not after_hashes:
        return '##', (xml_depth, visual_depth)

    content = after_hashes.lstrip(' \t')
    if not content:
        return '##', (xml_depth, visual_depth)

    is_closing_tag = content.startswith('</')
    is_opening_tag = content.startswith('<') and not is_closing_tag

    # Only <desc>, <ul>, and <ol> increase visual indentation
    indent_tags = ('desc>', 'ul>', 'ol>')

    # Count all opening and closing tags on this line
    opens = 0
    closes = 0
    visual_opens = 0
    visual_closes = 0
    pos = 0
    while pos < len(content):
        if content[pos:pos+2] == '</':
            end = content.find('>', pos)
            if end >= 0:
                tag = content[pos+2:end]
                closes += 1
                if any(tag.startswith(t.rstrip('>')) for t in indent_tags):
                    visual_closes += 1
                pos = end + 1
                continue
        elif content[pos] == '<' and pos + 1 < len(content) and content[pos+1] != '/':
            end = content.find('>', pos)
            if end >= 0:
                # Self-closing tags (e.g. <infoflow .../>, <rolecap/>) don't
                # nest anything; counting them as an unmatched open would
                # permanently bump xml_depth for the rest of the doc block.
                if content[end-1] != '/':
                    opens += 1
                    tag = content[pos+1:end].split()[0]
                    if any(tag.startswith(t.rstrip('>')) for t in indent_tags):
                        visual_opens += 1
                pos = end + 1
                continue
        pos += 1

    # Leading closer reduces depth before formatting this line
    if is_closing_tag:
        xml_depth = max(0, xml_depth - 1)
        tag_name = content[2:content.find('>')] if '>' in content else content[2:]
        if any(tag_name.startswith(t.rstrip('>')) for t in indent_tags):
            visual_depth = max(0, visual_depth - 1)
        # This close is already counted; remove it from the net
        closes -= 1
        if any(tag_name.startswith(t.rstrip('>')) for t in indent_tags):
            visual_closes -= 1

    if xml_depth == 0 and content.startswith('<'):
        result = '##' + ('\t' * base_depth + content if base_depth else ' ' + content)
    else:
        result = '##' + '\t' * (base_depth + max(1, visual_depth)) + content

    # Apply net depth change for subsequent lines
    xml_depth += opens - closes
    visual_depth += visual_opens - visual_closes
    xml_depth = max(0, xml_depth)
    visual_depth = max(0, visual_depth)

    return result, (xml_depth, visual_depth)


def get_indent_depth(line):
    """Count the effective indentation depth of a line.

    Tabs count as 1 each. Groups of 4 spaces count as 1.
    """
    indent = line[:len(line) - len(line.lstrip())]
    tabs = indent.count('\t')
    spaces = indent.count(' ')
    return tabs + (spaces + 3) // 4


def get_file_type(filepath):
    """Get the policy file type from a filepath.

    Handles .te, .if, .fc as well as template variants .te.in, .te.m4, .if.in, .if.m4.
    Returns 'te', 'if', 'fc', or None if not recognized.
    """
    base = os.path.basename(filepath)
    for suffix in ('.te.in', '.te.m4', '.if.in', '.if.m4', '.te', '.if', '.fc'):
        if base.endswith(suffix):
            return suffix.split('.')[1]
    return None


def compute_fixed_lines(original_lines, ext):
    """Apply all whitespace fixes to a list of lines.

    This is the single source of truth for what "fixed" looks like; both
    fix_file() (which writes the result) and verify_file() (which reports
    whether a file matches it) must go through this exact computation, or
    they drift out of sync and verify can miss things fix would change.

    Returns (fixed_lines, stats).
    """
    stats = {
        'trailing_ws': 0,
        'ws_only_lines': 0,
        'space_indent': 0,
        'depth_fixes': 0,
        'doc_comment_fixes': 0,
        'consecutive_blanks': 0,
        'double_space': 0,
        'total_changed': 0,
    }

    # Step 1: Strip trailing whitespace
    cleaned = []
    for line in original_lines:
        clean = line.rstrip()
        if line.rstrip('\n') != clean:
            if line.strip() == '' and line.rstrip('\n') != '':
                stats['ws_only_lines'] += 1
            else:
                stats['trailing_ws'] += 1
        cleaned.append(clean)

    # Step 2: Parse block depth
    depths = parse_block_depth(cleaned, ext)

    # Step 3: Re-indent each line
    fixed = []
    doc_state = (0, 0)
    for i, (line, expected_depth) in enumerate(zip(cleaned, depths)):
        stripped = line.strip()

        # Empty / whitespace-only -> truly empty
        if not stripped:
            fixed.append('')
            continue

        # .fc files: no indentation expected
        if ext == 'fc':
            fixed.append(stripped)
            if line != stripped:
                stats['space_indent'] += 1
            continue

        # ## documentation comments (but not section separators like ######)
        if stripped.startswith('##') and not stripped.startswith('###'):
            new_line, doc_state = fix_if_doc_comment(stripped, doc_state, expected_depth)
            if line != new_line:
                stats['doc_comment_fixes'] += 1
            fixed.append(new_line)
            continue

        doc_state = (0, 0)

        # Collapse mid-line double spaces in code (not in pure comment lines)
        if not stripped.startswith('#'):
            stripped, ds_changed = collapse_double_spaces(stripped)
            if ds_changed:
                stats['double_space'] += 1

        # Regular line (code or # comment): apply expected depth
        new_line = '\t' * expected_depth + stripped
        if line != new_line:
            cur_depth = get_indent_depth(line)
            indent = line[:len(line) - len(line.lstrip())]
            has_spaces = ' ' in indent
            if cur_depth != expected_depth:
                stats['depth_fixes'] += 1
            elif has_spaces:
                stats['space_indent'] += 1
        fixed.append(new_line)

    # Step 4: Collapse consecutive blank lines to a single blank line
    collapsed = []
    for line in fixed:
        if line == '' and collapsed and collapsed[-1] == '':
            stats['consecutive_blanks'] += 1
            continue
        collapsed.append(line)
    fixed = collapsed

    stats['total_changed'] = (
        stats['space_indent'] + stats['depth_fixes'] +
        stats['trailing_ws'] + stats['ws_only_lines'] +
        stats['doc_comment_fixes'] + stats['consecutive_blanks'] +
        stats['double_space']
    )

    return fixed, stats


def fix_file(filepath, dry_run=False, verbose=False):
    """Fix whitespace issues in a single policy file.

    Returns dict with change statistics.
    """
    ext = get_file_type(filepath)
    if ext is None:
        return {'error': f'Unknown file type: {os.path.splitext(filepath)[1].lstrip(".")}'}

    with open(filepath, 'r') as f:
        original_content = f.read()

    original_lines = original_content.split('\n')
    if original_lines and original_lines[-1] == '':
        original_lines = original_lines[:-1]

    fixed, stats = compute_fixed_lines(original_lines, ext)

    # Write
    new_content = '\n'.join(fixed) + '\n'
    if new_content != original_content:
        if not dry_run:
            with open(filepath, 'w') as f:
                f.write(new_content)
        if verbose and stats['total_changed'] > 0:
            print(f"  {filepath}: {stats['total_changed']} lines "
                  f"(indent:{stats['space_indent']} depth:{stats['depth_fixes']} "
                  f"trailing:{stats['trailing_ws']} ws-only:{stats['ws_only_lines']} "
                  f"doc:{stats['doc_comment_fixes']} dblank:{stats['consecutive_blanks']} "
                  f"dblspace:{stats['double_space']})")
    else:
        stats['total_changed'] = 0

    return stats


def verify_file(filepath):
    """Verify a file has no remaining whitespace issues.

    Runs the specific line-level checks below for readable messages, then
    falls back to compute_fixed_lines() (the same computation fix_file()
    writes out) as a catch-all: anything that pipeline would still change
    but that isn't covered by a specific check is flagged generically, so
    verify can never miss something fix would actually alter (e.g. an
    irregular "## \t" doc-comment prefix, only fixable via full
    re-derivation, not a simple per-line pattern check).
    """
    issues = []
    ext = get_file_type(filepath)
    prev_blank = False
    flagged_lines = set()

    with open(filepath, 'r') as f:
        original_content = f.read()

    original_lines = original_content.split('\n')
    if original_lines and original_lines[-1] == '':
        original_lines = original_lines[:-1]

    for lineno, line in enumerate(original_lines, 1):
        if line.strip() == '':
            if prev_blank:
                issues.append(f"{filepath}:{lineno}: consecutive blank line")
                flagged_lines.add(lineno)
            prev_blank = True
        else:
            prev_blank = False

        if line != line.rstrip():
            issues.append(f"{filepath}:{lineno}: trailing whitespace")
            flagged_lines.add(lineno)

        if line.strip() == '' and line != '':
            issues.append(f"{filepath}:{lineno}: whitespace-only line")
            flagged_lines.add(lineno)

        if line.startswith(' '):
            stripped = line.lstrip()
            skip = False
            if ext == 'if' and stripped.startswith('##'):
                after = stripped[2:]
                if after.startswith(' <') or after.startswith(' </'):
                    skip = True
            if not skip:
                issues.append(f"{filepath}:{lineno}: space indentation")
                flagged_lines.add(lineno)

        indent = line[:len(line) - len(line.lstrip())]
        if '\t' in indent and ' ' in indent:
            issues.append(f"{filepath}:{lineno}: mixed tab/space indent")
            flagged_lines.add(lineno)

        stripped = line.strip()
        if ext != 'fc' and stripped and not stripped.startswith('#'):
            comment_pos = find_comment_pos(stripped)
            code = stripped if comment_pos == -1 else stripped[:comment_pos]
            if '  ' in code:
                issues.append(f"{filepath}:{lineno}: mid-line double space")
                flagged_lines.add(lineno)

    # Catch-all: anything the actual fixer would still change.
    fixed_lines, _ = compute_fixed_lines(original_lines, ext)
    if fixed_lines != original_lines:
        matcher = difflib.SequenceMatcher(None, original_lines, fixed_lines)
        for tag, i1, i2, _j1, _j2 in matcher.get_opcodes():
            if tag == 'equal':
                continue
            lo, hi = (i1, i2) if i1 < i2 else (i1, i1 + 1)
            for lineno in range(lo + 1, hi + 1):
                if lineno not in flagged_lines:
                    issues.append(f"{filepath}:{lineno}: does not match expected formatting")
                    flagged_lines.add(lineno)

    return issues


def find_policy_files(root_dir):
    """Find all .te, .if, .fc files under root_dir."""
    files = []
    for dirpath, _dirnames, filenames in os.walk(root_dir):
        for fname in sorted(filenames):
            if fname.endswith(('.te', '.if', '.fc', '.te.in', '.te.m4', '.if.in', '.if.m4')):
                files.append(os.path.join(dirpath, fname))
    return sorted(files)


def main():
    parser = argparse.ArgumentParser(
        description='Fix whitespace issues in SELinux policy source files')
    parser.add_argument('paths', nargs='*', default=[],
                        help='Files or directories to process')
    parser.add_argument('-n', '--dry-run', action='store_true',
                        help='Report changes without modifying files')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Print detailed per-file changes')
    parser.add_argument('--verify', action='store_true',
                        help='Verify files have no whitespace issues')
    args = parser.parse_args()

    if not args.paths:
        print("Usage: fix_whitespace.py [-n] [-v] [--verify] <file_or_dir> ...")
        sys.exit(1)

    files = []
    for path in args.paths:
        if os.path.isdir(path):
            files.extend(find_policy_files(path))
        elif os.path.isfile(path):
            files.append(path)
        else:
            print(f"Warning: {path} not found", file=sys.stderr)

    if args.verify:
        total_issues = 0
        for filepath in files:
            issues = verify_file(filepath)
            for issue in issues:
                print(issue)
            total_issues += len(issues)
        if total_issues == 0:
            print(f"All {len(files)} files clean.")
        else:
            print(f"\n{total_issues} issues in {len(files)} files.")
        sys.exit(1 if total_issues > 0 else 0)

    totals = {
        'trailing_ws': 0, 'ws_only_lines': 0, 'space_indent': 0,
        'depth_fixes': 0, 'doc_comment_fixes': 0, 'consecutive_blanks': 0,
        'double_space': 0, 'total_changed': 0, 'files_changed': 0,
    }

    for filepath in files:
        stats = fix_file(filepath, dry_run=args.dry_run, verbose=args.verbose)
        if 'error' in stats:
            print(f"Error: {stats['error']}: {filepath}", file=sys.stderr)
            continue
        for key in totals:
            if key in stats:
                totals[key] += stats[key]
        if stats.get('total_changed', 0) > 0:
            totals['files_changed'] += 1

    action = "Would change" if args.dry_run else "Changed"
    print(f"\n{action} {totals['files_changed']}/{len(files)} files "
          f"({totals['total_changed']} lines total)")
    print(f"  Space indentation fixes: {totals['space_indent']}")
    print(f"  Depth corrections: {totals['depth_fixes']}")
    print(f"  Trailing whitespace: {totals['trailing_ws']}")
    print(f"  Whitespace-only lines: {totals['ws_only_lines']}")
    print(f"  Doc comment fixes: {totals['doc_comment_fixes']}")
    print(f"  Consecutive blank lines: {totals['consecutive_blanks']}")
    print(f"  Mid-line double spaces: {totals['double_space']}")


if __name__ == '__main__':
    main()
