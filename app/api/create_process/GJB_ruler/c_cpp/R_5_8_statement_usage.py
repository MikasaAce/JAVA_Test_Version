import re
from typing import Dict, List, Set, Tuple, Union


RULES_5_8 = [
    {"rule_id": "R-1-8-1", "message": "GJB R-1-8-1: 禁止使用无意义空语句", "severity": "中危"},
    {"rule_id": "R-1-8-2", "message": "GJB R-1-8-2: 控制语句体必须使用花括号", "severity": "中危"},
    {"rule_id": "R-1-8-3", "message": "GJB R-1-8-3: return/break/continue/goto 后禁止出现不可达语句", "severity": "高危"},
    {"rule_id": "R-1-8-4", "message": "GJB R-1-8-4: switch 的 case 分支应以 break/return/throw 结束", "severity": "高危"},
    {"rule_id": "R-1-8-5", "message": "GJB R-1-8-5: 禁止在 if/while 条件中使用逗号表达式", "severity": "中危"},
    {"rule_id": "R-1-8-6", "message": "GJB R-1-8-6: 禁止在一行中拼接多个可执行语句", "severity": "中危"},
    {"rule_id": "R-1-8-7", "message": "GJB R-1-8-7: 标号语句必须被 goto 使用", "severity": "低危"},
    {"rule_id": "A-1-8-1", "message": "GJB A-1-8-1: 建议减少 continue 语句使用", "severity": "建议"},
    {"rule_id": "A-1-8-2", "message": "GJB A-1-8-2: 建议避免语句块嵌套层数过深", "severity": "建议"},
    {"rule_id": "A-1-8-3", "message": "GJB A-1-8-3: 建议每条语句单独占一行", "severity": "建议"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_5_8}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-1-8-UNKNOWN"


def get_code_snippet(node_or_span: Union[Tuple[int, int], object], code: str, context_lines: int = 2) -> str:
    lines = code.split("\n")
    if isinstance(node_or_span, tuple):
        s, e = node_or_span
    else:
        s = getattr(node_or_span, "start_point", (0, 0))[0]
        e = getattr(node_or_span, "end_point", (s, 0))[0]

    start = max(0, s - context_lines)
    end = min(len(lines), e + context_lines + 1)
    snippet = "\n".join(lines[start:end])
    if len(snippet) > 280:
        snippet = snippet[:280] + "..."
    return snippet


def _add_violation(
    violations: List[dict],
    seen: Set[Tuple[int, str]],
    line: int,
    rule_id: str,
    code_snippet: str,
    suffix: str = "",
):
    if (line, rule_id) in seen:
        return
    seen.add((line, rule_id))

    meta = RULE_META[rule_id]
    message = meta["message"]
    if suffix:
        message = f"{message} ({suffix})"

    violations.append(
        {
            "line": line,
            "code_snippet": code_snippet,
            "violation_type": "编码规范",
            "severity": meta["severity"],
            "rule_id": rule_id,
            "message": message,
        }
    )


def _strip_line_comment(line: str) -> str:
    in_str = False
    quote = ""
    out = []
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if not in_str and ch == "/" and nxt == "/":
            break
        if ch in ('"', "'"):
            if not in_str:
                in_str = True
                quote = ch
            elif i > 0 and line[i - 1] != "\\" and ch == quote:
                in_str = False
                quote = ""
        out.append(ch)
        i += 1
    return "".join(out)


def _sanitize_lines(lines: List[str]) -> List[str]:
    cleaned = []
    in_block_comment = False

    for raw in lines:
        line = raw
        i = 0
        out = []
        while i < len(line):
            ch = line[i]
            nxt = line[i + 1] if i + 1 < len(line) else ""

            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    i += 2
                else:
                    i += 1
                continue

            if ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue

            out.append(ch)
            i += 1

        cleaned.append(_strip_line_comment("".join(out)))

    return cleaned


def _compute_depth(lines: List[str]) -> List[int]:
    depth = 0
    depths = []
    for line in lines:
        depths.append(depth)
        depth += line.count("{")
        depth -= line.count("}")
        if depth < 0:
            depth = 0
    return depths


def _collect_labels_and_gotos(lines: List[str]) -> Tuple[Dict[str, int], Set[str]]:
    labels: Dict[str, int] = {}
    goto_targets: Set[str] = set()

    label_pat = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?!\s*//)")
    case_default_pat = re.compile(r"^\s*(case\s+.*:|default\s*:)\s*$")
    goto_pat = re.compile(r"\bgoto\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")

    for i, line in enumerate(lines, 1):
        if case_default_pat.match(line.strip()):
            for m_goto in goto_pat.finditer(line):
                goto_targets.add(m_goto.group(1))
            continue

        m_label = label_pat.match(line)
        if m_label:
            labels[m_label.group(1)] = i

        for m_goto in goto_pat.finditer(line):
            goto_targets.add(m_goto.group(1))

    return labels, goto_targets


def _scan_rules(lines: List[str], code: str, language: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    sanitized = _sanitize_lines(lines)
    depths = _compute_depth(sanitized)
    labels, goto_targets = _collect_labels_and_gotos(sanitized)

    unreachable_until_block_end = False
    unreachable_depth = -1

    for i, line in enumerate(sanitized, 1):
        s = line.strip()

        # 块收束后恢复可达状态
        if unreachable_until_block_end and depths[i - 1] <= unreachable_depth:
            unreachable_until_block_end = False
            unreachable_depth = -1

        # R-1-8-1: 无意义空语句
        if s == ";":
            _add_violation(violations, seen, i, "R-1-8-1", get_code_snippet((i - 1, i - 1), code))

        # R-1-8-2: 控制语句体未使用花括号（近似）
        if re.match(r"^\s*(if|for|while)\s*\([^\)]*\)\s*[^\s{].*;\s*$", line):
            _add_violation(violations, seen, i, "R-1-8-2", get_code_snippet((i - 1, i - 1), code))

        # R-1-8-5: 条件中逗号表达式
        if re.search(r"\b(if|while)\s*\([^\)]*,[^\)]*\)", line):
            _add_violation(violations, seen, i, "R-1-8-5", get_code_snippet((i - 1, i - 1), code))

        # R-1-8-6: 一行多个语句（忽略for头）
        if s and not s.startswith("for") and s.count(";") >= 2:
            _add_violation(violations, seen, i, "R-1-8-6", get_code_snippet((i - 1, i - 1), code))
            _add_violation(violations, seen, i, "A-1-8-3", get_code_snippet((i - 1, i - 1), code))

        # A-1-8-1: continue使用建议
        if re.search(r"\bcontinue\s*;", line):
            _add_violation(violations, seen, i, "A-1-8-1", get_code_snippet((i - 1, i - 1), code))

        # A-1-8-2: 语句块嵌套层数
        if depths[i - 1] >= 4:
            _add_violation(violations, seen, i, "A-1-8-2", get_code_snippet((i - 1, i - 1), code), f"depth={depths[i - 1]}")

        # R-1-8-3: 不可达语句（近似）
        if unreachable_until_block_end:
            if s and not s.startswith("}") and not re.match(r"^(case\s+.*:|default\s*:|[A-Za-z_][A-Za-z0-9_]*\s*:)$", s):
                _add_violation(violations, seen, i, "R-1-8-3", get_code_snippet((i - 1, i - 1), code))

        # 设置不可达区间起点
        if re.search(r"\b(return|break|continue|goto)\b\s*[^;]*;", line):
            unreachable_until_block_end = True
            unreachable_depth = depths[i - 1]

    # R-1-8-4: switch case 分支终结检查（近似）
    in_switch = False
    case_open = False
    case_has_terminal = False
    case_line = 0

    for i, line in enumerate(sanitized, 1):
        s = line.strip()

        if re.match(r"^switch\s*\(.*\)\s*\{?\s*$", s):
            in_switch = True
            case_open = False
            case_has_terminal = False
            case_line = 0
            continue

        if not in_switch:
            continue

        if re.match(r"^(case\s+.*:|default\s*:)", s):
            if case_open and not case_has_terminal:
                _add_violation(violations, seen, case_line, "R-1-8-4", get_code_snippet((case_line - 1, case_line - 1), code))
            case_open = True
            case_has_terminal = False
            case_line = i
            continue

        if case_open and re.search(r"\b(break|return|throw)\b\s*[^;]*;", s):
            case_has_terminal = True

        if in_switch and s == "}":
            if case_open and not case_has_terminal:
                _add_violation(violations, seen, case_line, "R-1-8-4", get_code_snippet((case_line - 1, case_line - 1), code))
            in_switch = False
            case_open = False
            case_has_terminal = False
            case_line = 0

    # R-1-8-7: 未被goto使用的标号
    for label, line in labels.items():
        if label not in goto_targets:
            _add_violation(violations, seen, line, "R-1-8-7", get_code_snippet((line - 1, line - 1), code), label)


def detect_c_cpp_gjb_5_8_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中5.8（语句使用）条款的违规。

    Args:
        code: C/C++源码字符串
        language: 语言类型，支持"c"和"cpp"

    Returns:
        list[dict]: 违规列表
    """
    if language not in ("c", "cpp"):
        return []

    lines = code.split("\n")
    violations: List[dict] = []
    seen: Set[Tuple[int, str]] = set()

    _scan_rules(lines, code, language, violations, seen)

    return sorted(violations, key=lambda x: (x["line"], x["rule_id"]))


def analyze_c_cpp_gjb_5_8(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_c_cpp_gjb_5_8_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "c_basic_violations",
            "c",
            """
int foo(int x){
L_unused:
    if (x > 0) x--;
    if (x, x > 1) { x--; }
    x = x + 1; x = x + 2;
    switch(x){
        case 0:
            x++;
        case 1:
            x--;
            break;
        default:
            x += 2;
    }
    ;
    return x;
    x = 100;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
int foo(int x){
    if (x > 0) {
        x--;
    }

    while (x > 0) {
        x--;
    }

    switch (x) {
        case 0:
            x++;
            break;
        default:
            break;
    }

    return x;
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_c_cpp_gjb_5_8(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
