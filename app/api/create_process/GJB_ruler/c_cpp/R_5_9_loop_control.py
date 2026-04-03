import re
from typing import Dict, List, Set, Tuple, Union


RULES_5_9 = [
    {"rule_id": "R-1-9-1", "message": "GJB R-1-9-1: 循环控制变量禁止在循环体内被非预期修改", "severity": "高危"},
    {"rule_id": "R-1-9-2", "message": "GJB R-1-9-2: 禁止使用无边界或不可终止循环", "severity": "高危"},
    {"rule_id": "R-1-9-3", "message": "GJB R-1-9-3: for 循环控制表达式应完整且语义清晰", "severity": "中危"},
    {"rule_id": "R-1-9-4", "message": "GJB R-1-9-4: 禁止在循环条件中使用赋值表达式", "severity": "高危"},
    {"rule_id": "R-1-9-5", "message": "GJB R-1-9-5: 循环体必须使用花括号", "severity": "中危"},
    {"rule_id": "R-1-9-6", "message": "GJB R-1-9-6: do-while 循环条件禁止恒真", "severity": "高危"},
    {"rule_id": "R-1-9-7", "message": "GJB R-1-9-7: while/for 循环条件禁止恒真", "severity": "高危"},
    {"rule_id": "A-1-9-1", "message": "GJB A-1-9-1: 建议减少多层循环嵌套", "severity": "建议"},
    {"rule_id": "A-1-9-2", "message": "GJB A-1-9-2: 建议避免在循环体内使用多个 break/continue", "severity": "建议"},
    {"rule_id": "A-1-9-3", "message": "GJB A-1-9-3: 建议循环边界使用明确命名常量", "severity": "建议"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_5_9}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-1-9-UNKNOWN"


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
    message = RULE_META[rule_id]["message"]
    if suffix:
        message = f"{message} ({suffix})"
    violations.append(
        {
            "line": line,
            "code_snippet": code_snippet,
            "violation_type": "编码规范",
            "severity": RULE_META[rule_id]["severity"],
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
        i = 0
        out = []
        while i < len(raw):
            ch = raw[i]
            nxt = raw[i + 1] if i + 1 < len(raw) else ""
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


def _find_loop_blocks(lines: List[str]) -> List[Tuple[int, int, str, str]]:
    loops: List[Tuple[int, int, str, str]] = []
    i = 0
    while i < len(lines):
        s = lines[i]
        m_for = re.search(r"\bfor\s*\(([^)]*)\)", s)
        m_while = re.search(r"\bwhile\s*\(([^)]*)\)", s)
        m_do = re.search(r"\bdo\b", s)

        loop_type = ""
        cond = ""
        if m_for:
            loop_type = "for"
            cond = m_for.group(1)
        elif m_while and not re.search(r"\bdo\b", s):
            loop_type = "while"
            cond = m_while.group(1)
        elif m_do:
            loop_type = "do"
            cond = ""

        if not loop_type:
            i += 1
            continue

        start = i
        if "{" in s:
            depth = s.count("{") - s.count("}")
            j = i
            while j + 1 < len(lines) and depth > 0:
                j += 1
                depth += lines[j].count("{")
                depth -= lines[j].count("}")
            end = j
        else:
            end = min(i + 1, len(lines) - 1)

        # do-while 的条件在尾行
        if loop_type == "do":
            tail = end + 1
            if tail < len(lines):
                m_tail = re.search(r"\bwhile\s*\(([^)]*)\)\s*;", lines[tail])
                if m_tail:
                    cond = m_tail.group(1)
                    end = tail

        loops.append((start, end, loop_type, cond.strip()))
        i = end + 1
    return loops


def _is_true_constant(cond: str) -> bool:
    c = cond.replace(" ", "")
    return c in {"1", "true", "TRUE", "(1)", "(true)", "(TRUE)"}


def _scan_rules(lines: List[str], code: str, language: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    sanitized = _sanitize_lines(lines)
    depths = _compute_depth(sanitized)
    loops = _find_loop_blocks(sanitized)

    for start, end, loop_type, cond in loops:
        line_no = start + 1
        line = sanitized[start].strip()

        # R-1-9-5: 循环体必须使用花括号
        if "{" not in sanitized[start]:
            _add_violation(violations, seen, line_no, "R-1-9-5", get_code_snippet((start, start), code), loop_type)

        # R-1-9-2 / R-1-9-6 / R-1-9-7: 恒真/不可终止循环
        if _is_true_constant(cond):
            if loop_type == "do":
                _add_violation(violations, seen, line_no, "R-1-9-6", get_code_snippet((start, end), code), cond)
            else:
                _add_violation(violations, seen, line_no, "R-1-9-7", get_code_snippet((start, end), code), cond)
            _add_violation(violations, seen, line_no, "R-1-9-2", get_code_snippet((start, end), code), cond)

        # R-1-9-4: 循环条件赋值
        cond_expr = cond
        if loop_type == "for":
            parts = [x.strip() for x in cond.split(";")]
            if len(parts) == 3:
                cond_expr = parts[1]
            else:
                cond_expr = ""
        if cond_expr and re.search(r"(^|[^=!<>])=([^=]|$)", cond_expr):
            _add_violation(violations, seen, line_no, "R-1-9-4", get_code_snippet((start, end), code), cond_expr)

        # R-1-9-3: for 表达式完整性
        if loop_type == "for":
            parts = [x.strip() for x in cond.split(";")]
            if len(parts) != 3:
                _add_violation(violations, seen, line_no, "R-1-9-3", get_code_snippet((start, end), code), "for-part-count")
            else:
                if not parts[1]:
                    _add_violation(violations, seen, line_no, "R-1-9-3", get_code_snippet((start, end), code), "missing-condition")

                # A-1-9-3: 边界硬编码
                if re.search(r"[<>]=?\s*\d+", parts[1]):
                    _add_violation(violations, seen, line_no, "A-1-9-3", get_code_snippet((start, end), code), parts[1])

                # R-1-9-1: 控制变量在循环体被非预期修改（近似）
                var_m = re.match(r"(?:[A-Za-z_][A-Za-z0-9_\s\*]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", parts[0])
                if var_m:
                    ctrl_var = var_m.group(1)
                    for k in range(start + 1, end + 1):
                        body = sanitized[k]
                        # 忽略for头增量，检查循环体中赋值/复合赋值
                        if re.search(rf"\b{re.escape(ctrl_var)}\b\s*(\+=|-=|\*=|/=|%=|=(?!=))", body):
                            _add_violation(
                                violations,
                                seen,
                                k + 1,
                                "R-1-9-1",
                                get_code_snippet((k, k), code),
                                ctrl_var,
                            )
                            break

        # A-1-9-2: 循环体多 break/continue
        break_cnt = 0
        cont_cnt = 0
        for k in range(start + 1, end + 1):
            break_cnt += len(re.findall(r"\bbreak\s*;", sanitized[k]))
            cont_cnt += len(re.findall(r"\bcontinue\s*;", sanitized[k]))
        if break_cnt + cont_cnt >= 2:
            _add_violation(
                violations,
                seen,
                line_no,
                "A-1-9-2",
                get_code_snippet((start, end), code),
                f"break={break_cnt},continue={cont_cnt}",
            )

    # A-1-9-1: 多层循环嵌套（近似）
    for i, d in enumerate(depths, 1):
        if d >= 4:
            _add_violation(violations, seen, i, "A-1-9-1", get_code_snippet((i - 1, i - 1), code), f"depth={d}")


def detect_c_cpp_gjb_5_9_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中5.9（循环控制）条款的违规。

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


def analyze_c_cpp_gjb_5_9(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_c_cpp_gjb_5_9_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "c_basic_violations",
            "c",
            """
int main(void){
    int i = 0;
    for (i = 0; ; i++) {
        if (i > 20) { break; }
        i = i + 2;
    }

    while (1) {
        continue;
    }

    do {
        i++;
    } while (TRUE);

    for (int j = 0; j < 10; j++)
        i += j;

    return 0;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
static const int LIMIT = 10;

int main(){
    int i = 0;
    for (i = 0; i < LIMIT; i++) {
        if (i == 3) {
            break;
        }
    }

    while (i < LIMIT) {
        i++;
    }

    return 0;
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_c_cpp_gjb_5_9(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
