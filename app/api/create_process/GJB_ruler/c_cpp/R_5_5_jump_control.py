import re
from typing import Dict, List, Set, Tuple, Union


RULES_5_5 = [
    {
        "rule_id": "R-1-5-1",
        "message": "GJB R-1-5-1: 禁止从复合语句外goto到复合语句内，或由下向上goto",
        "severity": "高危",
    },
    {
        "rule_id": "R-1-5-2",
        "message": "GJB R-1-5-2: 禁止使用setjmp/longjmp",
        "severity": "高危",
    },
    {
        "rule_id": "A-1-5-1",
        "message": "GJB A-1-5-1: 谨慎使用goto语句",
        "severity": "建议",
    },
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_5_5}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-1-5-UNKNOWN"


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
    if len(snippet) > 260:
        snippet = snippet[:260] + "..."
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
    in_string = False
    quote = ""
    out = []
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if not in_string and ch == "/" and nxt == "/":
            break
        if ch in ('"', "'"):
            if not in_string:
                in_string = True
                quote = ch
            elif i > 0 and line[i - 1] != "\\" and ch == quote:
                in_string = False
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


def _find_function_blocks(lines: List[str]) -> List[Tuple[int, int]]:
    blocks = []
    start = None
    brace = 0
    pending_sig = None

    for i, raw in enumerate(lines):
        line = raw
        if start is None:
            if re.search(r"\)\s*\{\s*$", line) and not re.match(r"\s*(if|for|while|switch)\b", line):
                start = i
                brace = line.count("{") - line.count("}")
                pending_sig = None
            elif re.search(r"\)\s*$", line) and not re.match(r"\s*(if|for|while|switch)\b", line):
                pending_sig = i
            elif pending_sig is not None and re.match(r"^\s*\{\s*$", line):
                start = pending_sig
                brace = 1
                pending_sig = None
            elif pending_sig is not None and line.strip():
                pending_sig = None
        else:
            brace += line.count("{") - line.count("}")
            if brace <= 0:
                blocks.append((start, i))
                start = None
    return blocks


def _compute_depth(lines: List[str]) -> List[int]:
    depth = 0
    depths = []
    for line in lines:
        # 该行语句执行前的深度
        depths.append(depth)
        depth += line.count("{")
        depth -= line.count("}")
        if depth < 0:
            depth = 0
    return depths


def _scan_setjmp_longjmp(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    for i, line in enumerate(lines, 1):
        if re.search(r"\b(setjmp|longjmp)\s*\(", line):
            _add_violation(
                violations,
                seen,
                i,
                "R-1-5-2",
                get_code_snippet((i - 1, i - 1), code),
            )


def _scan_goto_rules(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    blocks = _find_function_blocks(lines)
    depths = _compute_depth(lines)

    label_pat = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(?!\s*//)")
    goto_pat = re.compile(r"\bgoto\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")

    # 全局建议：出现goto就提示A-1-5-1
    for i, line in enumerate(lines, 1):
        if goto_pat.search(line):
            _add_violation(
                violations,
                seen,
                i,
                "A-1-5-1",
                get_code_snippet((i - 1, i - 1), code),
            )

    # 强制规则在函数粒度做匹配
    for s, e in blocks:
        labels: Dict[str, int] = {}
        gotos: List[Tuple[int, str]] = []

        for idx in range(s, e + 1):
            line = lines[idx]
            m_label = label_pat.match(line)
            if m_label:
                labels[m_label.group(1)] = idx + 1

            for m_goto in goto_pat.finditer(line):
                gotos.append((idx + 1, m_goto.group(1)))

        for g_line, target in gotos:
            l_line = labels.get(target)
            if not l_line:
                continue

            # 由下向上goto（label在上，goto在下）
            if l_line < g_line:
                _add_violation(
                    violations,
                    seen,
                    g_line,
                    "R-1-5-1",
                    get_code_snippet((g_line - 1, g_line - 1), code),
                    f"upward-goto:{target}",
                )
                continue

            # 从复合语句外跳入复合语句内（近似检测策略）
            # 近似检测策略：目标label深度 > goto语句深度，认为跳入更深层复合语句。
            g_depth = depths[g_line - 1]
            l_depth = depths[l_line - 1]
            if l_depth > g_depth:
                _add_violation(
                    violations,
                    seen,
                    g_line,
                    "R-1-5-1",
                    get_code_snippet((g_line - 1, g_line - 1), code),
                    f"jump-into-block:{target}",
                )


def detect_c_cpp_gjb_5_5_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中5.5（跳转控制）条款的违规。

    Args:
        code: C/C++源码字符串
        language: 语言类型，支持"c"和"cpp"

    Returns:
        list[dict]: 违规列表
    """
    if language not in ("c", "cpp"):
        return []

    raw_lines = code.split("\n")
    lines = _sanitize_lines(raw_lines)

    violations: List[dict] = []
    seen: Set[Tuple[int, str]] = set()

    _scan_setjmp_longjmp(lines, violations, seen, code)
    _scan_goto_rules(lines, violations, seen, code)

    return sorted(violations, key=lambda x: (x["line"], x["rule_id"]))


def analyze_c_cpp_gjb_5_5(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_c_cpp_gjb_5_5_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "c_upward_goto",
            "c",
            """
int main(void){
    int i = 0;
L0:
    i = i + 1;
    if(i < 3){
        goto L0;
    }
    return 0;
}
""",
        ),
        (
            "c_jump_into_block",
            "c",
            """
int main(void){
    int j = -1;
    if(j < 0){
L1:
        j = 0;
    }
    goto L1;
    return 0;
}
""",
        ),
        (
            "c_setjmp_longjmp",
            "c",
            """
#include <setjmp.h>
jmp_buf mark;
int main(void){
    int r = setjmp(mark);
    if(r == 0){
        longjmp(mark, -1);
    }
    return 0;
}
""",
        ),
        (
            "cpp_only_advisory_goto",
            "cpp",
            """
int main(void){
    int i = 0;
L2:
    i++;
    if(i < 2){
        goto L2;
    }
    return 0;
}
""",
        ),
        (
            "cpp_compliant_no_goto",
            "cpp",
            """
int main(void){
    int i = 0;
    while(i < 3){
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
        results = analyze_c_cpp_gjb_5_5(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
