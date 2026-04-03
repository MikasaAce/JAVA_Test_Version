import re
from typing import Dict, List, Set, Tuple, Union


RULES_5_2 = [
    {
        "rule_id": "R-1-2-1",
        "message": "GJB R-1-2-1: 循环体必须用大括号括起来",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-2-2",
        "message": "GJB R-1-2-2: if、else if、else必须用大括号括起来",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-2-3",
        "message": "GJB R-1-2-3: 禁止在头文件前有可执行代码",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-2-4",
        "message": "GJB R-1-2-4: 引起二义性的逻辑表达式必须用括号显式说明优先级",
        "severity": "低危",
    },
    {
        "rule_id": "R-1-2-5",
        "message": "GJB R-1-2-5: 逻辑判别表达式中的运算项必须使用括号",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-2-6",
        "message": "GJB R-1-2-6: 禁止嵌套注释",
        "severity": "中危",
    },
    {
        "rule_id": "A-1-2-1",
        "message": "GJB A-1-2-1: 一个文件中的语句总行建议不超过2000行",
        "severity": "建议",
    },
    {
        "rule_id": "A-1-2-2",
        "message": "GJB A-1-2-2: 一个函数中的语句总行建议不超过200行",
        "severity": "建议",
    },
    {
        "rule_id": "A-1-2-3",
        "message": "GJB A-1-2-3: C语言建议使用/* */注释，谨慎使用//注释",
        "severity": "建议",
    },
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_5_2}


def extract_rule_id(message: str) -> str:
    match = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if match:
        return match.group(0)
    return "R-1-2-UNKNOWN"


def get_code_snippet(node_or_span: Union[Tuple[int, int], object], code: str, context_lines: int = 2) -> str:
    lines = code.split("\n")
    if isinstance(node_or_span, tuple):
        start_line, end_line = node_or_span
    else:
        start_line = getattr(node_or_span, "start_point", (0, 0))[0]
        end_line = getattr(node_or_span, "end_point", (start_line, 0))[0]

    start = max(0, start_line - context_lines)
    end = min(len(lines), end_line + context_lines + 1)
    snippet = "\n".join(lines[start:end])
    if len(snippet) > 240:
        snippet = snippet[:240] + "..."
    return snippet


def _add_violation(
    violations: List[dict],
    seen: Set[Tuple[int, str]],
    line: int,
    rule_id: str,
    code_snippet: str,
    message_suffix: str = "",
):
    if (line, rule_id) in seen:
        return
    seen.add((line, rule_id))

    meta = RULE_META[rule_id]
    message = meta["message"]
    if message_suffix:
        message = f"{message} ({message_suffix})"

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
    i = 0
    out = []
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if not in_string and ch == "/" and nxt == "/":
            break
        if ch in ('"', "'"):
            if not in_string:
                in_string = True
                quote = ch
            elif line[i - 1] != "\\" and ch == quote:
                in_string = False
                quote = ""
        out.append(ch)
        i += 1
    return "".join(out)


def _collect_block_comment_ranges(lines: List[str]) -> List[Tuple[int, int]]:
    ranges = []
    in_block = False
    start = -1
    for i, line in enumerate(lines):
        j = 0
        while j < len(line):
            nxt = line[j + 1] if j + 1 < len(line) else ""
            if not in_block and line[j] == "/" and nxt == "*":
                in_block = True
                start = i
                j += 2
                continue
            if in_block and line[j] == "*" and nxt == "/":
                in_block = False
                ranges.append((start, i))
                start = -1
                j += 2
                continue
            j += 1
    if in_block:
        ranges.append((start, len(lines) - 1))
    return ranges


def _is_inside_block_comment(line_no0: int, comment_ranges: List[Tuple[int, int]]) -> bool:
    for s, e in comment_ranges:
        if s <= line_no0 <= e:
            return True
    return False


def _find_function_ranges(lines: List[str]) -> List[Tuple[int, int]]:
    ranges = []
    start = None
    brace = 0
    pending_signature = None
    for i, raw in enumerate(lines):
        line = _strip_line_comment(raw)
        if start is None:
            if re.search(r"\)\s*\{\s*$", line) and not re.match(r"\s*(if|for|while|switch)\b", line):
                start = i
                brace = line.count("{") - line.count("}")
                pending_signature = None
            elif re.search(r"\)\s*$", line) and not re.match(r"\s*(if|for|while|switch)\b", line):
                pending_signature = i
            elif pending_signature is not None and re.match(r"^\s*\{\s*$", line):
                start = pending_signature
                brace = 1
                pending_signature = None
            elif pending_signature is not None and line.strip():
                pending_signature = None
        else:
            brace += line.count("{") - line.count("}")
            if brace <= 0:
                ranges.append((start, i))
                start = None
    return ranges


def _scan_loops_without_braces(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    loop_pat = re.compile(r"^\s*(for|while)\s*\((.*)\)\s*(.*)$")
    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw).strip()
        m = loop_pat.match(line)
        if not m:
            continue
        tail = m.group(3).strip()
        if tail.startswith("{"):
            continue
        if tail == "":
            # 下一行必须是{
            if i < len(lines) and _strip_line_comment(lines[i]).strip().startswith("{"):
                continue
            _add_violation(violations, seen, i, "R-1-2-1", get_code_snippet((i - 1, i - 1), code))
        else:
            # 单行循环体无大括号
            _add_violation(violations, seen, i, "R-1-2-1", get_code_snippet((i - 1, i - 1), code))


def _scan_if_else_without_braces(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    if_pat = re.compile(r"^\s*if\s*\((.*)\)\s*(.*)$")
    else_if_pat = re.compile(r"^\s*else\s+if\s*\((.*)\)\s*(.*)$")
    else_pat = re.compile(r"^\s*else\s*(.*)$")

    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw).strip()

        m_if = if_pat.match(line)
        m_eif = else_if_pat.match(line)
        m_else = else_pat.match(line)

        if m_if:
            tail = m_if.group(2).strip()
            if tail.startswith("{"):
                continue
            if tail == "":
                if i < len(lines) and _strip_line_comment(lines[i]).strip().startswith("{"):
                    continue
            _add_violation(violations, seen, i, "R-1-2-2", get_code_snippet((i - 1, i - 1), code), "if")
            continue

        if m_eif:
            tail = m_eif.group(2).strip()
            if tail.startswith("{"):
                continue
            if tail == "":
                if i < len(lines) and _strip_line_comment(lines[i]).strip().startswith("{"):
                    continue
            _add_violation(violations, seen, i, "R-1-2-2", get_code_snippet((i - 1, i - 1), code), "else if")
            continue

        if m_else:
            tail = m_else.group(1).strip()
            if line.startswith("else if"):
                continue
            if tail.startswith("{"):
                continue
            if tail == "":
                if i < len(lines) and _strip_line_comment(lines[i]).strip().startswith("{"):
                    continue
            _add_violation(violations, seen, i, "R-1-2-2", get_code_snippet((i - 1, i - 1), code), "else")


def _scan_include_order(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    include_seen = False
    executable_before_include = False

    for i, raw in enumerate(lines, 1):
        stripped = _strip_line_comment(raw).strip()
        if not stripped:
            continue
        if stripped.startswith("#include"):
            include_seen = True
            if executable_before_include:
                _add_violation(violations, seen, i, "R-1-2-3", get_code_snippet((i - 1, i - 1), code))
            continue

        # 粗略判断可执行代码
        if not stripped.startswith("#"):
            if any(tok in stripped for tok in ("=", "(", ";", "{")):
                executable_before_include = True


def _scan_ambiguous_logic(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    cond_pat = re.compile(r"\b(if|while)\s*\((.*)\)")
    for i, raw in enumerate(lines, 1):
        stripped = _strip_line_comment(raw)
        m = cond_pat.search(stripped)
        if not m:
            continue
        expr = m.group(2)

        # R-1-2-4: 近似检测策略，混用&&/||且缺少显式括号
        if "&&" in expr and "||" in expr and "(" not in expr:
            _add_violation(violations, seen, i, "R-1-2-4", get_code_snippet((i - 1, i - 1), code))

        # R-1-2-5: 近似检测策略，位运算与比较直接混用，未把位运算项括起来
        # 典型违背：if(tbc&0x80==0x80)
        if re.search(r"[^\(]\b[A-Za-z_][A-Za-z0-9_]*\s*[&|^]\s*[^\)]+\s*(==|!=|>=|<=|>|<)", expr):
            if not re.search(r"\([^\)]*[&|^][^\)]*\)\s*(==|!=|>=|<=|>|<)", expr):
                _add_violation(violations, seen, i, "R-1-2-5", get_code_snippet((i - 1, i - 1), code))


def _scan_nested_comments(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    in_block = False
    for i, line in enumerate(lines, 1):
        j = 0
        while j < len(line):
            nxt = line[j + 1] if j + 1 < len(line) else ""
            if line[j] == "/" and nxt == "*":
                if in_block:
                    _add_violation(violations, seen, i, "R-1-2-6", get_code_snippet((i - 1, i - 1), code))
                in_block = True
                j += 2
                continue
            if line[j] == "*" and nxt == "/":
                in_block = False
                j += 2
                continue
            j += 1


def _scan_advisory_rules(lines: List[str], language: str, violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    # A-1-2-1 文件总行
    if len(lines) > 2000:
        _add_violation(
            violations,
            seen,
            1,
            "A-1-2-1",
            get_code_snippet((0, min(5, len(lines) - 1)), code),
            f"当前行数={len(lines)}",
        )

    # A-1-2-2 函数总行
    func_ranges = _find_function_ranges(lines)
    for s, e in func_ranges:
        func_len = e - s + 1
        if func_len > 200:
            _add_violation(
                violations,
                seen,
                s + 1,
                "A-1-2-2",
                get_code_snippet((s, min(e, s + 3)), code),
                f"函数行数={func_len}",
            )

    # A-1-2-3 C语言中谨慎使用//
    if language == "c":
        for i, raw in enumerate(lines, 1):
            if "//" in raw:
                _add_violation(
                    violations,
                    seen,
                    i,
                    "A-1-2-3",
                    get_code_snippet((i - 1, i - 1), code),
                )


def detect_c_cpp_gjb_5_2_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中5.2（版面书写）条款的违规。

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

    _scan_loops_without_braces(lines, violations, seen, code)
    _scan_if_else_without_braces(lines, violations, seen, code)
    _scan_include_order(lines, violations, seen, code)
    _scan_ambiguous_logic(lines, violations, seen, code)
    _scan_nested_comments(lines, violations, seen, code)
    _scan_advisory_rules(lines, language, violations, seen, code)

    return sorted(violations, key=lambda x: (x["line"], x["rule_id"]))


def analyze_c_cpp_gjb_5_2(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_c_cpp_gjb_5_2_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "c_loop_without_braces",
            "c",
            """
int main(void){
    int i;
    int data[3];
    for(i=0;i<3;i++)
        data[i]=0;
    return 0;
}
""",
        ),
        (
            "c_if_else_without_braces",
            "c",
            """
int main(void){
    int i=0,j=0;
    if(i==0)
        j=1;
    else
        j=2;
    return 0;
}
""",
        ),
        (
            "c_include_after_executable",
            "c",
            """
int a = 0;
#include "x.h"
int main(void){ return 0; }
""",
        ),
        (
            "c_ambiguous_logic_and_operand",
            "c",
            """
int main(void){
    unsigned int tbc = 0x80;
    int i = 0, j = 1, k = 2;
    if(i==0 || j==1 && k==2){ i = 1; }
    if(tbc&0x80==0x80){ i = 2; }
    return 0;
}
""",
        ),
        (
            "c_nested_comment",
            "c",
            """
int main(void){
    /* level1
       /* level2 */
    */
    return 0;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
#include "x.h"
int main(void){
    int i = 0;
    int data[3] = {0,0,0};
    for(i=0;i<3;i++){
        data[i] = i;
    }
    if((i==3) || (data[0]==0)){
        return 0;
    } else {
        return 1;
    }
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_c_cpp_gjb_5_2(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
