import re
from typing import Dict, List, Set, Tuple, Union


RULES_6_9 = [
    {"rule_id": "R-2-9-1", "message": "GJB R-2-9-1: 模板的声明、定义与实现必须在同一个文件之中", "severity": "高危"},
    {"rule_id": "A-2-9-1", "message": "GJB A-2-9-1: 建议模板参数列表中的类型参数使用typename关键字说明", "severity": "建议"},
    {"rule_id": "A-2-9-2", "message": "GJB A-2-9-2: 建议除常数指针外，const说明均在类型说明的最外层", "severity": "建议"},
    {"rule_id": "A-2-9-3", "message": "GJB A-2-9-3: 建议不要对&&、||、,进行操作符重载", "severity": "建议"},
    {"rule_id": "A-2-9-4", "message": "GJB A-2-9-4: 建议不使用以.h为后缀的头文件", "severity": "建议"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_6_9}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-2-9-UNKNOWN"


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
    if len(snippet) > 300:
        snippet = snippet[:300] + "..."
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
    msg = RULE_META[rule_id]["message"]
    if suffix:
        msg = f"{msg} ({suffix})"
    violations.append(
        {
            "line": line,
            "code_snippet": code_snippet,
            "violation_type": "编码规范",
            "severity": RULE_META[rule_id]["severity"],
            "rule_id": rule_id,
            "message": msg,
        }
    )


def _strip_line_comment(line: str) -> str:
    in_str = False
    q = ""
    out = []
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if not in_str and ch == "/" and nxt == "/":
            break
        if ch in ('\"', "'"):
            if not in_str:
                in_str = True
                q = ch
            elif i > 0 and line[i - 1] != "\\" and ch == q:
                in_str = False
                q = ""
        out.append(ch)
        i += 1
    return "".join(out)


def _scan_rules(lines: List[str], code: str, language: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    template_decl_lines: Dict[str, int] = {}
    template_impl_lines: Dict[str, int] = {}
    pending_template_line = 0

    for i, raw in enumerate(lines, 1):
        s = _strip_line_comment(raw).strip()
        if not s:
            continue

        # A-2-9-4: 头文件后缀 .h
        if re.search(r"^\s*#\s*include\s*[<\"][^>\"]+\.h[>\"]", s):
            _add_violation(violations, seen, i, "A-2-9-4", get_code_snippet((i - 1, i - 1), code), s)

        # A-2-9-3: 操作符重载 &&、||、,
        if re.search(r"\boperator\s*(?:&&|\|\||,)\s*\(", s):
            _add_violation(violations, seen, i, "A-2-9-3", get_code_snippet((i - 1, i - 1), code), s)

        # A-2-9-2: const 位置推荐（不推荐 int const b / int const *p）
        # 允许常数指针场景：int * const p
        if re.search(r"\b[A-Za-z_][A-Za-z0-9_:<>]*\s+const\s+\*\s*[A-Za-z_][A-Za-z0-9_]*", s):
            _add_violation(violations, seen, i, "A-2-9-2", get_code_snippet((i - 1, i - 1), code), "prefer const T *p")
        elif re.search(r"\b[A-Za-z_][A-Za-z0-9_:<>]*\s+const\s+[A-Za-z_][A-Za-z0-9_]*\b", s):
            if not re.search(r"\*\s*const\s+[A-Za-z_][A-Za-z0-9_]*", s):
                _add_violation(violations, seen, i, "A-2-9-2", get_code_snippet((i - 1, i - 1), code), "prefer const T x")

        # 模板相关：记录声明/实现
        # A-2-9-1: 建议 typename
        if re.search(r"\btemplate\s*<", s):
            pending_template_line = i
            if re.search(r"\bclass\s+[A-Za-z_][A-Za-z0-9_]*", s):
                _add_violation(violations, seen, i, "A-2-9-1", get_code_snippet((i - 1, i - 1), code), s)

        # 统计模板函数/类声明与实现
        # 简化匹配：template<...> class X; / template<...> class X { ... }
        m_tpl_class = re.search(r"\btemplate\s*<[^>]+>\s*class\s+([A-Za-z_][A-Za-z0-9_]*)", s)
        if m_tpl_class:
            name = m_tpl_class.group(1)
            template_decl_lines.setdefault(name, i)
            if "{" in s:
                template_impl_lines.setdefault(name, i)

        # 处理跨行模板类声明/定义：
        # template <...>
        # class X;
        if pending_template_line and (i == pending_template_line + 1):
            m_next_class = re.search(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\s*([;{])", s)
            if m_next_class:
                name = m_next_class.group(1)
                tail = m_next_class.group(2)
                template_decl_lines.setdefault(name, pending_template_line)
                if tail == "{":
                    template_impl_lines.setdefault(name, i)
            pending_template_line = 0
        elif pending_template_line and (i > pending_template_line + 1):
            pending_template_line = 0

        # 模板函数（同一行）
        m_tpl_fn = re.search(r"\btemplate\s*<[^>]+>\s+[A-Za-z_][A-Za-z0-9_:\s<>&\*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", s)
        if m_tpl_fn:
            name = m_tpl_fn.group(1)
            template_decl_lines.setdefault(name, i)
            if "{" in s:
                template_impl_lines.setdefault(name, i)

        # 模板外实现（粗粒度识别）：xxx<...>::foo(...)
        m_out_impl = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*<[^>]+>\s*::\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", s)
        if m_out_impl and "{" in s:
            name = m_out_impl.group(1)
            template_impl_lines.setdefault(name, i)

    # R-2-9-1: 模板声明、定义与实现需同文件（单文件分析里以“声明有但实现缺失”提示）
    for name, line in template_decl_lines.items():
        if name not in template_impl_lines:
            _add_violation(
                violations,
                seen,
                line,
                "R-2-9-1",
                get_code_snippet((line - 1, line - 1), code),
                f"template {name} declaration without implementation in current file",
            )


def detect_cpp_gjb_6_9_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中6.9（其他条款）条款的违规。

    Args:
        code: C++源码字符串
        language: 语言类型，支持"cpp"和"c++"

    Returns:
        list[dict]: 违规列表
    """
    if language not in ("cpp", "c++"):
        return []

    lines = code.split("\n")
    violations: List[dict] = []
    seen: Set[Tuple[int, str]] = set()

    _scan_rules(lines, code, language, violations, seen)

    return sorted(violations, key=lambda x: (x["line"], x["rule_id"]))


def analyze_cpp_gjb_6_9(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_cpp_gjb_6_9_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "cpp_basic_violations",
            "cpp",
            """
#include <iostream.h>      // A-2-9-4

template <class T>         // A-2-9-1
class Box;                 // R-2-9-1

int const b = 1;           // A-2-9-2
int const *p = &b;         // A-2-9-2

class Demo {
public:
    bool operator&&(const Demo &rhs);   // A-2-9-3
    bool operator||(const Demo &rhs);   // A-2-9-3
    int operator,(const Demo &rhs);     // A-2-9-3
};
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
#include <iostream>

template <typename T>
class Box {
public:
    T value;
};

const int b = 1;
const int *p = &b;
int * const cp = 0;

class Demo {
public:
    bool ok(const Demo &rhs);
};
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_cpp_gjb_6_9(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
