import re
from typing import Dict, List, Set, Tuple, Union


RULES_6_6 = [
    {"rule_id": "R-2-6-1", "message": "GJB R-2-6-1: 使用new分配的内存空间，用完后必须使用delete释放", "severity": "高危"},
    {"rule_id": "R-2-6-2", "message": "GJB R-2-6-2: 必须使用delete[]释放new[]分配的内存空间", "severity": "高危"},
    {"rule_id": "R-2-6-3", "message": "GJB R-2-6-3: 被delete的指针必须指向最初new分配的地址", "severity": "高危"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_6_6}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-2-6-UNKNOWN"


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
        if ch in ('"', "'"):
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
    # 指针生命周期状态
    ptr_state: Dict[str, Dict[str, Union[str, int, bool]]] = {}

    def _flush_unfreed(current_state: Dict[str, Dict[str, Union[str, int, bool]]]):
        for p, st in current_state.items():
            if bool(st["freed"]):
                continue
            if st.get("alias_of") != p:
                continue
            line_no = int(st["alloc_line"])
            _add_violation(
                violations,
                seen,
                line_no,
                "R-2-6-1",
                get_code_snippet((line_no - 1, line_no - 1), code),
                f"{p}:{st['alloc']}",
            )

    for i, raw in enumerate(lines, 1):
        s = _strip_line_comment(raw)

        # 粗粒度函数边界：进入新函数时重置状态，避免同名局部变量跨函数污染
        if re.search(r"\)\s*\{\s*$", s) and not re.search(r"\b(if|for|while|switch|catch)\b", s):
            _flush_unfreed(ptr_state)
            ptr_state = {}

        # new/new[] 赋值
        m_new = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+[^;\[]+;", s)
        m_new_arr = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+[^;]+\[.+\]\s*;", s)

        if m_new_arr:
            p = m_new_arr.group(1)
            ptr_state[p] = {
                "alloc": "new[]",
                "alloc_line": i,
                "freed": False,
                "moved": False,
                "alias_of": p,
            }
        elif m_new:
            p = m_new.group(1)
            ptr_state[p] = {
                "alloc": "new",
                "alloc_line": i,
                "freed": False,
                "moved": False,
                "alias_of": p,
            }

        # 备份指针关系：int *pbak = p;
        m_alias = re.search(
            r"^\s*(?:[A-Za-z_][A-Za-z0-9_:\s<>\*&,]+)?\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*;\s*$",
            s,
        )
        if m_alias:
            dst = m_alias.group(1)
            src = m_alias.group(2)
            if src in ptr_state:
                root = str(ptr_state[src].get("alias_of") or src)
                ptr_state[dst] = {
                    "alloc": ptr_state[src]["alloc"],
                    "alloc_line": ptr_state[src]["alloc_line"],
                    "freed": bool(ptr_state[src]["freed"]),
                    "moved": bool(ptr_state[src]["moved"]),
                    "alias_of": root,
                }

        # 指针偏移导致不再指向原始地址
        m_shift = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(\+\+|--|\+=|-=)", s)
        if not m_shift:
            m_pre_shift = re.search(r"(\+\+|--)\s*([A-Za-z_][A-Za-z0-9_]*)", s)
            if m_pre_shift:
                p = m_pre_shift.group(2)
                if p in ptr_state and not bool(ptr_state[p]["freed"]):
                    ptr_state[p]["moved"] = True
        if m_shift:
            p = m_shift.group(1)
            if p in ptr_state and not bool(ptr_state[p]["freed"]):
                ptr_state[p]["moved"] = True

        # delete / delete[]
        m_del_arr = re.search(r"\bdelete\s*\[\s*\]\s*([A-Za-z_][A-Za-z0-9_]*)\s*;", s)
        m_del = re.search(r"\bdelete\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", s)

        if m_del_arr:
            p = m_del_arr.group(1)
            if p in ptr_state:
                # R-2-6-2: new[] -> 必须 delete[]
                if ptr_state[p]["alloc"] != "new[]":
                    _add_violation(violations, seen, i, "R-2-6-2", get_code_snippet((i - 1, i - 1), code), f"delete[] on {ptr_state[p]['alloc']}")

                # R-2-6-3: delete 的必须是原始地址
                if bool(ptr_state[p]["moved"]):
                    _add_violation(violations, seen, i, "R-2-6-3", get_code_snippet((i - 1, i - 1), code), p)

                root = str(ptr_state[p].get("alias_of") or p)
                for name, st in ptr_state.items():
                    if str(st.get("alias_of") or name) == root:
                        st["freed"] = True
        elif m_del:
            p = m_del.group(1)
            if p in ptr_state:
                # R-2-6-2: new[] 禁止 delete
                if ptr_state[p]["alloc"] == "new[]":
                    _add_violation(violations, seen, i, "R-2-6-2", get_code_snippet((i - 1, i - 1), code), p)

                # R-2-6-3: delete 的必须是原始地址
                if bool(ptr_state[p]["moved"]):
                    _add_violation(violations, seen, i, "R-2-6-3", get_code_snippet((i - 1, i - 1), code), p)

                root = str(ptr_state[p].get("alias_of") or p)
                for name, st in ptr_state.items():
                    if str(st.get("alias_of") or name) == root:
                        st["freed"] = True

    # R-2-6-1: 文件结束时再检查一次未释放
    _flush_unfreed(ptr_state)


def detect_cpp_gjb_6_6_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中6.6（内存释放）条款的违规。

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


def analyze_cpp_gjb_6_6(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_cpp_gjb_6_6_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "cpp_basic_violations",
            "cpp",
            """
int fun1(){
    int *p = new int;   // R-2-6-1
    *p = 1;
    return 0;
}

int fun2(){
    int *p = new int[3];
    p[0] = 1;
    delete p;           // R-2-6-2
    return 0;
}

int fun3(){
    int *p = new int[3];
    p++;
    delete[] p;         // R-2-6-3
    return 0;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
int fun1(){
    int *p = new int;
    *p = 1;
    delete p;
    p = 0;
    return 0;
}

int fun2(){
    int *p = new int[3];
    int *pbak = p;
    p[0] = 1;
    p++;
    delete[] pbak;
    pbak = 0;
    return 0;
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_cpp_gjb_6_6(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
