import re
from typing import Dict, List, Set, Tuple, Union


RULES_6_8 = [
    {"rule_id": "R-2-8-1", "message": "GJB R-2-8-1: 捕获的顺序必须按由派生类到基类的次序排序", "severity": "高危"},
    {"rule_id": "R-2-8-2", "message": "GJB R-2-8-2: 每个指定的抛出必须有与之匹配的捕获", "severity": "高危"},
    {"rule_id": "R-2-8-3", "message": "GJB R-2-8-3: 异常抛出的对象必须使用引用方式捕获", "severity": "高危"},
    {"rule_id": "R-2-8-4", "message": "GJB R-2-8-4: 缺省捕获必须放在所有指定捕获之后", "severity": "高危"},
    {"rule_id": "R-2-8-5", "message": "GJB R-2-8-5: 禁止显式直接抛出NULL", "severity": "高危"},
    {"rule_id": "A-2-8-1", "message": "GJB A-2-8-1: 建议在所有指定捕获之后使用缺省捕获防范遗漏的异常", "severity": "建议"},
    {"rule_id": "A-2-8-2", "message": "GJB A-2-8-2: 谨慎对指针类型进行抛出捕获", "severity": "建议"},
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_6_8}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-2-8-UNKNOWN"


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


def _collect_inheritance(lines: List[str]) -> Dict[str, str]:
    rel: Dict[str, str] = {}
    pat = re.compile(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*public\s+(?:virtual\s+)?([A-Za-z_][A-Za-z0-9_]*)")
    for raw in lines:
        s = _strip_line_comment(raw)
        m = pat.search(s)
        if m:
            rel[m.group(1)] = m.group(2)
    return rel


def _is_derived_of(child: str, parent: str, rel: Dict[str, str]) -> bool:
    cur = child
    visited: Set[str] = set()
    while cur in rel and cur not in visited:
        visited.add(cur)
        cur = rel[cur]
        if cur == parent:
            return True
    return False


def _collect_var_types(lines: List[str]) -> Dict[str, str]:
    var_types: Dict[str, str] = {}
    pat = re.compile(
        r"^\s*(?:const\s+|volatile\s+)?([A-Za-z_][A-Za-z0-9_:<>]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;|\()"
    )
    for raw in lines:
        s = _strip_line_comment(raw).strip()
        m = pat.match(s)
        if m:
            t = m.group(1).split("::")[-1]
            n = m.group(2)
            if t not in {"if", "for", "while", "switch", "catch", "throw", "return"}:
                var_types[n] = t
    return var_types


def _parse_throw_type(expr: str, var_types: Dict[str, str]) -> str:
    e = expr.strip()
    if not e:
        return ""
    if e.startswith("&"):
        return "ptr"
    if re.match(r"^(NULL|nullptr)\b", e):
        return "NULL"
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", e):
        return var_types.get(e, "")
    m_ctor = re.match(r"^([A-Za-z_][A-Za-z0-9_:]*)\s*(?:\(|\{)", e)
    if m_ctor:
        t = m_ctor.group(1)
        if t in {"throw", "static_cast", "reinterpret_cast", "const_cast", "dynamic_cast"}:
            return ""
        return t.split("::")[-1]
    return ""


def _parse_catch_type(param: str) -> Tuple[str, bool, bool, bool]:
    p = " ".join(param.replace("...", "...").split())
    if p == "...":
        return ("...", False, False, True)
    is_ptr = "*" in p
    is_ref = "&" in p
    # 去掉变量名，保留类型部分
    q = re.sub(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*$", "", p).strip()
    q = q.replace("const", "").replace("volatile", "")
    q = q.replace("&", "").replace("*", "").strip()
    q = q.split("::")[-1]
    return (q, is_ptr, is_ref, False)


def _scan_rules(lines: List[str], code: str, language: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    rel = _collect_inheritance(lines)
    var_types = _collect_var_types(lines)

    throw_items: List[Tuple[int, int, str, str]] = []
    catch_items: List[Tuple[int, int, str, bool, bool, bool]] = []

    throw_pat = re.compile(r"\bthrow\s+([^;]+);")
    catch_pat = re.compile(r"\bcatch\s*\(\s*([^\)]*)\s*\)")

    current_try_group = 0
    active_try_group = 0

    for i, raw in enumerate(lines, 1):
        s = _strip_line_comment(raw)

        if re.search(r"\btry\b", s):
            current_try_group += 1
            active_try_group = current_try_group

        for tm in throw_pat.finditer(s):
            expr = tm.group(1).strip()
            t = _parse_throw_type(expr, var_types)
            throw_items.append((i, active_try_group, expr, t))

            # R-2-8-5: throw NULL/nullptr
            if re.match(r"^(NULL|nullptr)\b", expr):
                _add_violation(violations, seen, i, "R-2-8-5", get_code_snippet((i - 1, i - 1), code), expr)

            # R-2-8-3: throw 地址形式通常导致指针捕获
            if expr.startswith("&"):
                _add_violation(violations, seen, i, "R-2-8-3", get_code_snippet((i - 1, i - 1), code), expr)

            # A-2-8-2: 指针抛出建议谨慎
            if expr.startswith("&") or "*" in expr:
                _add_violation(violations, seen, i, "A-2-8-2", get_code_snippet((i - 1, i - 1), code), f"throw {expr}")

        for cm in catch_pat.finditer(s):
            param = cm.group(1).strip()
            ctype, is_ptr, is_ref, is_default = _parse_catch_type(param)
            catch_items.append((i, active_try_group, ctype, is_ptr, is_ref, is_default))

            # R-2-8-3: 捕获必须使用引用
            if (not is_default) and (not is_ref):
                _add_violation(violations, seen, i, "R-2-8-3", get_code_snippet((i - 1, i - 1), code), param)

            # A-2-8-2: 指针捕获建议谨慎
            if is_ptr:
                _add_violation(violations, seen, i, "A-2-8-2", get_code_snippet((i - 1, i - 1), code), f"catch({param})")

    # R-2-8-4: catch(...) 必须最后
    for idx, (line, gid, ctype, _, _, is_default) in enumerate(catch_items):
        if not is_default:
            continue
        for _, later_gid, later_ctype, _, _, later_is_default in catch_items[idx + 1:]:
            if later_gid != gid:
                continue
            if not later_is_default and later_ctype:
                _add_violation(violations, seen, line, "R-2-8-4", get_code_snippet((line - 1, line - 1), code), "catch(...) position")
                break

    # R-2-8-1: 派生到基类顺序
    for i in range(len(catch_items)):
        line_i, gid_i, type_i, _, _, def_i = catch_items[i]
        if def_i or type_i == "":
            continue
        for j in range(i + 1, len(catch_items)):
            line_j, gid_j, type_j, _, _, def_j = catch_items[j]
            if gid_j != gid_i:
                continue
            if def_j or type_j == "":
                continue
            if _is_derived_of(type_j, type_i, rel):
                _add_violation(
                    violations,
                    seen,
                    line_i,
                    "R-2-8-1",
                    get_code_snippet((line_i - 1, line_i - 1), code),
                    f"{type_i} before {type_j}",
                )
                break

    # R-2-8-2: 每个throw需要匹配catch
    catches_by_gid: Dict[int, List[Tuple[str, bool]]] = {}
    for _, gid, ctype, _, _, is_default in catch_items:
        catches_by_gid.setdefault(gid, []).append((ctype, is_default))

    for line, gid, expr, t in throw_items:
        if not t or t in {"NULL", "ptr"}:
            continue
        group_catches = catches_by_gid.get(gid, [])
        has_default = any(x[1] for x in group_catches)
        if has_default:
            continue
        catch_types = [x[0] for x in group_catches if x[0]]
        matched = False
        for ct in catch_types:
            if ct == t or _is_derived_of(t, ct, rel):
                matched = True
                break
        if not matched:
            _add_violation(violations, seen, line, "R-2-8-2", get_code_snippet((line - 1, line - 1), code), expr)

    # A-2-8-1: 有指定catch但无缺省catch
    group_to_lines: Dict[int, List[Tuple[int, bool]]] = {}
    for line, gid, _, _, _, is_default in catch_items:
        group_to_lines.setdefault(gid, []).append((line, is_default))
    for gid, items in group_to_lines.items():
        has_specific = any(not is_default for _, is_default in items)
        has_default = any(is_default for _, is_default in items)
        if has_specific and (not has_default):
            line = items[-1][0]
            _add_violation(violations, seen, line, "A-2-8-1", get_code_snippet((line - 1, line - 1), code), "missing catch(...)")


def detect_cpp_gjb_6_8_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中6.8（异常处理）条款的违规。

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


def analyze_cpp_gjb_6_8(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_cpp_gjb_6_8_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "cpp_basic_violations",
            "cpp",
            """
class Document {};
class Book : public Document {};
class A1 {};
class A2 {};

int main() {
    Book mybook;
    try {
        throw mybook;
    }
    catch(Document &d) { }     // R-2-8-1
    catch(Book &b) { }         // R-2-8-1

    try {
        throw A2();             // R-2-8-2
    }
    catch(A1 &) { }

    try {
        Document d;
        throw &d;               // R-2-8-3, A-2-8-2
    }
    catch(Document *p) { }      // R-2-8-3, A-2-8-2

    try {
        throw Document();
    }
    catch(...) { }              // R-2-8-4
    catch(Document &d) { }

    try {
        throw NULL;             // R-2-8-5
    }
    catch(int &) { }

    return 0;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
class Document {};
class Book : public Document {};
class A1 {};
class A2 {};

int main() {
    Book mybook;
    try {
        throw mybook;
    }
    catch(Book &b) { }
    catch(Document &d) { }
    catch(...) { }

    try {
        throw A2();
    }
    catch(A2 &) { }
    catch(...) { }

    try {
        Document d;
        throw d;
    }
    catch(Document &r) { }
    catch(...) { }

    return 0;
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_cpp_gjb_6_8(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
