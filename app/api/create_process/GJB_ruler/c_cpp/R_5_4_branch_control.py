import re
from typing import Dict, List, Set, Tuple, Union


RULES_5_4 = [
    {
        "rule_id": "R-1-4-1",
        "message": "GJB R-1-4-1: 在if-else if语句中必须使用else分支",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-4-2",
        "message": "GJB R-1-4-2: 条件判定空分支必须使用分号并注释/*no deal with*/明确说明",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-4-3",
        "message": "GJB R-1-4-3: 禁止使用空switch语句",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-4-4",
        "message": "GJB R-1-4-4: 禁止对bool量使用switch语句",
        "severity": "低危",
    },
    {
        "rule_id": "R-1-4-5",
        "message": "GJB R-1-4-5: 禁止switch语句中只包含default语句",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-4-6",
        "message": "GJB R-1-4-6: 除枚举类型列举完全外，switch必须有default",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-4-7",
        "message": "GJB R-1-4-7: switch中的case/default必须以break或return终止，共用case需注释",
        "severity": "高危",
    },
    {
        "rule_id": "R-1-4-8",
        "message": "GJB R-1-4-8: switch语句所有分支必须具有相同层次范围",
        "severity": "中危",
    },
    {
        "rule_id": "A-1-4-1",
        "message": "GJB A-1-4-1: 避免层数过多的分支嵌套，建议最多不超过7层",
        "severity": "建议",
    },
]

RULE_META: Dict[str, dict] = {x["rule_id"]: x for x in RULES_5_4}


def extract_rule_id(message: str) -> str:
    m = re.search(r"[RA]-\d+-\d+-\d+", message or "")
    if m:
        return m.group(0)
    return "R-1-4-UNKNOWN"


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


def _max_branch_nesting(lines: List[str]) -> int:
    depth = 0
    max_depth = 0
    in_block_comment = False
    for raw in lines:
        line = raw
        i = 0
        while i < len(line):
            ch = line[i]
            nxt = line[i + 1] if i + 1 < len(line) else ""
            if not in_block_comment and ch == "/" and nxt == "*":
                in_block_comment = True
                i += 2
                continue
            if in_block_comment and ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            if in_block_comment:
                i += 1
                continue
            i += 1

        s = _strip_line_comment(line)
        if re.search(r"\b(if|else\s+if|switch|case|default)\b", s):
            depth += s.count("{")
            max_depth = max(max_depth, depth)
        depth -= s.count("}")
        if depth < 0:
            depth = 0
    return max_depth


def _scan_if_else_rules(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    # R-1-4-1: if-else if链必须有else（近似检测策略）
    # 近似检测策略：检测出现else if但当前链在遇到非else语句前没有else块。
    chain_open_line = None
    pending_chain = False

    for i, raw in enumerate(lines, 1):
        line = _strip_line_comment(raw).strip()
        if re.match(r"^if\s*\(", line):
            chain_open_line = i
            pending_chain = False
            continue

        if re.match(r"^else\s+if\s*\(", line):
            if chain_open_line is not None:
                pending_chain = True
            continue

        if re.match(r"^else\b", line):
            chain_open_line = None
            pending_chain = False
            continue

        if chain_open_line is not None and pending_chain and line:
            _add_violation(violations, seen, chain_open_line, "R-1-4-1", get_code_snippet((chain_open_line - 1, chain_open_line - 1), code))
            chain_open_line = None
            pending_chain = False

    if chain_open_line is not None and pending_chain:
        _add_violation(violations, seen, chain_open_line, "R-1-4-1", get_code_snippet((chain_open_line - 1, chain_open_line - 1), code))

    # R-1-4-2: 空分支必须 ;/*no deal with*/
    for i, raw in enumerate(lines, 1):
        line = raw.strip().lower()
        if re.match(r"^(if|else\s+if|else)\b", _strip_line_comment(raw).strip()):
            # 下一有效行若是空块或者单独;，检查注释
            j = i
            while j < len(lines):
                nxt_raw = lines[j]
                nxt = _strip_line_comment(nxt_raw).strip()
                if not nxt:
                    j += 1
                    continue

                if nxt in ("{}", "{", "}"):
                    # 空块场景，不算合规；要求 ;/*no deal with*/
                    _add_violation(violations, seen, i, "R-1-4-2", get_code_snippet((i - 1, min(i + 1, len(lines) - 1)), code), "empty-branch")
                elif nxt == ";":
                    low = nxt_raw.lower()
                    if "no deal with" not in low:
                        # 允许注释在同一行
                        _add_violation(violations, seen, j + 1, "R-1-4-2", get_code_snippet((j, j), code), "missing-no-deal-with")
                elif nxt.startswith(";/*"):
                    if "no deal with" not in nxt_raw.lower():
                        _add_violation(violations, seen, j + 1, "R-1-4-2", get_code_snippet((j, j), code), "bad-no-deal-with-comment")
                break


def _find_switch_blocks(lines: List[str]) -> List[Tuple[int, int]]:
    blocks = []
    i = 0
    while i < len(lines):
        line = _strip_line_comment(lines[i])
        if re.search(r"\bswitch\s*\(", line):
            # 找到第一个{
            j = i
            found = False
            while j < len(lines):
                if "{" in _strip_line_comment(lines[j]):
                    found = True
                    break
                j += 1
            if not found:
                i += 1
                continue

            start = i
            brace = 0
            k = j
            while k < len(lines):
                s = _strip_line_comment(lines[k])
                brace += s.count("{")
                brace -= s.count("}")
                if brace == 0:
                    blocks.append((start, k))
                    i = k
                    break
                k += 1
        i += 1
    return blocks


def _scan_switch_rules(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    blocks = _find_switch_blocks(lines)

    for s, e in blocks:
        header = _strip_line_comment(lines[s])
        body = lines[s:e + 1]
        body_stripped = [_strip_line_comment(x).strip() for x in body]

        case_lines = [idx for idx, x in enumerate(body_stripped, start=s + 1) if re.match(r"^case\b", x)]
        default_lines = [idx for idx, x in enumerate(body_stripped, start=s + 1) if re.match(r"^default\b", x)]

        # R-1-4-3 空switch
        has_non_trivial = any(x for x in body_stripped[1:-1] if x not in ("", "{", "}"))
        if not has_non_trivial:
            _add_violation(violations, seen, s + 1, "R-1-4-3", get_code_snippet((s, min(e, s + 2)), code))
            continue

        # R-1-4-4 switch(bool)
        # 近似检测策略：switch条件中包含比较运算或显式bool标识。
        cond_m = re.search(r"\bswitch\s*\((.*)\)", header)
        if cond_m:
            cond = cond_m.group(1)
            if re.search(r"(==|!=|>=|<=|>|<)", cond) or re.search(r"\bbool\b", cond):
                _add_violation(violations, seen, s + 1, "R-1-4-4", get_code_snippet((s, s), code))

        # R-1-4-5 只有default
        if default_lines and not case_lines:
            _add_violation(violations, seen, default_lines[0], "R-1-4-5", get_code_snippet((default_lines[0] - 1, default_lines[0] - 1), code))

        # R-1-4-6 缺少default
        if not default_lines:
            _add_violation(violations, seen, s + 1, "R-1-4-6", get_code_snippet((s, s), code))

        # R-1-4-7 case/default终止与shared注释
        labels = []
        for idx in range(s, e + 1):
            x = _strip_line_comment(lines[idx]).strip()
            if re.match(r"^case\b", x) or re.match(r"^default\b", x):
                labels.append(idx)

        for p, label_idx in enumerate(labels):
            next_idx = labels[p + 1] if p + 1 < len(labels) else e + 1
            segment = lines[label_idx:next_idx]
            segment_join = "\n".join(_strip_line_comment(x).strip() for x in segment)

            # 若直接落到下一个label且无break/return
            if not re.search(r"\b(break|return)\b", segment_join):
                # 检查是否是共用case注释
                first = segment[0].lower()
                if "shared" not in first:
                    _add_violation(violations, seen, label_idx + 1, "R-1-4-7", get_code_snippet((label_idx, min(e, label_idx + 2)), code), "missing-break-return-or-shared")

        # R-1-4-8 分支层次范围一致（近似检测策略）
        # 近似检测策略：在switch块内部若出现case/default处于更深嵌套层，视为违规。
        depth = 0
        base_case_depth = None
        for idx in range(s, e + 1):
            sline = _strip_line_comment(lines[idx])
            if re.match(r"\s*(case\b|default\b)", sline):
                if base_case_depth is None:
                    base_case_depth = depth
                elif depth != base_case_depth:
                    _add_violation(violations, seen, idx + 1, "R-1-4-8", get_code_snippet((idx, idx), code))
                    break
            depth += sline.count("{")
            depth -= sline.count("}")
            if depth < 0:
                depth = 0


def _scan_advisory(lines: List[str], violations: List[dict], seen: Set[Tuple[int, str]], code: str):
    nest = _max_branch_nesting(lines)
    if nest > 7:
        _add_violation(
            violations,
            seen,
            1,
            "A-1-4-1",
            get_code_snippet((0, min(6, len(lines) - 1)), code),
            f"max-depth={nest}",
        )


def detect_c_cpp_gjb_5_4_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中5.4（分支控制）条款的违规。

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

    _scan_if_else_rules(lines, violations, seen, code)
    _scan_switch_rules(lines, violations, seen, code)
    _scan_advisory(lines, violations, seen, code)

    return sorted(violations, key=lambda x: (x["line"], x["rule_id"]))


def analyze_c_cpp_gjb_5_4(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_c_cpp_gjb_5_4_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "c_if_else_if_no_else",
            "c",
            """
int main(void){
    int i = 0;
    if(i == 0){ i = 1; }
    else if(i == 1){ i = 2; }
    i = 3;
    return 0;
}
""",
        ),
        (
            "c_empty_branch_without_no_deal_with",
            "c",
            """
int main(void){
    int i = 0;
    if(i == 0)
        ;
    return 0;
}
""",
        ),
        (
            "c_empty_switch_and_no_default",
            "c",
            """
int main(void){
    int i = 0;
    switch(i){
    }
    return 0;
}
""",
        ),
        (
            "c_switch_only_default",
            "c",
            """
int main(void){
    int i = 0;
    switch(i){
        default:
            break;
    }
    return 0;
}
""",
        ),
        (
            "c_switch_fallthrough_without_shared",
            "c",
            """
int main(void){
    int i = 1;
    switch(i){
        case 1:
            i++;
        case 2:
            i += 2;
            break;
        default:
            break;
    }
    return 0;
}
""",
        ),
        (
            "c_switch_nested_case_depth",
            "c",
            """
int main(void){
    int x=2, y=0;
    switch(x){
        case 1:
            if(y==0){
                case 2:
                    y = 1;
                    break;
            }
            break;
        default:
            break;
    }
    return 0;
}
""",
        ),
        (
            "cpp_compliant_sample",
            "cpp",
            """
int main(void){
    int i = 0;
    if(i == 0){
        i = 1;
    } else if(i == 1){
        i = 2;
    } else {
        ;/*no deal with*/
    }

    switch(i){
        case 1:
            i += 1;
            break;
        case 2:/*shared*/
        case 3:
            i += 2;
            break;
        default:
            i = 0;
            break;
    }
    return 0;
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_c_cpp_gjb_5_4(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
