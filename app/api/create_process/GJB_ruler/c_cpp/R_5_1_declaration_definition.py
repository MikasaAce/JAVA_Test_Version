import os
import re
from typing import Dict, List, Optional, Set, Tuple, Union

try:
    from tree_sitter import Language, Parser
except Exception:
    Language = None
    Parser = None


RULES_5_1_MANDATORY = [
    {
        "rule_id": "R-1-1-1",
        "message": "GJB R-1-1-1: 禁止通过宏定义改变关键字和基本类型含义",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-2",
        "message": "GJB R-1-1-2: 禁止将其他标识宏定义为关键字和基本类型",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-3",
        "message": "GJB R-1-1-3: 用typedef自定义的类型禁止被重新定义",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-4",
        "message": "GJB R-1-1-4: 禁止重新定义C或C++关键字",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-5",
        "message": "GJB R-1-1-5: 禁止#define被重复定义（未先#undef）",
        "severity": "低危",
    },
    {
        "rule_id": "R-1-1-6",
        "message": "GJB R-1-1-6: 函数中的#define和#undef必须配对使用",
        "severity": "低危",
    },
    {
        "rule_id": "R-1-1-7",
        "message": "GJB R-1-1-7: 函数式宏参数和结果必须使用括号",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-8",
        "message": "GJB R-1-1-8: 结构、联合、枚举定义必须定义标识名",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-9",
        "message": "GJB R-1-1-9: 结构体定义中禁止含有无名结构体",
        "severity": "低危",
    },
    {
        "rule_id": "R-1-1-10",
        "message": "GJB R-1-1-10: 位定义的有符号整型变量位长必须大于1",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-11",
        "message": "GJB R-1-1-11: 位定义的整数型变量必须明确定义有符号或无符号",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-12",
        "message": "GJB R-1-1-12: 位定义变量应同长度类型且不跨越类型长度",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-13",
        "message": "GJB R-1-1-13: 函数声明必须声明参数类型并带变量名",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-14",
        "message": "GJB R-1-1-14: 函数声明必须与函数原型一致",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-15",
        "message": "GJB R-1-1-15: 函数中的参数必须使用类型声明",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-16",
        "message": "GJB R-1-1-16: 外部声明变量类型必须与定义一致",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-17",
        "message": "GJB R-1-1-17: 禁止在函数体内使用extern声明",
        "severity": "低危",
    },
    {
        "rule_id": "R-1-1-18",
        "message": "GJB R-1-1-18: 数组定义禁止没有显式边界限定",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-19",
        "message": "GJB R-1-1-19: 禁止使用extern声明对变量初始化",
        "severity": "中危",
    },
    {
        "rule_id": "R-1-1-20",
        "message": "GJB R-1-1-20: 用于数值计算的char变量必须显式signed/unsigned",
        "severity": "建议",
    },
    {
        "rule_id": "R-1-1-21",
        "message": "GJB R-1-1-21: 禁止在#include语句中使用绝对路径",
        "severity": "低危",
    },
    {
        "rule_id": "R-1-1-22",
        "message": "GJB R-1-1-22: 禁止头文件重复包含",
        "severity": "低危",
    },
    {
        "rule_id": "R-1-1-23",
        "message": "GJB R-1-1-23: 函数参数表为空时必须使用void明确说明",
        "severity": "中危",
    },
]

RULE_META = {x["rule_id"]: x for x in RULES_5_1_MANDATORY}

C_CPP_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double",
    "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long",
    "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct",
    "switch", "typedef", "union", "unsigned", "void", "volatile", "while", "_Bool",
    "_Complex", "_Imaginary", "class", "namespace", "template", "typename", "public",
    "private", "protected", "virtual", "new", "delete", "this", "try", "catch", "throw",
    "operator", "using", "friend", "nullptr", "bool", "wchar_t", "constexpr", "decltype",
    "cout", "cin", "endl",
}

BASIC_TYPES = {
    "char", "short", "int", "long", "float", "double", "void", "signed", "unsigned", "bool",
}

TYPE_BIT_WIDTH = {
    "char": 8,
    "signed char": 8,
    "unsigned char": 8,
    "short": 16,
    "short int": 16,
    "signed short": 16,
    "unsigned short": 16,
    "int": 32,
    "signed int": 32,
    "unsigned int": 32,
    "long": 32,
    "long int": 32,
    "signed long": 32,
    "unsigned long": 32,
    "long long": 64,
    "signed long long": 64,
    "unsigned long long": 64,
}


def _get_language_library_path() -> Optional[str]:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(current_dir, "..", "..", "build", "languages.so"),
        os.path.join(current_dir, "..", "..", "build", "languages.dll"),
        "/home2/JAVA_Test_Version/app/api/create_process/build/languages.so",
    ]
    for p in candidates:
        p_norm = os.path.abspath(p)
        if os.path.exists(p_norm):
            return p_norm
    return None


def _build_languages() -> Dict[str, object]:
    if Language is None:
        return {}

    lib = _get_language_library_path()
    if not lib:
        return {}

    langs = {}
    for lang_key in ("c", "cpp"):
        try:
            langs[lang_key] = Language(lib, lang_key)
        except Exception:
            continue
    return langs


LANGUAGES = _build_languages()


def extract_rule_id(message: str) -> str:
    match = re.search(r"R-\d+-\d+-\d+", message or "")
    if match:
        return match.group(0)
    return "R-1-1-UNKNOWN"


def get_code_snippet(node_or_span: Union[object, Tuple[int, int]], code: str, context_lines: int = 2) -> str:
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
    base = RULE_META[rule_id]
    message = base["message"]
    if message_suffix:
        message = f"{message} ({message_suffix})"

    violations.append(
        {
            "line": line,
            "code_snippet": code_snippet,
            "violation_type": "编码规范",
            "severity": base["severity"],
            "rule_id": rule_id,
            "message": message,
        }
    )


def _normalize_type(raw_type: str) -> str:
    t = re.sub(r"\s+", " ", raw_type.strip())
    t = t.replace("const ", "").replace("volatile ", "")
    t = t.replace("static ", "").replace("extern ", "")
    return t.strip()


def _find_function_ranges(code: str) -> List[Tuple[int, int]]:
    lines = code.split("\n")
    ranges = []
    brace = 0
    start = None
    pending_signature = None
    for i, line in enumerate(lines):
        if start is None:
            # 支持两种函数体起始：") {" 同行、")" 下一行再"{"。
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


def _line_in_ranges(line_no0: int, ranges: List[Tuple[int, int]]) -> bool:
    for s, e in ranges:
        if s <= line_no0 <= e:
            return True
    return False


def _sanitize_code_lines(code: str, strip_strings: bool = True) -> List[str]:
    """生成用于规则扫描的代码行：移除注释，按需移除字符串以降低误报。"""
    lines = code.split("\n")
    out = []
    in_block_comment = False

    for line in lines:
        i = 0
        n = len(line)
        buf = []
        while i < n:
            ch = line[i]
            nxt = line[i + 1] if i + 1 < n else ""

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

            if ch == "/" and nxt == "/":
                break

            if strip_strings and ch in ('"', "'"):
                quote = ch
                buf.append(" ")
                i += 1
                while i < n:
                    if line[i] == "\\":
                        i += 2
                        continue
                    if line[i] == quote:
                        i += 1
                        break
                    i += 1
                continue

            buf.append(ch)
            i += 1

        out.append("".join(buf))

    return out


def _detect_with_tree_sitter(code: str, language: str, violations: List[dict], seen: Set[Tuple[int, str]]):
    lang = LANGUAGES.get(language)
    if not lang or Parser is None:
        return

    parser = Parser()
    parser.set_language(lang)
    root = parser.parse(code.encode("utf8")).root_node

    # 优先使用语法树做基础抓取，再结合规则细化。
    ts_queries = {
        "macro_def": "(preproc_def name: (identifier) @macro_name value: (_)? @macro_value) @macro_def",
        "macro_func": "(preproc_function_def name: (identifier) @mname parameters: (preproc_params) @mparams) @mdef",
        "include": "(preproc_include path: (_) @inc) @inc_stmt",
        "type_def": "(type_definition declarator: (type_identifier) @tname) @tdef",
    }

    captures_map = {}
    for k, q in ts_queries.items():
        try:
            query = lang.query(q)
            captures_map[k] = query.captures(root)
        except Exception:
            captures_map[k] = []

    # R-1-1-1 / R-1-1-2 / R-1-1-5
    defined_macros = {}
    lines = code.split("\n")
    for node, tag in captures_map.get("macro_def", []):
        if tag != "macro_def":
            continue
        text = node.text.decode("utf8", errors="ignore")
        m = re.match(r"\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+(.+)$", text.strip())
        if not m:
            continue
        name, value = m.group(1), m.group(2).strip()
        line = node.start_point[0] + 1
        snippet = get_code_snippet(node, code)

        if name in C_CPP_KEYWORDS or name in BASIC_TYPES:
            _add_violation(violations, seen, line, "R-1-1-1", snippet, name)

        value_head = value.split()[0].strip("()")
        if value_head in C_CPP_KEYWORDS or value_head in BASIC_TYPES:
            _add_violation(violations, seen, line, "R-1-1-2", snippet, f"{name}->{value_head}")

        if name in defined_macros:
            _add_violation(violations, seen, line, "R-1-1-5", snippet, name)
        defined_macros[name] = line

    # R-1-1-7
    for node, tag in captures_map.get("macro_func", []):
        if tag != "mdef":
            continue
        text = node.text.decode("utf8", errors="ignore").strip()
        m = re.match(r"#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(.+)$", text)
        if not m:
            continue
        params = [x.strip() for x in m.group(2).split(",") if x.strip()]
        body = m.group(3).strip()
        line = node.start_point[0] + 1
        snippet = get_code_snippet(node, code)

        bad = False
        # 近似检测策略：函数式宏整体要求被括号包裹，且参数出现时建议被括号包裹。
        if not (body.startswith("(") and body.endswith(")")):
            bad = True
        for p in params:
            if re.search(rf"\b{re.escape(p)}\b", body) and not re.search(rf"\({re.escape(p)}\)", body):
                bad = True
                break
        if bad:
            _add_violation(violations, seen, line, "R-1-1-7", snippet, m.group(1))

    # R-1-1-3
    typedef_seen = {}
    typedef_pattern = re.compile(r"\btypedef\b[^{;]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*;")
    for i, line in enumerate(lines, 1):
        m = typedef_pattern.search(line)
        if not m:
            continue
        tname = m.group(1)
        if tname in typedef_seen:
            _add_violation(violations, seen, i, "R-1-1-3", get_code_snippet((i - 1, i - 1), code), tname)
        else:
            typedef_seen[tname] = i


def detect_c_cpp_gjb_5_1_violations(code: str, language: str = "cpp") -> List[dict]:
    """
    检测GJB 8114-2013中5.1（声明定义）条款的违规。

    Args:
        code: C/C++源码字符串
        language: 语言类型，支持"c"和"cpp"

    Returns:
        list[dict]: 违规列表
    """
    if language not in ("c", "cpp"):
        return []

    violations: List[dict] = []
    seen: Set[Tuple[int, str]] = set()
    lines = code.split("\n")
    scan_lines = _sanitize_code_lines(code, strip_strings=True)
    scan_lines_keep_strings = _sanitize_code_lines(code, strip_strings=False)

    # 先走tree-sitter路径；无法解析时再走纯正则。
    _detect_with_tree_sitter(code, language, violations, seen)

    func_ranges = _find_function_ranges("\n".join(scan_lines))

    macro_status = {}
    typedef_names = {}
    include_seen = {}
    extern_decls = {}
    var_defs = {}
    func_decls = {}

    # 预处理：逐行扫描收集关键信息。
    for i, line in enumerate(lines, 1):
        scan_line = scan_lines[i - 1]

        # R-1-1-1 / R-1-1-2 / R-1-1-5
        m_define = re.match(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+(.+))?$", scan_lines_keep_strings[i - 1])
        if m_define:
            name = m_define.group(1)
            value = (m_define.group(2) or "").strip()
            snippet = get_code_snippet((i - 1, i - 1), code)
            if name in C_CPP_KEYWORDS or name in BASIC_TYPES:
                _add_violation(violations, seen, i, "R-1-1-1", snippet, name)

            value_head = value.split()[0].strip("()") if value else ""
            if value_head in C_CPP_KEYWORDS or value_head in BASIC_TYPES:
                _add_violation(violations, seen, i, "R-1-1-2", snippet, f"{name}->{value_head}")

            if name in macro_status and macro_status[name] == "defined":
                _add_violation(violations, seen, i, "R-1-1-5", snippet, name)
            macro_status[name] = "defined"

        m_undef = re.match(r"^\s*#\s*undef\s+([A-Za-z_][A-Za-z0-9_]*)", scan_lines_keep_strings[i - 1])
        if m_undef:
            macro_status[m_undef.group(1)] = "undefined"

        # R-1-1-3
        m_typedef = re.search(r"\btypedef\b[^{;]*?\b([A-Za-z_][A-Za-z0-9_]*)\s*;", scan_line)
        if m_typedef:
            tname = m_typedef.group(1)
            if tname in typedef_names:
                _add_violation(violations, seen, i, "R-1-1-3", get_code_snippet((i - 1, i - 1), code), tname)
            else:
                typedef_names[tname] = i

        # R-1-1-4（近似检测策略）
        # 近似检测策略：在声明语句中检测关键字被当作标识符的情况。
        m_decl = re.match(
            r"^\s*(?:static\s+|extern\s+|const\s+|volatile\s+)*"
            r"(?:signed\s+|unsigned\s+)?(?:char|short|int|long|float|double|bool)\s+"
            r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:[=;,\[:])",
            scan_line,
        )
        if m_decl:
            ident = m_decl.group(1)
            if ident in C_CPP_KEYWORDS:
                _add_violation(violations, seen, i, "R-1-1-4", get_code_snippet((i - 1, i - 1), code), ident)

        # R-1-1-8
        if re.match(r"^\s*(struct|union|enum)\s*\{", scan_line):
            _add_violation(violations, seen, i, "R-1-1-8", get_code_snippet((i - 1, i - 1), code))

        # R-1-1-10 / R-1-1-11 / R-1-1-12
        m_bitfield = re.search(
            r"^\s*((?:signed|unsigned)?\s*(?:char|short|int|long(?:\s+long)?))\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(\d+)\s*;",
            scan_line,
        )
        if m_bitfield:
            raw_type = _normalize_type(m_bitfield.group(1))
            width = int(m_bitfield.group(3))
            snippet = get_code_snippet((i - 1, i - 1), code)

            if raw_type.startswith("signed") and width <= 1:
                _add_violation(violations, seen, i, "R-1-1-10", snippet, f"{raw_type}:{width}")

            if not (raw_type.startswith("signed") or raw_type.startswith("unsigned")):
                _add_violation(violations, seen, i, "R-1-1-11", snippet, raw_type)

            # 近似检测策略：按基础类型位宽判断位域是否越界。
            bit_max = TYPE_BIT_WIDTH.get(raw_type)
            if bit_max is None:
                # 兼容诸如"int"、"long"等未显式signed/unsigned的情况。
                bit_max = TYPE_BIT_WIDTH.get(_normalize_type(raw_type.replace("signed ", "").replace("unsigned ", "")), 32)
            if width > bit_max:
                _add_violation(violations, seen, i, "R-1-1-12", snippet, f"{raw_type}:{width}>{bit_max}")

        # R-1-1-13 / R-1-1-14 / R-1-1-15 / R-1-1-23
        m_func_sig = re.match(
            r"^\s*([A-Za-z_][\w\s\*:&<>]*)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(;|\{)?\s*$",
            scan_line,
        )
        if m_func_sig and not re.match(r"^\s*(if|for|while|switch)\b", scan_line):
            ret_type = _normalize_type(m_func_sig.group(1))
            fname = m_func_sig.group(2)
            params = m_func_sig.group(3).strip()
            tail = m_func_sig.group(4) or ""
            snippet = get_code_snippet((i - 1, i - 1), code)

            if params == "":
                _add_violation(violations, seen, i, "R-1-1-23", snippet, fname)

            if params and params != "void":
                for p in [x.strip() for x in params.split(",") if x.strip()]:
                    # 近似检测策略：参数至少应有“类型 + 名称”两个token。
                    # 同时支持指针/引用形式。
                    p_clean = p.replace("*", " * ").replace("&", " & ")
                    tokens = [t for t in p_clean.split() if t]
                    if len(tokens) < 2:
                        _add_violation(violations, seen, i, "R-1-1-13", snippet, f"{fname}({p})")
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", p):
                        _add_violation(violations, seen, i, "R-1-1-15", snippet, f"{fname}({p})")

            sig_key = fname
            sig_norm = (ret_type, " ".join(params.split()))
            if tail == ";":
                func_decls.setdefault(sig_key, []).append((i, sig_norm))
            elif tail == "{":
                prior = func_decls.get(sig_key, [])
                for decl_line, decl_sig in prior:
                    if decl_sig != sig_norm:
                        _add_violation(
                            violations,
                            seen,
                            i,
                            "R-1-1-14",
                            snippet,
                            f"{fname} 声明行{decl_line}",
                        )

        # R-1-1-16 / R-1-1-19
        m_extern = re.match(
            r"^\s*extern\s+([A-Za-z_][\w\s\*]+?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(=\s*[^;]+)?\s*;\s*$",
            scan_line,
        )
        if m_extern:
            etype = _normalize_type(m_extern.group(1))
            ename = m_extern.group(2)
            init_part = m_extern.group(3)
            extern_decls[ename] = (etype, i)
            if init_part:
                _add_violation(violations, seen, i, "R-1-1-19", get_code_snippet((i - 1, i - 1), code), ename)

        m_def = re.match(
            r"^\s*(?:static\s+)?([A-Za-z_][\w\s\*]+?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*[^;]+)?\s*;\s*$",
            scan_line,
        )
        if m_def and "(" not in scan_line and not scan_line.strip().startswith("extern"):
            vtype = _normalize_type(m_def.group(1))
            vname = m_def.group(2)
            var_defs[vname] = (vtype, i)

        # R-1-1-17
        if re.match(r"^\s*extern\b", scan_line) and _line_in_ranges(i - 1, func_ranges):
            _add_violation(violations, seen, i, "R-1-1-17", get_code_snippet((i - 1, i - 1), code))

        # R-1-1-18（近似检测策略）
        # 近似检测策略：检测非函数形参场景下的空数组边界定义。
        if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\[\s*\]\s*(?:=|;)", scan_line) and "(" not in scan_line:
            _add_violation(violations, seen, i, "R-1-1-18", get_code_snippet((i - 1, i - 1), code))

        # R-1-1-20（近似检测策略）
        # 近似检测策略：plain char声明后参与+-*/%运算则判定为违规。
        m_plain_char = re.match(r"^\s*char\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:=\s*[^;]+)?\s*;", scan_line)
        if m_plain_char:
            cname = m_plain_char.group(1)
            for j in range(i, min(i + 40, len(lines))):
                scan_next = scan_lines[j]
                if re.search(rf"\b{re.escape(cname)}\b\s*[\+\-\*/%]", scan_next) or re.search(
                    rf"[\+\-\*/%]\s*\b{re.escape(cname)}\b", scan_next
                ):
                    _add_violation(
                        violations,
                        seen,
                        i,
                        "R-1-1-20",
                        get_code_snippet((i - 1, i - 1), code),
                        cname,
                    )
                    break

        # R-1-1-21 / R-1-1-22
        m_include = re.match(r"^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]", scan_lines_keep_strings[i - 1])
        if m_include:
            inc = m_include.group(1)
            if re.match(r"^[A-Za-z]:[\\/]", inc) or inc.startswith("/"):
                _add_violation(violations, seen, i, "R-1-1-21", get_code_snippet((i - 1, i - 1), code), inc)

            if inc in include_seen:
                _add_violation(violations, seen, i, "R-1-1-22", get_code_snippet((i - 1, i - 1), code), inc)
            else:
                include_seen[inc] = i

    # R-1-1-16: extern类型一致性检查
    for name, (etype, eline) in extern_decls.items():
        if name in var_defs:
            vtype, _ = var_defs[name]
            if _normalize_type(etype) != _normalize_type(vtype):
                _add_violation(
                    violations,
                    seen,
                    eline,
                    "R-1-1-16",
                    get_code_snippet((eline - 1, eline - 1), code),
                    f"{name}: extern={etype}, def={vtype}",
                )

    # R-1-1-6: 函数内define/undef配对
    for s, e in func_ranges:
        local_status = {}
        for idx in range(s, e + 1):
            line = scan_lines[idx]
            md = re.match(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)", line)
            mu = re.match(r"^\s*#\s*undef\s+([A-Za-z_][A-Za-z0-9_]*)", line)
            if md:
                local_status[md.group(1)] = local_status.get(md.group(1), 0) + 1
            if mu:
                local_status[mu.group(1)] = local_status.get(mu.group(1), 0) - 1

        for mname, balance in local_status.items():
            if balance != 0:
                _add_violation(
                    violations,
                    seen,
                    s + 1,
                    "R-1-1-6",
                    get_code_snippet((s, min(e, s + 3)), code),
                    mname,
                )

    # R-1-1-9（近似检测策略）
    # 近似检测策略：检测结构体内部出现"struct X {...};"且无实例名。
    code_joined = "\n".join(lines)
    for m in re.finditer(r"struct\s+[A-Za-z_][A-Za-z0-9_]*\s*\{([\s\S]*?)\};", code_joined):
        body = m.group(1)
        # 近似检测策略：仅识别“内层struct定义后直接分号结束、无实例名”的写法。
        for inner in re.finditer(r"struct\s+[A-Za-z_][A-Za-z0-9_]*\s*\{[\s\S]*?\}\s*;", body):
            line = code_joined[: m.start(1) + inner.start()].count("\n") + 1
            _add_violation(violations, seen, line, "R-1-1-9", get_code_snippet((line - 1, line - 1), code))

    return sorted(violations, key=lambda x: (x["line"], x["rule_id"]))


def analyze_c_cpp_gjb_5_1(code_string: str, language: str = "cpp") -> List[dict]:
    return detect_c_cpp_gjb_5_1_violations(code_string, language)


if __name__ == "__main__":
    test_cases = [
        (
            "c_violation_macro_and_empty_param",
            "c",
            """
#define long 100
#define KW if
int fun();
int fun(){ return 0; }
""",
        ),
        (
            "c_violation_extern_and_array",
            "c",
            """
extern int g = 1;
extern float datax;
int datax = 3;
int arr[] = {1,2,3};
""",
        ),
        (
            "c_violation_bitfield",
            "c",
            """
struct S {
    signed int a:1;
    int b:3;
    unsigned int c:40;
};
""",
        ),
        (
            "cpp_violation_macro_func_and_include",
            "cpp",
            """
#include "C:/abs/path/a.h"
#include "C:/abs/path/a.h"
#define PABS(x) x >= 0 ? x : -x
int main(){ return 0; }
""",
        ),
        (
            "cpp_violation_extern_in_function",
            "cpp",
            """
int main(){
    extern int g_data;
    #define LOC 1
    return LOC;
}
""",
        ),
        (
            "cpp_compliant_basic",
            "cpp",
            """
#include "a.h"
typedef unsigned int UINT32;
int add(int x, int y);
int add(int x, int y){ return x + y; }
int no_arg(void){ return 0; }
""",
        ),
        (
            "cpp_comment_should_not_trigger",
            "cpp",
            """
// #include "C:/abs/path/should_not_detect.h"
/* #define int 100 */
int add(int x, int y){ return x + y; }
""",
        ),
        (
            "c_multiline_function_range",
            "c",
            """
int main(void)
{
    extern int gx;
    #define LOCAL_BLOCK 1
    return LOCAL_BLOCK;
}
""",
        ),
    ]

    for name, lang, src in test_cases:
        print("=" * 70)
        print(f"CASE: {name} ({lang})")
        results = analyze_c_cpp_gjb_5_1(src, lang)
        if not results:
            print("未检测到违规")
            continue
        print(f"检测到 {len(results)} 个违规")
        for item in results:
            print(
                f"line={item['line']} | rule_id={item['rule_id']} | "
                f"message={item['message']} | code_snippet={item['code_snippet'].replace(chr(10), ' ')}"
            )
