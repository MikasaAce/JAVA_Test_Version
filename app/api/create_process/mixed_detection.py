import sys
import os
import re

from app.api.main_app.M_app import *
import xml.etree.ElementTree as ET
from app.api.ccn.processCCN import calculate_file_ccn

# 导入所有C++检测函数
from .cpp_module.cpp_mybatis import detect_mybatis_sql_injection as detect_cpp_mybatis_sql_injection
from .cpp_module.cpp_cmdin import detect_cpp_command_injection
from .cpp_module.cpp_dc_ujsd import detect_cpp_json_deserialization_vulnerabilities
from .cpp_module.cpp_dc_usd import detect_cpp_deserialization_vulnerabilities
from .cpp_module.cpp_dcci import detect_cpp_dynamic_code_injection
from .cpp_module.cpp_dos import detect_cpp_dos_vulnerabilities
from .cpp_module.cpp_hardpswd import detect_hardcoded_passwords as detect_cpp_hardcoded_passwords
from .cpp_module.cpp_hpp import detect_cpp_hpp_vulnerabilities
from .cpp_module.cpp_httponly import detect_cpp_cookie_httponly_vulnerability
from .cpp_module.cpp_httprespl import detect_cpp_http_response_splitting
from .cpp_module.cpp_jsonin import detect_cpp_json_injection
from .cpp_module.cpp_logforge import detect_cpp_log_forgery
from .cpp_module.cpp_nssl import detect_cpp_cookie_security
from .cpp_module.cpp_openrd import detect_cpp_open_redirection
from .cpp_module.cpp_pathtraverse import detect_cpp_path_traversal
from .cpp_module.cpp_resin import detect_cpp_resource_injection
from .cpp_module.cpp_settingm import detect_cpp_setting_manipulation
from .cpp_module.cpp_SMTP import detect_cpp_smtp_header_injection
from .cpp_module.cpp_spring import detect_cpp_spring_expression_injection
from .cpp_module.cpp_sqlin import detect_cpp_sql_injection
from .cpp_module.cpp_ssrf import detect_cpp_ssrf_vulnerabilities
from .cpp_module.cpp_ssti import detect_cpp_ssti_vulnerabilities
from .cpp_module.cpp_XMLEExpI import detect_cpp_xml_entity_expansion
from .cpp_module.cpp_XMLExtI import detect_cpp_xxe_vulnerabilities
from .cpp_module.cpp_xss_ref import detect_cpp_xss_reflected
from .cpp_module.cpp_XStream import detect_cpp_xstream_deserialization
from .cpp_module.cpp_dos_fs import detect_cpp_format_string_vulnerabilities

# 导入GJB 8114-2013检测函数
from .cpp_module.cpp_gjb_memory import detect_cpp_gjb_memory_violations
from .cpp_module.cpp_gjb_type import detect_cpp_gjb_type_violations
from .cpp_module.cpp_gjb_coding import detect_cpp_gjb_coding_violations
from .cpp_module.cpp_gjb_checker import detect_cpp_gjb_violations, generate_gjb_report

# 导入所有JavaScript检测函数
from .js_module.js_mybatis import detect_mybatis_sql_injection as detect_js_mybatis_sql_injection
from .js_module.js_cmdin import detect_js_command_injection
from .js_module.js_dc_ujsd import detect_js_json_deserialization_vulnerabilities
from .js_module.js_dc_usd import detect_js_deserialization_vulnerabilities
from .js_module.js_dcci import detect_js_dynamic_code_injection
from .js_module.js_dos import detect_js_dos_vulnerabilities
from .js_module.js_hardpswd import detect_hardcoded_passwords as detect_js_hardcoded_passwords
from .js_module.js_hpp import detect_js_hpp_vulnerabilities
from .js_module.js_httponly import detect_js_cookie_vulnerabilities
from .js_module.js_httprespl import detect_http_response_splitting
from .js_module.js_jsonin import detect_js_json_injection
from .js_module.js_logforge import detect_js_log_forgery_vulnerabilities
from .js_module.js_nssl import detect_js_cookie_ssl_vulnerabilities
from .js_module.js_openrd import detect_js_open_redirect_vulnerabilities
from .js_module.js_pathtraverse import detect_js_path_manipulation_vulnerabilities
from .js_module.js_resin import detect_js_resource_injection
from .js_module.js_settingm import detect_js_setting_vulnerabilities
from .js_module.js_SMTP import detect_smtp_header_vulnerabilities
from .js_module.js_spring import detect_expression_injection_vulnerabilities
from .js_module.js_sqlin import detect_js_sql_injection
from .js_module.js_ssrf import detect_js_ssrf_vulnerabilities
from .js_module.js_ssti import detect_js_ssti_vulnerabilities
from .js_module.js_XMLEExpI import detect_js_xxe_exp_vulnerabilities
from .js_module.js_XMLExtI import detect_js_xxe_ext_vulnerabilities
from .js_module.js_xss_ref import detect_reflected_xss_vulnerabilities
from .js_module.js_XStream import detect_xstream_deserialization_vulnerabilities

# 导入所有C语言检测函数
from .c_module.c_mybatis import detect_mybatis_sql_injection as detect_c_mybatis_sql_injection
from .c_module.c_cmdin import detect_command_injection_vulnerabilities
from .c_module.c_dc_ujsd import detect_c_json_deserialization_vulnerabilities
from .c_module.c_dc_usd import detect_c_deserialization_vulnerabilities
from .c_module.c_dcci import detect_c_dynamic_code_injection
from .c_module.c_dos import detect_c_dos_vulnerabilities
from .c_module.c_hardpswd import detect_hardcoded_passwords as detect_c_hardcoded_passwords
from .c_module.c_hpp import detect_c_hpp_vulnerabilities
from .c_module.c_httponly import detect_c_cookie_httponly_vulnerability
from .c_module.c_httprespl import detect_c_http_response_splitting
from .c_module.c_jsonin import detect_c_json_injection
from .c_module.c_logforge import detect_c_log_forgery
from .c_module.c_nssl import detect_c_cookie_security
from .c_module.c_openrd import detect_c_open_redirection
from .c_module.c_pathtraverse import detect_c_path_traversal
from .c_module.c_resin import detect_c_resource_injection
from .c_module.c_settingm import detect_c_setting_manipulation
from .c_module.c_SMTP import detect_c_smtp_header_injection
from .c_module.c_spring import detect_c_spring_expression_injection
from .c_module.c_sqlin import detect_c_sql_injection
from .c_module.c_ssrf import detect_c_ssrf_vulnerabilities
from .c_module.c_ssti import detect_c_ssti_vulnerabilities
from .c_module.c_XMLEExpI import detect_c_xml_entity_expansion
from .c_module.c_XMLExtI import detect_c_xxe_vulnerabilities
from .c_module.c_xss_ref import detect_c_xss_reflected
from .c_module.c_XStream import detect_c_xstream_deserialization
from .c_module.c_dos_fs import detect_c_format_string_vulnerabilities

# 导入所有Python检测函数
from .python_module.py_mybatis import analyze_python_mybatis_sql_injection
from .python_module.py_cmdin import detect_python_command_injection
from .python_module.py_dc_ujsd import analyze_python_deserialization
from .python_module.py_dc_usd import detect_unsafe_deserialization
from .python_module.py_dcci import detect_code_injection as detect_python_code_injection
from .python_module.py_dos import detect_denial_of_service as detect_python_denial_of_service
from .python_module.py_hardpswd import detect_hardcoded_passwords as detect_python_hardcoded_passwords
from .python_module.py_hpp import detect_http_parameter_pollution as detect_python_http_parameter_pollution
from .python_module.py_httponly import detect_cookie_security_issues as detect_python_cookie_security_issues
from .python_module.py_httprespl import analyze_python_http_response_splitting
from .python_module.py_jsonin import analyze_python_json_injection
from .python_module.py_logforge import analyze_python_log_forgery
from .python_module.py_nssl import detect_cookie_security_issues as analyze_python_cookie_security_nssl
from .python_module.py_openrd import analyze_open_redirects as analyze_python_openrds
from .python_module.py_pathtraverse import analyze_path_traversal as analyze_python_pathtraverse
from .python_module.py_resin import analyze_resource_injection as analyze_python_resin
from .python_module.py_settingm import analyze_config_manipulation as analyze_python_settingm
from .python_module.py_SMTP import analyze_smtp_header_injection as analyze_python_SMTP_header_injection
from .python_module.py_sqlin import analyze_sql_injection as analyze_python_sql_injection
from .python_module.py_ssrf import analyze_ssrf as analyze_python_ssrf
from .python_module.py_ssti import analyze_ssti as analyze_python_ssti
from .python_module.py_xss_ref import analyze_reflected_xss as analyze_python_reflected_xss

# 导入所有PHP检测函数
from .php_module.php_dc_ujsd import detect_php_unserialize_vulnerability as detect_php_json_deserialization
from .php_module.php_dc_usd import detect_php_unserialize_vulnerability as detect_php_deserialization
from .php_module.php_dcci import detect_php_code_injection
from .php_module.php_dos import detect_php_dos_vulnerability
from .php_module.php_hardpswd import detect_hardcoded_passwords as detect_php_hardcoded_passwords
from .php_module.php_hpp import detect_http_parameter_pollution as detect_php_http_parameter_pollution
from .php_module.php_httponly import detect_cookie_httponly_vulnerability as detect_php_httponly_vulnerability
from .php_module.php_httprespl import detect_http_response_splitting as detect_php_http_response_splitting
from .php_module.php_jsonin import detect_json_injection as detect_php_json_injection
from .php_module.php_logforge import detect_log_forgery_vulnerability as detect_php_log_forgery
from .php_module.php_cmdin import detect_php_command_injection
from .php_module.php_mybatis import detect_mybatis_sql_injection as detect_php_mybatis_sql_injection
from .php_module.php_nssl import detect_cookie_ssl_vulnerability as detect_php_nssl_cookie_ssl_vulnerability
from .php_module.php_openrd import detect_open_redirect_vulnerability as detect_php_openrd_vulnerability
from .php_module.php_pathtraverse import detect_path_traversal as detect_php_pathtraverse_vulnerability
from .php_module.php_resin import detect_resource_injection as detect_php_res_injection
from .php_module.php_settingm import detect_configuration_manipulation as detect_php_settingm_manipulation
from .php_module.php_SMTP import detect_smtp_header_injection as detect_php_smtp_header_injection
from .php_module.php_spring import detect_spring_expression_injection as detect_php_spring_expression_injection
from .php_module.php_sqlin import detect_sql_injection as detect_php_sql_injection
from .php_module.php_ssrf import detect_ssrf_vulnerability as detect_php_ssrf_vulnerability
from .php_module.php_ssti import detect_ssti_vulnerability as detect_php_ssti_vulnerability
from .php_module.php_xss_ref import detect_reflected_xss_vulnerability as detect_php_php_xss_reflected_vulnerability


CPP_VULNERABILITY_DETECTORS = {
    'command_injection': {
        'name': '命令注入漏洞',
        'description': '检测命令执行相关的安全漏洞',
        'detector': detect_cpp_command_injection,
        'severity': '高危'
    },
    'general_sql_injection': {
        'name': '通用SQL注入',
        'description': '检测通用的SQL注入漏洞',
        'detector': detect_cpp_sql_injection,
        'severity': '高危'
    },
    'dos': {
        'name': '拒绝服务漏洞',
        'description': '检测可能导致拒绝服务的代码模式',
        'detector': detect_cpp_dos_vulnerabilities,
        'severity': '中危'
    },
    'hardcoded_passwords': {
        'name': '硬编码密码',
        'description': '检测代码中的硬编码密码',
        'detector': detect_cpp_hardcoded_passwords,
        'severity': '高危'
    },
    'log_forgery': {
        'name': '日志伪造',
        'description': '检测日志注入和伪造漏洞',
        'detector': detect_cpp_log_forgery,
        'severity': '低危'
    },
    'open_redirect': {
        'name': '开放重定向',
        'description': '检测不安全的URL重定向',
        'detector': detect_cpp_open_redirection,
        'severity': '中危'
    },
    'path_traversal': {
        'name': '路径遍历',
        'description': '检测目录遍历和路径操作漏洞',
        'detector': detect_cpp_path_traversal,
        'severity': '高危'
    },
    'ssrf': {
        'name': 'SSRF漏洞',
        'description': '检测服务器端请求伪造漏洞',
        'detector': detect_cpp_ssrf_vulnerabilities,
        'severity': '高危'
    },
    'xxe_expansion': {
        'name': 'XXE实体扩展',
        'description': '检测XML外部实体扩展漏洞',
        'detector': detect_cpp_xml_entity_expansion,
        'severity': '高危'
    },
    'xxe_external': {
        'name': 'XXE外部实体',
        'description': '检测XML外部实体引用漏洞',
        'detector': detect_cpp_xxe_vulnerabilities,
        'severity': '高危'
    },
    'reflected_xss': {
        'name': '反射型XSS',
        'description': '检测反射型跨站脚本漏洞',
        'detector': detect_cpp_xss_reflected,
        'severity': '高危'
    },
    'dos_format_string': {
        'name': '拒绝服务：格式字符串',
        'description': '检测拒绝服务：格式字符串漏洞',
        'detector': detect_cpp_format_string_vulnerabilities,
        'severity': '高危'
    },
    'gjb_memory_safety': {
        'name': 'GJB内存安全',
        'description': '检测GJB 8114-2013内存安全规则违规',
        'detector': detect_cpp_gjb_memory_violations,
        'severity': '中危'
    },
    'gjb_type_safety': {
        'name': 'GJB类型安全',
        'description': '检测GJB 8114-2013类型安全规则违规',
        'detector': detect_cpp_gjb_type_violations,
        'severity': '中危'
    },
    'gjb_coding_standard': {
        'name': 'GJB编码规范',
        'description': '检测GJB 8114-2013编码规范规则违规',
        'detector': detect_cpp_gjb_coding_violations,
        'severity': '低危'
    }
}

JS_VULNERABILITY_DETECTORS = {
    'command_injection': {
        'name': '命令注入漏洞',
        'description': '检测命令执行相关的安全漏洞',
        'detector': detect_js_command_injection,
        'severity': '高危'
    },
    'dynamic_code_injection': {
        'name': '动态代码注入',
        'description': '检测动态代码执行漏洞',
        'detector': detect_js_dynamic_code_injection,
        'severity': '高危'
    },
    'dos': {
        'name': '拒绝服务漏洞',
        'description': '检测可能导致拒绝服务的代码模式',
        'detector': detect_js_dos_vulnerabilities,
        'severity': '中危'
    },
    'hardcoded_passwords': {
        'name': '硬编码密码',
        'description': '检测代码中的硬编码密码',
        'detector': detect_js_hardcoded_passwords,
        'severity': '高危'
    },
    'hpp': {
        'name': 'HTTP参数污染',
        'description': '检测HTTP参数污染漏洞',
        'detector': detect_js_hpp_vulnerabilities,
        'severity': '中危'
    },
    'cookie_httponly': {
        'name': 'Cookie HttpOnly缺失',
        'description': '检测Cookie缺少HttpOnly属性',
        'detector': detect_js_cookie_vulnerabilities,
        'severity': '中危'
    },
    'http_response_splitting': {
        'name': 'HTTP响应拆分',
        'description': '检测HTTP响应头拆分漏洞',
        'detector': detect_http_response_splitting,
        'severity': '中危'
    },
    'log_forgery': {
        'name': '日志伪造',
        'description': '检测日志注入和伪造漏洞',
        'detector': detect_js_log_forgery_vulnerabilities,
        'severity': '低危'
    },
    'cookie_ssl': {
        'name': 'Cookie SSL缺失',
        'description': '检测Cookie缺少Secure属性',
        'detector': detect_js_cookie_ssl_vulnerabilities,
        'severity': '中危'
    },
    'open_redirect': {
        'name': '开放重定向',
        'description': '检测不安全的URL重定向',
        'detector': detect_js_open_redirect_vulnerabilities,
        'severity': '中危'
    },
    'path_traversal': {
        'name': '路径遍历',
        'description': '检测目录遍历和路径操作漏洞',
        'detector': detect_js_path_manipulation_vulnerabilities,
        'severity': '高危'
    },
    'general_sql_injection': {
        'name': '通用SQL注入',
        'description': '检测通用的SQL注入漏洞',
        'detector': detect_js_sql_injection,
        'severity': '高危'
    },
    'ssrf': {
        'name': 'SSRF漏洞',
        'description': '检测服务器端请求伪造漏洞',
        'detector': detect_js_ssrf_vulnerabilities,
        'severity': '高危'
    },
    'ssti': {
        'name': 'SSTI漏洞',
        'description': '检测服务器端模板注入漏洞',
        'detector': detect_js_ssti_vulnerabilities,
        'severity': '高危'
    },
    'reflected_xss': {
        'name': '反射型XSS',
        'description': '检测反射型跨站脚本漏洞',
        'detector': detect_reflected_xss_vulnerabilities,
        'severity': '高危'
    }
}


C_VULNERABILITY_DETECTORS = {
    'command_injection': {
        'name': '命令注入漏洞',
        'description': '检测命令执行相关的安全漏洞',
        'detector': detect_command_injection_vulnerabilities,
        'severity': '高危'
    },
    'general_sql_injection': {
        'name': '通用SQL注入',
        'description': '检测通用的SQL注入漏洞',
        'detector': detect_c_sql_injection,
        'severity': '高危'
    },
    'dos': {
        'name': '拒绝服务漏洞',
        'description': '检测可能导致拒绝服务的代码模式',
        'detector': detect_c_dos_vulnerabilities,
        'severity': '中危'
    },
    'hardcoded_passwords': {
        'name': '硬编码密码',
        'description': '检测代码中的硬编码密码',
        'detector': detect_c_hardcoded_passwords,
        'severity': '高危'
    },
    'log_forgery': {
        'name': '日志伪造',
        'description': '检测日志注入和伪造漏洞',
        'detector': detect_c_log_forgery,
        'severity': '低危'
    },
    'open_redirect': {
        'name': '开放重定向',
        'description': '检测不安全的URL重定向',
        'detector': detect_c_open_redirection,
        'severity': '中危'
    },
    'path_traversal': {
        'name': '路径遍历',
        'description': '检测目录遍历和路径操作漏洞',
        'detector': detect_c_path_traversal,
        'severity': '高危'
    },
    'ssrf': {
        'name': 'SSRF漏洞',
        'description': '检测服务器端请求伪造漏洞',
        'detector': detect_c_ssrf_vulnerabilities,
        'severity': '高危'
    },
    'xxe_expansion': {
        'name': 'XXE实体扩展',
        'description': '检测XML外部实体扩展漏洞',
        'detector': detect_c_xml_entity_expansion,
        'severity': '高危'
    },
    'xxe_external': {
        'name': 'XXE外部实体',
        'description': '检测XML外部实体引用漏洞',
        'detector': detect_c_xxe_vulnerabilities,
        'severity': '高危'
    },
    'dos_format_string': {
        'name': '拒绝服务：格式字符串',
        'description': '检测拒绝服务：格式字符串漏洞',
        'detector': detect_c_format_string_vulnerabilities,
        'severity': '高危'
    }
}


PYTHON_VULNERABILITY_DETECTORS = {
    'sql_injection': {
        'name': 'SQL注入漏洞',
        'description': '检测MyBatis风格的SQL注入漏洞',
        'detector': analyze_python_mybatis_sql_injection,
        'severity': '高危'
    },
    'command_injection': {
        'name': '命令注入漏洞',
        'description': '检测命令执行相关的安全漏洞',
        'detector': detect_python_command_injection,
        'severity': '高危'
    },
    'deserialization': {
        'name': '反序列化漏洞',
        'description': '检测不安全的反序列化操作',
        'detector': detect_unsafe_deserialization,
        'severity': '高危'
    },
    'dynamic_code_injection': {
        'name': '动态代码注入',
        'description': '检测动态代码执行漏洞',
        'detector': detect_python_code_injection,
        'severity': '高危'
    },
    'dos': {
        'name': '拒绝服务漏洞',
        'description': '检测可能导致拒绝服务的代码模式',
        'detector': detect_python_denial_of_service,
        'severity': '中危'
    },
    'hardcoded_passwords': {
        'name': '硬编码密码',
        'description': '检测代码中的硬编码密码',
        'detector': detect_python_hardcoded_passwords,
        'severity': '高危'
    },
    'log_forgery': {
        'name': '日志伪造',
        'description': '检测日志注入和伪造漏洞',
        'detector': analyze_python_log_forgery,
        'severity': '低危'
    },
    'open_redirect': {
        'name': '开放重定向',
        'description': '检测不安全的URL重定向',
        'detector': analyze_python_openrds,
        'severity': '中危'
    },
    'path_traversal': {
        'name': '路径遍历',
        'description': '检测目录遍历和路径操作漏洞',
        'detector': analyze_python_pathtraverse,
        'severity': '高危'
    },
    'smtp_header': {
        'name': 'SMTP头注入',
        'description': '检测SMTP邮件头注入漏洞',
        'detector': analyze_python_SMTP_header_injection,
        'severity': '中危'
    },
    'general_sql_injection': {
        'name': '通用SQL注入',
        'description': '检测通用的SQL注入漏洞',
        'detector': analyze_python_sql_injection,
        'severity': '高危'
    },
    'ssrf': {
        'name': 'SSRF漏洞',
        'description': '检测服务器端请求伪造漏洞',
        'detector': analyze_python_ssrf,
        'severity': '高危'
    },
    'ssti': {
        'name': 'SSTI漏洞',
        'description': '检测服务器端模板注入漏洞',
        'detector': analyze_python_ssti,
        'severity': '高危'
    }
}


PHP_VULNERABILITY_DETECTORS = {
    'deserialization': {
        'name': '反序列化漏洞',
        'description': '检测不安全的反序列化操作（unserialize）',
        'detector': detect_php_deserialization,
        'severity': '高危'
    },
    'dynamic_code_injection': {
        'name': '动态代码注入',
        'description': '检测动态代码执行漏洞（eval、create_function等）',
        'detector': detect_php_code_injection,
        'severity': '高危'
    },
    'dos': {
        'name': '拒绝服务漏洞',
        'description': '检测可能导致拒绝服务的代码模式（如正则回溯）',
        'detector': detect_php_dos_vulnerability,
        'severity': '中危'
    },
    'hardcoded_passwords': {
        'name': '硬编码密码',
        'description': '检测代码中的硬编码密码',
        'detector': detect_php_hardcoded_passwords,
        'severity': '高危'
    },
    'hpp': {
        'name': 'HTTP参数污染',
        'description': '检测HTTP参数污染漏洞（影响$_GET/$_POST解析）',
        'detector': detect_php_http_parameter_pollution,
        'severity': '中危'
    },
    'cookie_httponly': {
        'name': 'Cookie安全：HttpOnly未设置',
        'description': '检测Cookie缺少HttpOnly属性',
        'detector': detect_php_httponly_vulnerability,
        'severity': '中危'
    },
    'http_response_splitting': {
        'name': 'HTTP响应拆分',
        'description': '检测HTTP响应头拆分漏洞（header注入\\r\\n）',
        'detector': detect_php_http_response_splitting,
        'severity': '中危'
    },
    'log_forgery': {
        'name': '日志伪造',
        'description': '检测日志注入和伪造漏洞',
        'detector': detect_php_log_forgery,
        'severity': '低危'
    },
    'command_injection': {
        'name': '命令注入',
        'description': '检测命令执行相关的安全漏洞',
        'detector': detect_php_command_injection,
        'severity': '高危'
    },
    'cookie_ssl': {
        'name': 'Cookie SSL缺失',
        'description': '检测Cookie缺少Secure属性',
        'detector': detect_php_nssl_cookie_ssl_vulnerability,
        'severity': '中危'
    },
    'open_redirect': {
        'name': '开放重定向',
        'description': '检测不安全的URL重定向',
        'detector': detect_php_openrd_vulnerability,
        'severity': '中危'
    },
    'path_traversal': {
        'name': '路径遍历',
        'description': '检测目录遍历和路径操作漏洞',
        'detector': detect_php_pathtraverse_vulnerability,
        'severity': '高危'
    },
    'smtp_header': {
        'name': 'SMTP头注入',
        'description': '检测SMTP邮件头注入漏洞（mail函数注入\\n）',
        'detector': detect_php_smtp_header_injection,
        'severity': '中危'
    },
    'sql_injection': {
        'name': '通用SQL注入',
        'description': '检测通用的SQL注入漏洞',
        'detector': detect_php_sql_injection,
        'severity': '高危'
    },
    'ssrf': {
        'name': 'SSRF漏洞',
        'description': '检测服务器端请求伪造漏洞',
        'detector': detect_php_ssrf_vulnerability,
        'severity': '高危'
    },
    'ssti': {
        'name': 'SSTI漏洞',
        'description': '检测服务器端模板注入漏洞（如Twig、Smarty）',
        'detector': detect_php_ssti_vulnerability,
        'severity': '高危'
    },
    'reflected_xss': {
        'name': '反射型XSS',
        'description': '检测PHP反射型跨站脚本漏洞',
        'detector': detect_php_php_xss_reflected_vulnerability,
        'severity': '高危'
    }
}


def get_level_EN_CN(vul_name):
    # 根据cwe_id获取危险等级
    # 注：这里其实是根据英文名获取中文名，注释有误
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                if vul_name:
                    name_sql = """select name_CN from subVulList where name_EN = %s"""
                    cursor.execute(name_sql, (vul_name,))
                data = cursor.fetchall()
                if data:
                    return data[0][0]
                else:
                    # print("未能查询到中文名的漏洞类型",vul_name)
                    return "高危"
    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}{vul_name}")
    return "Error occurred while fetching vulnerability level"


def get_risk_level_EN(vul_name):
    # 根据英文名获取危险等级
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                if vul_name:
                    level_sql = """select level from subVulList where name_EN = %s"""
                    cursor.execute(level_sql, (vul_name,))
                data = cursor.fetchall()
                if data:
                    return data[0][0]
                else:
                    # print("未能查询到危险等级",vul_name)
                    return vul_name
    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}{vul_name}")
    return "Error occurred while fetching vulnerability level"


def get_risk_level_CN(vul_name):
    # 根据中文名获取危险等级
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                if vul_name:
                    level_sql = """select level from subVulList where name_CN = %s"""
                    cursor.execute(level_sql, (vul_name,))
                data = cursor.fetchall()
                if data:
                    return data[0][0]
                else:
                    # print("未能查询到危险等级",vul_name)
                    return "高危"
    except pymysql.MySQLError as e:
        print(f"MySQL Error: {e}{vul_name}")
    return "Error occurred while fetching vulnerability level"


def check_duplicate_vulnerability(task_id, file_path, filename, vulnerability_name, line_number):
    """
    检查数据库中是否已存在相同的漏洞记录

    Args:
        task_id: 任务ID
        file_path: 文件路径
        filename: 文件名
        vulnerability_name: 漏洞名称
        line_number: 行号

    Returns:
        bool: 如果存在重复记录返回True，否则返回False
    """
    try:
        with pymysql.connect(**config) as conn:
            with conn.cursor() as cursor:
                # 查询是否存在相同记录
                check_sql = """
                SELECT COUNT(*) FROM vulfile 
                WHERE taskId = %s 
                AND filepath = %s 
                AND filename = %s 
                AND vultype = %s 
                AND location = %s
                """
                cursor.execute(check_sql, (task_id, file_path, filename, vulnerability_name, line_number))
                count = cursor.fetchone()[0]

                return count > 0

    except pymysql.MySQLError as e:
        print(f"检查重复漏洞时数据库错误: {e}")
        # 如果检查失败，默认不插入，避免重复
        return True
    except Exception as e:
        print(f"检查重复漏洞时发生错误: {e}")
        return True


def get_code_context(code, line_number, context_lines=5):
    """
    获取指定行号的代码上下文

    Args:
        code: 完整的代码字符串
        line_number: 目标行号
        context_lines: 上下文的行数

    Returns:
        str: 包含上下文代码的字符串
    """
    try:
        lines = code.splitlines()
        start_line = max(0, line_number - 1 - context_lines)  # 转换为0-based索引
        end_line = min(len(lines), line_number + context_lines)

        context = []
        for i in range(start_line, end_line):
            prefix = ">>> " if i == line_number - 1 else "    "  # 标记当前行
            context.append(f"{prefix}Line {i + 1}: {lines[i]}")

        return "\n".join(context)
    except Exception as e:
        return f"获取代码上下文失败: {str(e)}"


def detect_vulnerabilities(code, detectors=None, language='cpp'):
    """
    统一漏洞检测函数

    Args:
        code: 源代码字符串
        detectors: 要使用的检测器列表，None表示使用所有检测器
        language: 语言类型 ('cpp', 'javascript', 'c', 'python', 'php')

    Returns:
        dict: 检测结果，按漏洞类型分类
    """
    # 根据语言选择对应的检测器集合
    if language == 'cpp':
        print(language)
        vulnerability_detectors = CPP_VULNERABILITY_DETECTORS
    elif language == 'javascript':
        print(language)
        vulnerability_detectors = JS_VULNERABILITY_DETECTORS
    elif language == 'c':
        print(language)
        vulnerability_detectors = C_VULNERABILITY_DETECTORS
    elif language == 'python':
        print(language)
        vulnerability_detectors = PYTHON_VULNERABILITY_DETECTORS
    elif language == 'php':
        print(language)
        vulnerability_detectors = PHP_VULNERABILITY_DETECTORS
    else:
        raise ValueError(f"Unsupported language: {language}")

    if detectors is None:
        detectors = vulnerability_detectors.keys()

    results = {}

    for detector_name in detectors:
        if detector_name not in vulnerability_detectors:
            continue

        detector_info = vulnerability_detectors[detector_name]
        detector_func = detector_info['detector']

        try:
            if language == 'php':
                vulnerabilities = detector_func(code)
            else:
                vulnerabilities = detector_func(code, language)

            results[detector_name] = {
                'vulnerabilities': vulnerabilities,
                'count': len(vulnerabilities),
                'info': detector_info
            }

        except Exception as e:
            results[detector_name] = {
                'vulnerabilities': [],
                'count': 0,
                'error': str(e),
                'info': detector_info
            }

    return results


def rule3_detection(arg, process_name, status, process_num):
    """通过统一漏洞检测规则进行检测"""
    file_path_list = arg['file_path']
    item_id = arg['item_id']
    task_name = arg['task_name']
    language = arg['language']
    task_id = arg['task_id']

    try:
        for path in file_path_list:
            print(path)
            # 根据文件后缀确定语言类型
            if path.endswith('.cpp'):
                file_language = 'cpp'
                print(file_language)
                vulnerability_detectors = CPP_VULNERABILITY_DETECTORS
            elif path.endswith('.js'):
                file_language = 'javascript'
                print(file_language)
                vulnerability_detectors = JS_VULNERABILITY_DETECTORS
            elif path.endswith('.c'):
                file_language = 'c'
                print(file_language)
                vulnerability_detectors = C_VULNERABILITY_DETECTORS
            elif path.endswith('.py'):
                file_language = 'python'
                print(file_language)
                vulnerability_detectors = PYTHON_VULNERABILITY_DETECTORS
            elif path.endswith('.php'):
                file_language = 'php'
                print(file_language)
                vulnerability_detectors = PHP_VULNERABILITY_DETECTORS
            else:
                # 跳过不支持的文件类型
                continue

            file_detectors = vulnerability_detectors.keys()
            print(file_detectors)

            try:
                # 读取文件内容
                code = read_file(path)
                path = code['path']
                data = code['data']
                code_lines = data.splitlines()
            except Exception:
                continue

            # 执行漏洞检测
            results = detect_vulnerabilities(data, file_detectors, file_language)
            print(results)

            # 提取漏洞信息并构建元组列表
            vulnerability_tuples = []
            seen_vulnerabilities = set()

            # 遍历results字典中的每个漏洞类型
            for vuln_type, vuln_data in results.items():
                # 获取该漏洞类型的漏洞列表
                vulnerabilities = vuln_data.get('vulnerabilities', [])
                # 遍历每个漏洞
                for vuln in vulnerabilities:
                    # 提取需要的字段，使用不同的键名尝试获取
                    line = vuln.get('line')
                    code_snippet = vuln.get('code_snippet')

                    # vulnerability_type可能有不同的键名
                    vulnerability_type = vuln.get('vulnerability_type') or vuln.get('vul_type')

                    # 只有当所有字段都存在时才添加到结果中
                    if line is not None and code_snippet is not None and vulnerability_type is not None:
                        # 创建元组作为唯一标识
                        vuln_tuple = (line, code_snippet, vulnerability_type)

                        # 检查是否已经存在
                        if vuln_tuple not in seen_vulnerabilities:
                            seen_vulnerabilities.add(vuln_tuple)
                            vulnerability_tuples.append(vuln_tuple)

            # 打印结果,处理检测到的漏洞
            for tup in vulnerability_tuples:
                print(tup)

            for vuln_info in vulnerability_tuples:
                line_number, code_snippet, vulnerability_name = vuln_info
                if line_number:
                    if vulnerability_name:
                        print(f"处理漏洞: {vulnerability_name}, 行号: {line_number}")

                        # 检查行号是否有效
                        if not (1 <= line_number <= len(code_lines)):
                            continue

                        # 获取当前行的内容
                        line_content = code_lines[line_number - 1].strip()

                        file_id = get_id('fileId', 'vulfile')
                        filename = os.path.basename(path)

                        # 获取代码上下文
                        code_context = get_code_context(data, line_number, 15)
                        print(code_context)

                        # 在插入前检查是否已存在相同记录
                        if not check_duplicate_vulnerability(task_id, path, filename, vulnerability_name, line_number):
                            # 准备漏洞数据
                            test_result_dtl = [{
                                'filename': filename,
                                'file_path': path,
                                'cwe_id': '',
                                'vul_name': vulnerability_name,
                                'code': code_context,
                                'line_number': line_number,
                                'src_line_number': line_number,
                                'func_line_number': line_number,
                                'risk_level': get_risk_level_CN(vulnerability_name),
                                'repair_code': '',
                                'new_line_number': '',
                                'repair_status': '未修复',
                                'is_question': '是问题',
                                'model': '',
                                'Sink': line_content,
                                'Enclosing_Method': '',
                                'Source': '',
                                'src_filename': filename
                            }]

                            print(test_result_dtl)
                            # 插入数据库
                            vulfile_insert(task_id, file_id, test_result_dtl)
                        else:
                            print(f"重复漏洞记录已跳过: {filename} - {vulnerability_name} - 行{line_number}")

        return JsonResponse({"msg": "统一规则扫描成功", "code": "200"})

    except Exception as e:
        return JsonResponse({"msg": "统一规则扫描失败", "code": "500", "error": str(e)})