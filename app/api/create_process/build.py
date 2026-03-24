# build.py
from tree_sitter import Language, Parser

# 构建Tree-sitter语言库
Language.build_library(
    'build/languages.so',
    [
        'vendor/tree-sitter-python',
        'vendor/tree-sitter-java',
        'vendor/tree-sitter-c',
        'vendor/tree-sitter-cpp',
        'vendor/tree-sitter-ruby',
        'vendor/tree-sitter-go',
        'vendor/tree-sitter-javascript',
    ]
)