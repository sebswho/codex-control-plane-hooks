"""UserPromptSubmit core behavior and its shared policy dependencies."""

from __future__ import annotations

import hashlib
import importlib
import json
import ntpath
import os
import re
import shlex
import shutil
import stat
import subprocess
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

policy_store = importlib.import_module("control_plane.policy")

state_store = importlib.import_module("control_plane.state")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_SECRET_PATTERNS = (
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("bearer_token", re.compile(r"(?i)\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|token|secret|password|client[_-]?secret|access[_-]?key)"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+=:-]{16,}"
        ),
    ),
    ("github_token", re.compile(r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
)

_SENSITIVE_EXTERNAL_VERB_RE = re.compile(r"外发|披露|上传|发送|共享|external|upload|share|send", re.IGNORECASE)

_SENSITIVE_NEGATION_RE = re.compile(
    r"(?:不要|别|禁止|不许|不得|不允许|拒绝)|"
    r"\b(?:do\s+not|don['’]t|never|can(?:not|\s+not)|can['’]t|"
    r"(?:will|must|should|shall)\s+not|won['’]t)\b",
    re.IGNORECASE,
)

_TERM_NEGATION_SUFFIX_RE = re.compile(
    r"(?ix)(?:"
    r"(?:but\s+)?not|except(?:\s+for)?|excluding|exclude|without|"
    r"do\s+not\s+(?:include|send)|不要|不包括|不含|排除|除外"
    r")\s*[,，:]?\s*$"
)

_TERM_NEGATION_POSTFIX_RE = re.compile(
    r"(?ix)^[ \t]*[,，:]?[ \t]*(?:"
    r"(?:is[ \t]+)?not[ \t]+(?:included|authorized|allowed|sent|shared|uploaded|disclosed)|"
    r"(?:is[ \t]+)?excluded|"
    r"(?:(?:must|should|will|shall)[ \t]+not(?:[ \t]+be)?|won['’]t(?:[ \t]+be)?)[ \t]+"
    r"(?:included|sent|shared|uploaded|disclosed)|"
    r"(?:can[ \t]*not|can['’]t)(?:[ \t]+be)?[ \t]+"
    r"(?:included|sent|shared|uploaded|disclosed)|"
    r"不包括|不包含|不含|排除|除外|不发送|不得发送|不上传|不得上传|不披露|不得披露|"
    r"不会上传|不会披露"
    r")(?=$|[\s,，;；:.])"
)

_SENSITIVE_EXPLICIT_AUTH_RE = re.compile(
    r"本轮明确授权|这次明确授权|现在明确授权|本轮明确允许|这次明确允许|I\s+explicitly\s+authorize",
    re.IGNORECASE,
)

_EXTERNAL_TARGET_PATTERNS = (
    ("google_drive", re.compile(r"(?i)google[ _-]*drive|mcp__google_drive")),
    ("gmail", re.compile(r"(?i)gmail|mcp__gmail")),
    ("notion", re.compile(r"(?i)notion|mcp__notion")),
    ("slack", re.compile(r"(?i)slack|mcp__slack")),
    ("teams", re.compile(r"(?i)(?:microsoft[ _-]*)?teams|mcp__teams")),
    ("sharepoint", re.compile(r"(?i)sharepoint|mcp__sharepoint")),
    ("box", re.compile(r"(?i)(?:^|[^a-z])box(?:[^a-z]|$)|mcp__box")),
    ("github", re.compile(r"(?i)github|mcp__github|\bgh\b")),
    ("browser", re.compile(r"(?i)browser|chrome|computer[ _-]*use")),
    ("web", re.compile(r"(?i)(?:^|[^a-z])web(?:[^a-z]|$)|https?://")),
)

_PROMPT_EXTERNAL_TARGET_PATTERNS = (
    (
        "google_drive",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_./-])google[ _-]*drive"
            r"(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"
        ),
    ),
    (
        "gmail",
        re.compile(r"(?i)(?<![A-Za-z0-9_./-])gmail(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"),
    ),
    (
        "notion",
        re.compile(r"(?i)(?<![A-Za-z0-9_./-])notion(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"),
    ),
    (
        "slack",
        re.compile(r"(?i)(?<![A-Za-z0-9_./-])slack(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"),
    ),
    (
        "teams",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_./-])(?:microsoft[ _-]*)?teams"
            r"(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"
        ),
    ),
    (
        "sharepoint",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_./-])sharepoint"
            r"(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"
        ),
    ),
    (
        "box",
        re.compile(r"(?i)(?<![A-Za-z0-9_./-])box(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"),
    ),
    (
        "github",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_./-])(?:github|gh)"
            r"(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"
        ),
    ),
    (
        "browser",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_./-])"
            r"(?:browser|chrome|computer[ _-]*use)"
            r"(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])"
        ),
    ),
    (
        "web",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_./-])web(?![A-Za-z0-9_/-]|\.[A-Za-z0-9_])|https?://"
        ),
    ),
)

_MCP_TARGET_CANDIDATE_RE = re.compile(r"(?i)mcp__\S+")

_MCP_TARGET_TOKEN_RE = re.compile(r"(?i)^mcp__[A-Za-z0-9_]+(?:__[A-Za-z0-9_]+)?$")

_MCP_TARGET_TRAILING_PUNCTUATION = ".,!?;:，。！？；：`'\")]})）】」』》〉〕］｝"

_PROMPT_TARGET_TERMINAL_PUNCTUATION = ".,!?;:，。！？；：`'\")]})）】」』》〉〕］｝"

_TRUSTED_MCP_SERVER_TARGETS = {
    "box": "box",
    "browser": "browser",
    "chrome": "browser",
    "computer_use": "browser",
    "github": "github",
    "gmail": "gmail",
    "google_drive": "google_drive",
    "microsoft_teams": "teams",
    "notion": "notion",
    "sharepoint": "sharepoint",
    "slack": "slack",
    "teams": "teams",
    "web": "web",
}

_TRUSTED_MCP_MULTIPLEXER_TARGET_PREFIXES = {
    "codex_apps": (
        ("box_", "box"),
        ("browser_", "browser"),
        ("chrome_", "browser"),
        ("computer_use_", "browser"),
        ("github_", "github"),
        ("gmail_", "gmail"),
        ("google_drive_", "google_drive"),
        ("notion_", "notion"),
        ("sharepoint_", "sharepoint"),
        ("slack_", "slack"),
        ("teams_", "teams"),
        ("web_", "web"),
    )
}

_AUTH_NEGATED_RE = re.compile(
    r"(?i)(不|未|没有|拒绝|禁止).{0,4}(?:明确授权|授权|确认执行|批准执行|执行|同意执行|允许)"
    r"|(?:不要|别).{0,4}执行|\b(?:do\s+not|don't|never)\b.{0,24}\b(?:go\s+ahead|proceed|authorize|execute|run)\b"
    r"|\bnot\s+(?:authorized|approved)\b|\bwithout\s+(?:authorization|approval)\b"
)

_AUTHORIZATION_REVOCATION_RE = re.compile(
    r"(?is)(?:但|但是|不过|\bbut\b|\bhowever\b).{0,32}"
    r"(?:不要|别|禁止|不许|不得|do\s+not|don't|never).{0,32}"
    r"(?:执行|运行|上述|前述|该命令|这些命令|execute|run|proceed)"
)

_DANGEROUS_APPROVAL_RE = re.compile(
    r"(?ix)^\s*(?:"
    r"(?:(?:本轮|这次|现在)\s*)?(?:并\s*)?(?:明确\s*)?"
    r"(?:批准(?:你)?(?:执行)?|同意(?:你)?(?:执行)?|确认(?:你)?(?:执行)?|授权(?:你)?(?:执行)?|"
    r"允许(?:你)?(?:执行)?|现在执行|直接执行)"
    r"|I\s+explicitly\s+authorize(?:\s+execution\s+of)?"
    r")"
)

_LOCAL_GIT_APPROVAL_RE = re.compile(
    r"(?ix)^\s*(?:"
    r"(?:我\s*)?(?:(?:本轮|这次|现在)\s*)?(?:明确\s*)?(?:批准|同意|确认|授权|允许)"
    r"|I\s+explicitly\s+authorize(?:\s+execution\s+of)?"
    r")"
)

_SCOPED_GIT_OPERATIONS = frozenset({"init", "add", "commit", "push"})

_SCOPED_TRANSACTION_OPERATIONS = _SCOPED_GIT_OPERATIONS | {"repo_create"}

_GIT_OPERATION_LIST_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_./-])git(?:\.exe)?\s+"
    r"(?P<operations>(?:init|add|commit|push)(?![A-Za-z0-9_.-])"
    r"(?:\s*(?:/|,|，|、|\+|和|及|与|and(?:\s+then)?|then)\s*"
    r"(?:git(?:\.exe)?\s+)?(?:init|add|commit|push)(?![A-Za-z0-9_.-]))*)"
)

_CHINESE_GIT_OPERATION_LIST_RE = re.compile(
    r"(?i)(?:^|(?:执行|运行|进行|批准|授权|允许|同意|确认|随后|然后|以及|同时|并)\s*)"
    r"(?:git\s*)?"
    r"(?P<operations>(?:初始化|暂存|提交|推送)"
    r"(?:\s*(?:/|,|，|、|\+|和|及|与)\s*(?:初始化|暂存|提交|推送))*)"
    r"(?=$|\s|[。；])"
)

_CHINESE_GIT_OPERATION_MAP = {
    "初始化": "init",
    "暂存": "add",
    "提交": "commit",
    "推送": "push",
}

_NEGATED_GIT_OPERATION_RE = re.compile(
    r"(?i)(?:不要|别|禁止|不许|不得|无需|不用|do\s+not|don't|never).{0,24}?"
    r"(?P<operation>init|add|commit|push|初始化|暂存|提交|推送|创建(?:仓库|repo(?:sitory)?)?)"
)

_PENDING_COMMAND_REFERENCE_RE = re.compile(r"上述|上面|刚才|前述|该命令|这个命令|previous\s+command", re.IGNORECASE)

_AUTHORIZED_TRANSACTION_CONTINUATION_RE = re.compile(
    r"(?is)(?:继续(?:执行|完成)?|随后(?:继续)?(?:执行|完成)?|接着(?:执行|完成)?).{0,160}"
    r"(?:上一条|上次|前述|原(?:发布)?|previous).{0,80}"
    r"(?:已授权|授权|approved|authorized).{0,80}(?:(?:git(?:hub)?|发布)\s*)?事务"
    r"|(?:上一条|上次|前述|原(?:发布)?|previous).{0,80}"
    r"(?:已授权|授权|approved|authorized).{0,80}(?:(?:git(?:hub)?|发布)\s*)?事务.{0,160}"
    r"(?:继续|完成|执行)"
)

_ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9_.-])(/[^\s，。；;`\"']+)")

_WINDOWS_ABSOLUTE_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])("
    r"\"(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+[\\/])[^\"\r\n]+\""
    r"|(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+[\\/])[^\s，。；;`\"']+)"
)

_QUOTED_ABSOLUTE_PATH_RE = re.compile(
    r"(?i)(?P<quote>[\"'`])(?P<path>"
    r"/[^\n\r]*?"
    r"|(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+[\\/])[^\n\r]*?"
    r")(?P=quote)"
)

_URI_SPAN_RE = re.compile(
    r"(?i)\b[A-Z][A-Z0-9+.-]*://[^\s，。；;`\"']+"
)

_CURRENT_REPO_RE = re.compile(r"当前(?:仓库|repo)|这个(?:仓库|repo)|current\s+(?:repository|repo)", re.IGNORECASE)

_GITHUB_OWNER_CONTEXT_RE = re.compile(
    r"(?i)(?:在|under)\s+(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,37}[A-Za-z0-9])?)\s*"
    r"(?:下|账户|账号|account|owner)"
)

_GITHUB_CREATE_COMMAND_RE = re.compile(
    r"(?i)\bgh(?:\.exe)?\s+repo\s+create\s+"
    r"(?P<target>[A-Za-z0-9][A-Za-z0-9.-]*/[A-Za-z0-9][A-Za-z0-9._-]*)"
)

_GITHUB_CREATE_INTENT_RE = re.compile(
    r"(?i)(?:创建|create).{0,240}(?:private\s+(?:repo|repository)|私有仓库)"
)

_GITHUB_REPO_NAME_RE = re.compile(r"(?i)\b[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+\b")

_CURRENT_EXPANSION_RE = re.compile(
    r"(?i)(?:开|开启|启动|使用|派|创建)\s*(?:到|共|最多)?\s*(?:[4-9]|[1-9]\d+)\s*个?\s*(?:子\s*)?agent"
)

_CURRENT_EXPANSION_AUTH_RE = re.compile(
    r"(?i)(?:(?:本轮|这次|现在).{0,16})?(?:明确)?(?:授权|允许).{0,48}"
    r"(?:高并发|超过\s*3|扩大.*agent|并发\s*(?:[4-9]|[1-9]\d+)\s*个?\s*(?:子\s*)?agent)"
)

_NESTED_AUTH_RE = re.compile(
    r"(?i)(?:(?:本轮|这次|现在).{0,16})?(?:明确)?(?:授权|允许).{0,80}"
    r"(?:二级\s*(?:嵌套|(?:子\s*)?agent)|nested|子\s*agent\s*(?:继续|再)\s*(?:开|创建))"
)

_EXPANSION_NEGATED_RE = re.compile(
    r"(?i)(?:不要|别|禁止|不许|无需|不用).{0,6}(?:开|开启|启动|使用|派|创建).{0,16}(?:子\s*)?agent"
)

_SHELL_CONTROL_RE = re.compile(r"[;&|<>]|\$\(|\x60")

_WINDOWS_ENV_EXPANSION_RE = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%|![A-Za-z_][A-Za-z0-9_]*!")

_WINDOWS_INLINE_GIT_GLOBAL_VALUE_RE = re.compile(
    r"(?i)(?<!\S)(?P<option>--(?:config-env|git-dir|work-tree|namespace|exec-path))="
    r"(?P<quote>['\"])(?P<value>[^'\"\r\n]*)(?P=quote)(?=\s|$)"
)

_AUTH_SEGMENT_SPLIT_RE = re.compile(r"[，。；！？、\n\r]+")

_AUTH_GIT_CONTINUATION_RE = re.compile(
    r"(?i)^\s*(?:(?:并(?:且)?|随后|然后|以及|同时|and(?:\s+then)?|then)\s*)?"
    r"(?!.*(?:文档|示例|日志|报告|说明|教程|文本|"
    r"(?<![A-Za-z0-9_-])(?:documentation|example|log|report)(?![A-Za-z0-9_-])))"
    r"(?:在\s+.{0,300}?\s*)?"
    r"(?:继续\s*)?(?:执行|完成|运行|创建|推送|初始化|暂存|提交|git\b|gh\b|push\b|create\b)"
)

_NEGATED_AUTH_COMMENT_RE = re.compile(
    r"(?i)^\s*#.*(?:不要|禁止|别|不许|不得|do\s+not|don't|never)"
)

_COMMAND_NEGATION_RE = re.compile(
    r"(?i)(?:不要|别|禁止|不许|不得|无需|不用|do\s+not|don't|never).{0,32}"
    r"(?:git|gh|rm|sudo|python3?|node|bash|sh|zsh)\b"
)

_PENDING_GIT_TTL_SECONDS = 600

_SCOPED_GIT_TRANSACTION_TTL_SECONDS = 30 * 60

_ASSIGNMENT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)

_SENSITIVE_ENV_NAMES = {
    "BASH_ENV",
    "ENV",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "LD_PRELOAD",
    "NODE_OPTIONS",
    "PATH",
    "PERL5OPT",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "RUBYOPT",
}

_READ_ONLY_COMMANDS = {
    "pwd",
    "ls",
    "cat",
    "grep",
    "nl",
    "wc",
    "head",
    "tail",
    "stat",
    "file",
    "du",
    "echo",
    "printf",
    "date",
    "which",
    "ps",
    "jq",
    "shasum",
    "cmp",
    "true",
    "false",
    "dir",
    "type",
    "where",
    "get-childitem",
    "get-content",
    "get-location",
    "get-process",
    "select-string",
}

_POWERSHELL_READ_ONLY_COMMANDS = {
    "get-childitem",
    "get-content",
    "get-location",
    "get-process",
    "select-string",
}

_POWERSHELL_SAFE_SWITCHES = {
    "mta",
    "nol",
    "nologo",
    "noni",
    "noninteractive",
    "nop",
    "noprofile",
    "noprofileloadtime",
    "sta",
}

_POWERSHELL_TERMINAL_SWITCHES = {"?", "h", "help", "v", "version"}

_POWERSHELL_VALUE_OPTIONS = {
    "if",
    "inp",
    "inputformat",
    "of",
    "o",
    "out",
    "outputformat",
    "w",
    "windowstyle",
}

_POWERSHELL_ENVIRONMENT_OPTIONS = {
    "config",
    "configurationfile",
    "configurationname",
    "settings",
    "settingsfile",
    "wd",
    "wo",
    "workingdirectory",
}

_READ_ONLY_GIT_SUBCOMMANDS = {
    "blame",
    "branch",
    "config",
    "diff",
    "grep",
    "log",
    "ls-files",
    "ls-tree",
    "remote",
    "rev-parse",
    "show",
    "status",
}

_READ_ONLY_GIT_CONFIG_SCOPES = {"--global", "--local", "--system", "--worktree"}

_READ_ONLY_GIT_CONFIG_QUERIES = {
    "--get",
    "--get-all",
    "--get-regexp",
    "--get-urlmatch",
    "--list",
    "-l",
}

_CONTROL_TOKENS = {";", "&&", "||", "|", "&"}

_SHELL_EVAL = {"ash", "bash", "dash", "fish", "ksh", "sh", "zsh"}

_PRIVILEGE_WRAPPERS = {"doas", "pkexec", "runuser", "su", "sudo"}

_INTERPRETER_EVAL_FLAGS = {
    "py": {"-c"},
    "python": {"-c"},
    "python3": {"-c"},
    "pythonw": {"-c"},
    "node": {"-e", "--eval", "-p", "--print"},
    "ruby": {"-e"},
    "perl": {"-e"},
    "osascript": {"-e"},
}

_GIT_GLOBAL_FLAGS = {
    "--bare",
    "--no-pager",
    "--paginate",
    "--no-replace-objects",
    "--literal-pathspecs",
    "--glob-pathspecs",
    "--noglob-pathspecs",
    "--icase-pathspecs",
}

_GIT_GLOBAL_VALUE_FLAGS = {
    "-C",
    "-c",
    "--config-env",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
}

_GIT_SCOPE_FLAGS = {"--git-dir", "--work-tree", "--namespace"}

_GIT_NETWORK_SUBCOMMANDS = {"push", "pull", "fetch", "clone"}

_EXACT_PUSH_BOOLEAN_OPTIONS = frozenset(
    "--atomic --dry-run --force --force-if-includes --force-with-lease --ipv4 "
    "--ipv6 --no-atomic --no-force-if-includes --no-progress --no-signed "
    "--no-thin --no-verify --porcelain --progress --quiet --set-upstream "
    "--signed --thin --verbose --verify".split()
)

_EXACT_PUSH_VALUE_OPTIONS = frozenset({"-o", "--push-option"})

_EXACT_PUSH_VALUE_PREFIXES = tuple(
    option + "=" for option in _EXACT_PUSH_VALUE_OPTIONS if option.startswith("--")
)

_EXACT_PUSH_OPTIONAL_VALUE_PREFIXES = (
    "--force-with-lease=",
    "--signed=",
)

_SCOPED_PUSH_OPTIONS = frozenset(
    {"-u", "--set-upstream", "--porcelain", "-q", "--quiet", "-v", "--verbose"}
)

_CONSTRAINED_CLONE_BOOLEAN_OPTIONS = frozenset(
    "--no-checkout --no-tags --progress --quiet --single-branch".split()
)

_CONSTRAINED_CLONE_SENSITIVE_COMPONENTS = frozenset(
    ".aws|.codex|.config|.git|.gnupg|.kube|.local|.ssh|$recycle.bin|program files|"
    "program files (x86)|programdata|system volume information|windows".split("|")
)

_CONSTRAINED_CLONE_POSIX_SYSTEM_ROOTS = tuple(
    "/Applications /Library /System /bin /cores /dev /etc /opt /private/etc "
    "/private/var/audit /private/var/backups /private/var/db /private/var/log "
    "/private/var/networkd /private/var/protected /private/var/root /private/var/run "
    "/private/var/vm /proc /sbin /usr".split()
)

_CONSTRAINED_CLONE_POSIX_BROAD_ROOTS = {"/", "/Users", "/private", "/private/var"}

_CONSTRAINED_CLONE_DESTINATION_META = frozenset("*?[]{}()!")

_PACKAGE_VALUE_OPTIONS = {
    "--prefix",
    "--workspace",
    "-w",
    "--cwd",
    "--dir",
    "--global-dir",
    "--registry",
    "--cache",
    "--userconfig",
}

_PACKAGE_INSTALL_SUBCOMMANDS = {"install", "add", "ci", "i", "update", "up", "link", "rebuild"}

_PACKAGE_RUNNER_SUBCOMMANDS = {"exec", "x", "dlx"}

_SYSTEM_PACKAGE_VALUE_OPTIONS = {"-c", "--config-file", "-o", "--option", "-t", "--target-release"}

_SYSTEM_PACKAGE_ACTIONS = {
    "apk": {"add", "del", "fix", "upgrade"},
    "apt": {"autoremove", "autopurge", "full-upgrade", "install", "purge", "remove", "update", "upgrade"},
    "apt-get": {
        "auto-remove",
        "autoremove",
        "autopurge",
        "dist-upgrade",
        "install",
        "purge",
        "remove",
        "update",
        "upgrade",
    },
    "aptitude": {"full-upgrade", "install", "purge", "remove", "update", "upgrade"},
    "brew": {"install", "reinstall", "uninstall", "update", "upgrade"},
    "dnf": {"install", "remove", "update", "upgrade"},
    "emerge": {"--sync"},
    "flatpak": {"install", "uninstall", "update"},
    "microdnf": {"install", "remove", "update", "upgrade"},
    "nala": {"fetch", "install", "remove", "update", "upgrade"},
    "nix": {"build", "develop", "profile", "run", "shell"},
    "nix-env": {"--install", "--upgrade", "-i", "-u"},
    "pacman": {"-S", "-R", "-U", "-Syu"},
    "snap": {"install", "refresh", "remove"},
    "yum": {"install", "remove", "update", "upgrade"},
    "zypper": {"install", "remove", "update"},
}

_COMMAND_EXECUTABLES = {
    "apk",
    "aria2c",
    "apt",
    "apt-get",
    "aptitude",
    "ash",
    "aws",
    "azcopy",
    "bash",
    "bitsadmin",
    "brew",
    "busybox",
    "bunx",
    "certutil",
    "chmod",
    "choco",
    "cmd",
    "curl",
    "dash",
    "del",
    "dnf",
    "doas",
    "emerge",
    "eval",
    "erase",
    "exec",
    "find",
    "fish",
    "flatpak",
    "ftp",
    "gcloud",
    "gh",
    "gsutil",
    "git",
    "icacls",
    "invoke-restmethod",
    "invoke-webrequest",
    "invoke-expression",
    "iex",
    "ksh",
    "lftp",
    "microdnf",
    "nala",
    "nc",
    "ncat",
    "netcat",
    "nix",
    "nix-env",
    "node",
    "npm",
    "npx",
    "osascript",
    "parallel",
    "pacman",
    "perl",
    "pip",
    "pip3",
    "pipx",
    "pnpm",
    "py",
    "python",
    "python3",
    "pythonw",
    "powershell",
    "pwsh",
    "pkexec",
    "rclone",
    "rg",
    "rm",
    "rd",
    "remove-item",
    "ri",
    "rmdir",
    "runas",
    "runuser",
    "ruby",
    "sh",
    "snap",
    "socat",
    "ssh",
    "su",
    "sudo",
    "scoop",
    "saps",
    "set-executionpolicy",
    "start-bitstransfer",
    "start-job",
    "start-process",
    "start",
    "timeout",
    "toybox",
    "uv",
    "uvx",
    "wget",
    "watch",
    "winget",
    "xargs",
    "yarn",
    "yum",
    "zsh",
    "zypper",
    "gtimeout",
}

_COMMAND_START_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_./-])((?:(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+[\\/]|/)"
    r"[A-Za-z0-9_.\\/ -]*[\\/])?(?:"
    + "|".join(sorted(re.escape(item) for item in _COMMAND_EXECUTABLES))
    + r")(?:\.exe|\.cmd|\.bat|\.com|\.ps1)?\b)"
)

_QUOTED_WINDOWS_EXECUTABLE_RE = re.compile(
    r"(?i)(?P<quote>[\"'])(?P<path>(?:[A-Z]:[\\/]|\\\\[^\\/\s]+[\\/][^\\/\s]+[\\/])"
    r"[^\"'\r\n]+\.(?:exe|cmd|bat|com|ps1))(?P=quote)"
)

def _finding(code: str, severity: str = "high") -> dict[str, str]:
    return {"severity": severity, "category": "dangerous_command", "code": code}

def _windows_segment_findings(
    executable: str, args: list[str], *, depth: int = 0
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    lowered = [token.casefold() for token in args]
    powershell_delete = executable in {"del", "erase", "rd", "remove-item", "ri", "rm", "rmdir"}
    recursive_parameter = any(token == "-r" or token.startswith("-rec") for token in lowered)
    cmd_recursive = executable in {"del", "erase", "rd", "rmdir"} and "/s" in lowered
    if (powershell_delete and recursive_parameter) or cmd_recursive:
        findings.append(_finding("windows_recursive_delete"))

    if executable in {"cmd", "iex", "invoke-expression"}:
        findings.append(_finding("dynamic_eval", "medium"))
    if executable in {"powershell", "pwsh"}:
        findings.extend(_powershell_launcher_findings(args, depth=depth))
    if executable == "." and args:
        findings.append(_finding("dynamic_eval", "medium"))
    if executable == "runas" or (
        executable in {"saps", "start", "start-process"}
        and _powershell_runas_requested(args)
    ):
        findings.append(_finding("privilege_escalation", "medium"))
    if executable == "set-executionpolicy":
        findings.append(_finding("profile_persistence", "medium"))
    if executable == "icacls":
        joined = " ".join(lowered)
        if "/grant" in lowered and "everyone" in joined and "/t" in lowered:
            findings.append(_finding("recursive_world_writable", "medium"))
    if executable in {"saps", "start", "start-job", "start-process"}:
        findings.append(_finding("background_process", "medium"))
    if executable in {"choco", "scoop", "winget"} and any(
        token in {"install", "remove", "uninstall", "update", "upgrade"} for token in lowered
    ):
        findings.append(_finding("package_install", "medium"))
    return findings

def _looks_like_windows_command(command: str) -> bool:
    return bool(
        os.name == "nt"
        or re.search(r"(?i)(?:\b[A-Z]:\\|\\\\[^\\\s]+\\|\.(?:exe|cmd|bat|com|ps1)\b)", command)
        or re.search(
            r"(?i)\b(?:powershell|pwsh|remove-item|start-process|invoke-expression|iex|"
            r"invoke-webrequest|invoke-restmethod)\b",
            command,
        )
    )

def _strip_token_quotes(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}:
        return token[1:-1]
    return token

def _executable_name(token: str) -> str:
    executable = ntpath.basename(_strip_token_quotes(token).replace("/", "\\")).casefold()
    for suffix in (".exe", ".cmd", ".bat", ".com", ".ps1"):
        if executable.endswith(suffix):
            executable = executable[: -len(suffix)]
            break
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", executable):
        return "python"
    if re.fullmatch(r"pythonw(?:\d+(?:\.\d+)*)?", executable):
        return "pythonw"
    if re.fullmatch(r"pip(?:\d+(?:\.\d+)*)?", executable):
        return "pip"
    return executable

def _trusted_executable_token(token: str, expected: str) -> bool:
    raw = _strip_token_quotes(token)
    if _executable_name(raw) != expected.casefold():
        return False
    resolved = shutil.which(raw) if not any(separator in raw for separator in ("/", "\\")) else (
        shutil.which(expected) or (shutil.which(f"{expected}.exe") if os.name == "nt" else None)
    )
    if not resolved:
        return False
    if any(separator in raw for separator in ("/", "\\")) and not os.path.isabs(raw):
        return False
    candidate = resolved if not any(separator in raw for separator in ("/", "\\")) else raw
    return bool(
        os.path.normcase(os.path.realpath(candidate))
        == os.path.normcase(os.path.realpath(resolved))
    )

def _is_literal_powershell_script_target(token: str) -> bool:
    target = _strip_token_quotes(token)
    if not target or any(char in target for char in "$`{};&|<>*?[]"):
        return False
    if target.startswith(("\\\\", "//")) or re.match(r"(?i)^[a-z][a-z0-9+.-]*://", target):
        return False
    return target.casefold().endswith(".ps1")

def _is_literal_powershell_call_target(token: str) -> bool:
    target = _strip_token_quotes(token)
    if not target or any(char in target for char in "$`{};&|<>"):
        return False
    if target.casefold().endswith(".ps1"):
        return _is_literal_powershell_script_target(target)
    if re.search(r"(?i)\.(?:cmd|bat)$", target):
        return False
    if re.search(r"(?i)\.(?:exe|com)$", target):
        return True
    return target.casefold() in _POWERSHELL_READ_ONLY_COMMANDS

def _powershell_option(token: str) -> tuple[str, str | None]:
    if len(token) < 2 or token[0] not in {"-", "/"}:
        return "", None
    option = token[1:]
    for separator in (":", "="):
        if separator in option:
            name, value = option.split(separator, 1)
            return name.casefold(), value
    return option.casefold(), None

def _powershell_runas_requested(args: list[str]) -> bool:
    for index, token in enumerate(args):
        name, inline_value = _powershell_option(token)
        if name not in {"v", "verb"}:
            continue
        value = inline_value if inline_value is not None else (
            args[index + 1] if index + 1 < len(args) else ""
        )
        if _strip_token_quotes(value).casefold() == "runas":
            return True
    return False

def _powershell_launcher_findings(args: list[str], *, depth: int) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    index = 0
    while index < len(args):
        name, inline_value = _powershell_option(args[index])
        encoded_option = (
            bool(name)
            and (
                "encodedcommand".startswith(name)
                or (len(name) >= 2 and "encodedarguments".startswith(name))
            )
        )
        if encoded_option:
            findings.append(_finding("dynamic_eval", "medium"))
            return findings
        if name == "ep" or (len(name) >= 2 and "executionpolicy".startswith(name)):
            value_index = index if inline_value is not None else index + 1
            value = inline_value if inline_value is not None else (
                args[value_index] if value_index < len(args) else ""
            )
            if not value:
                findings.append(_finding("dynamic_eval", "medium"))
                return findings
            findings.append(_finding("execution_environment_override", "medium"))
            index = value_index + 1
            continue
        if len(name) >= 3 and "noexit".startswith(name):
            findings.append(_finding("background_process", "medium"))
            return findings
        if name in {"c", "command"}:
            command_args = ([inline_value] if inline_value is not None else []) + args[index + 1 :]
            if not command_args or command_args[0] in {"", "-"} or depth >= 4:
                findings.append(_finding("dynamic_eval", "medium"))
            elif any(any(char in token for char in "(){}") for token in command_args):
                findings.append(_finding("dynamic_eval", "medium"))
            elif len(command_args) == 1:
                findings.extend(_structured_command_findings(command_args[0], depth=depth + 1))
            else:
                findings.extend(_segment_findings(command_args, depth=depth + 1))
            return findings
        if name in {"f", "file"}:
            file_args = ([inline_value] if inline_value is not None else []) + args[index + 1 :]
            if not file_args or not _is_literal_powershell_script_target(file_args[0]):
                findings.append(_finding("dynamic_eval", "medium"))
            return findings
        if not name and _is_literal_powershell_script_target(args[index]):
            return findings
        if name in _POWERSHELL_TERMINAL_SWITCHES:
            if inline_value is not None or index + 1 != len(args):
                code = (
                    "execution_environment_override"
                    if name in {"v", "version"}
                    else "dynamic_eval"
                )
                findings.append(_finding(code, "medium"))
            return findings
        if name in _POWERSHELL_SAFE_SWITCHES:
            if inline_value is not None:
                findings.append(_finding("dynamic_eval", "medium"))
                return findings
            index += 1
            continue
        if name in _POWERSHELL_ENVIRONMENT_OPTIONS or name == "custompipename":
            value_index = index if inline_value is not None else index + 1
            value = inline_value if inline_value is not None else (
                args[value_index] if value_index < len(args) else ""
            )
            if not value:
                findings.append(_finding("dynamic_eval", "medium"))
                return findings
            code = "background_process" if name == "custompipename" else "execution_environment_override"
            findings.append(_finding(code, "medium"))
            index = value_index + 1
            continue
        if name in _POWERSHELL_VALUE_OPTIONS:
            value_index = index if inline_value is not None else index + 1
            value = inline_value if inline_value is not None else (
                args[value_index] if value_index < len(args) else ""
            )
            if not value:
                findings.append(_finding("dynamic_eval", "medium"))
                return findings
            if name in {"w", "windowstyle"}:
                visible_styles = {"normal", "minimized", "maximized"}
                if _strip_token_quotes(value).casefold() not in visible_styles:
                    findings.append(_finding("background_process", "medium"))
            index = value_index + 1
            continue
        findings.append(_finding("dynamic_eval", "medium"))
        return findings
    findings.append(_finding("dynamic_eval", "medium"))
    return findings

def _shell_tokens(command: str) -> list[str]:
    try:
        windows_style = _looks_like_windows_command(command)
        token_source = (
            _WINDOWS_INLINE_GIT_GLOBAL_VALUE_RE.sub(
                lambda match: (
                    f"{match.group('quote')}{match.group('option')}="
                    f"{match.group('value')}{match.group('quote')}"
                ),
                command,
            )
            if windows_style
            else command
        )
        lexer = shlex.shlex(
            token_source, posix=not windows_style, punctuation_chars=";&|<>"
        )
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
        return [_strip_token_quotes(token) for token in tokens] if windows_style else tokens
    except ValueError:
        return []

def _has_shell_indirection(command: str) -> bool:
    windows_style = _looks_like_windows_command(command)
    if windows_style and _WINDOWS_ENV_EXPANSION_RE.search(command):
        if os.name == "nt":
            return True
        tokens = _shell_tokens(command)
        executable, _, wrappers = _unwrap_command(tokens)
        read_only_literal_context = not wrappers and (
            executable in _READ_ONLY_COMMANDS or executable in {"rg", "sed"}
        )
        if not read_only_literal_context:
            return True
    quote = ""
    escaped = False
    for index, char in enumerate(command):
        if escaped:
            escaped = False
            continue
        if char == "^" and windows_style and not quote:
            return True
        if char == "\\" and quote != "'" and not windows_style:
            escaped = True
            continue
        if quote == "'":
            if char == "'":
                quote = ""
            continue
        if char in {"'", '"'}:
            if not quote:
                quote = char
                continue
            if quote == char:
                quote = ""
                continue
        next_char = command[index + 1] if index + 1 < len(command) else ""
        if windows_style and not quote and char in "(){}":
            return True
        if char == "\x60" or (char == "<" and next_char in {"(", "<"}) or (
            char == ">" and next_char == "("
        ):
            return True
        if char == "$" and (next_char in {"(", "{"} or next_char.isalnum() or next_char in "_@*#?$!-"):
            return True
    return False

def _has_unquoted_shell_comment(command: str) -> bool:
    quote = ""
    escaped = False
    for index, char in enumerate(command):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'" and not _looks_like_windows_command(command):
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char == "#" and (index == 0 or command[index - 1].isspace()):
            return True
    return False

def _split_shell_commands(
    tokens: list[str], *, windows_style: bool = False
) -> tuple[list[list[str]], list[str]]:
    commands: list[list[str]] = []
    operators: list[str] = []
    current: list[str] = []
    for index, token in enumerate(tokens):
        if (
            token == "&"
            and not current
            and index + 1 < len(tokens)
            and _is_literal_powershell_call_target(tokens[index + 1])
            and (
                windows_style
                or _strip_token_quotes(tokens[index + 1]).casefold()
                in _POWERSHELL_READ_ONLY_COMMANDS
            )
        ):
            continue
        if token in _CONTROL_TOKENS:
            if current:
                commands.append(current)
                current = []
            operators.append(token)
        else:
            current.append(token)
    if current:
        commands.append(current)
    return commands, operators

def _skip_options(tokens: list[str], value_options: set[str]) -> list[str]:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return tokens[index + 1 :]
        if not token.startswith("-"):
            break
        index += 2 if token in value_options and index + 1 < len(tokens) else 1
    return tokens[index:]

def _unwrap_command(tokens: list[str]) -> tuple[str, list[str], set[str]]:
    remaining = list(tokens)
    wrappers: set[str] = set()
    while remaining:
        assignment = _ASSIGNMENT_RE.match(remaining[0])
        if assignment:
            wrappers.add("environment_assignment")
            name = assignment.group(1)
            if name in _SENSITIVE_ENV_NAMES or name.startswith(("DYLD_", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
                wrappers.add("sensitive_environment")
            remaining = remaining[1:]
            continue
        executable = _executable_name(remaining[0])
        if executable == "env":
            wrappers.add(executable)
            remaining = remaining[1:]
            while remaining:
                token = remaining[0]
                if token == "--":
                    remaining = remaining[1:]
                    break
                if token.startswith("--split-string=") or (token.startswith("-S") and token != "-S"):
                    wrappers.add("env_split")
                    remaining = remaining[1:]
                    continue
                if token in {"-S", "--split-string"}:
                    wrappers.add("env_split")
                    remaining = remaining[2:]
                    continue
                if token in {"-u", "--unset", "-C", "--chdir"}:
                    remaining = remaining[2:]
                    continue
                assignment = _ASSIGNMENT_RE.match(token)
                if assignment:
                    wrappers.add("environment_assignment")
                    name = assignment.group(1)
                    if name in _SENSITIVE_ENV_NAMES or name.startswith(
                        ("DYLD_", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
                    ):
                        wrappers.add("sensitive_environment")
                    remaining = remaining[1:]
                    continue
                if token.startswith("-"):
                    remaining = remaining[1:]
                    continue
                break
            continue
        if executable == "command":
            wrappers.add(executable)
            remaining = _skip_options(remaining[1:], set())
            continue
        if executable == "exec":
            wrappers.add(executable)
            remaining = _skip_options(remaining[1:], {"-a"})
            continue
        if executable == "sudo":
            wrappers.add(executable)
            remaining = _skip_options(remaining[1:], {"-u", "-g", "-h", "-p", "-C", "-T", "-R"})
            continue
        if executable == "doas":
            wrappers.add(executable)
            remaining = _skip_options(remaining[1:], {"-a", "-C", "-u"})
            continue
        if executable == "pkexec":
            wrappers.add(executable)
            remaining = _skip_options(remaining[1:], {"--user"})
            continue
        if executable == "runuser":
            wrappers.add(executable)
            remaining = _skip_options(
                remaining[1:],
                {"-u", "--user", "-g", "--group", "-G", "--supp-group", "-s", "--shell"},
            )
            continue
        if executable == "su":
            wrappers.add(executable)
            return "", [], wrappers
        if executable in {"time", "nice"}:
            wrappers.add(executable)
            remaining = _skip_options(remaining[1:], {"-n"})
            continue
        if executable in {"timeout", "gtimeout"}:
            wrappers.add(executable)
            inner = _skip_options(remaining[1:], {"-s", "--signal", "-k", "--kill-after"})
            remaining = inner[1:] if inner else []
            continue
        if executable in {"nohup", "setsid"}:
            wrappers.add(executable)
            remaining = _skip_options(remaining[1:], set())
            continue
        return executable, remaining[1:], wrappers
    return "", [], wrappers

def _git_command(args: list[str]) -> tuple[str, list[str], bool]:
    index = 0
    dynamic_config = False
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        if token in _GIT_GLOBAL_FLAGS:
            index += 1
            continue
        if token in _GIT_GLOBAL_VALUE_FLAGS:
            dynamic_config = dynamic_config or token in {"-c", "--config-env"}
            index += 2
            continue
        if any(
            token.startswith(prefix + "=")
            for prefix in _GIT_GLOBAL_VALUE_FLAGS
            if prefix.startswith("--")
        ):
            dynamic_config = dynamic_config or token.startswith("--config-env=")
            index += 1
            continue
        if token.startswith("-c") and token != "-C":
            dynamic_config = True
            index += 1
            continue
        if token.startswith("-"):
            return "", args[index:], True
        break
    if index >= len(args):
        return "", [], dynamic_config
    return args[index], args[index + 1 :], dynamic_config

def _git_is_read_only(subcommand: str, args: list[str], dynamic_config: bool) -> bool:
    if dynamic_config or subcommand not in _READ_ONLY_GIT_SUBCOMMANDS:
        return False
    if any(token in {"--ext-diff", "--textconv"} for token in args):
        return False
    if any(token == "--output" or token.startswith("--output=") for token in args):
        return False
    if subcommand == "branch":
        mutation_options = {
            "-d",
            "-D",
            "-m",
            "-M",
            "--delete",
            "--move",
            "--copy",
            "-c",
            "-C",
            "-u",
            "--set-upstream-to",
            "--unset-upstream",
            "--edit-description",
        }
        option_args = _before_option_terminator(args)
        if any(
            token.split("=", 1)[0] in mutation_options or _branch_short_options_mutate(token)
            for token in option_args
        ):
            return False
        positional = [token for token in args if not token.startswith("-")]
        return not positional or "--list" in args
    if subcommand == "config":
        config_args = list(args)
        while config_args and config_args[0] in _READ_ONLY_GIT_CONFIG_SCOPES:
            config_args.pop(0)
        if not config_args or config_args[0] not in _READ_ONLY_GIT_CONFIG_QUERIES:
            return False
        query, values = config_args[0], config_args[1:]
        if any(not value or value == "--" for value in values):
            return False
        if query in {"--list", "-l"}:
            return not values
        if query == "--get-urlmatch":
            return len(values) == 2
        return 1 <= len(values) <= 2
    if subcommand == "remote":
        action, remote_args = _git_remote_command(args)
        if not action:
            return True
        if action == "get-url":
            return True
        if action == "show":
            return _has_option_before_terminator(remote_args, {"-n", "--no-query"})
        return False
    return True

def _before_option_terminator(args: list[str]) -> list[str]:
    try:
        return args[: args.index("--")]
    except ValueError:
        return args

def _has_option_before_terminator(args: list[str], options: set[str]) -> bool:
    return any(token in options for token in _before_option_terminator(args))

def _branch_short_options_mutate(token: str) -> bool:
    if not token.startswith("-") or token.startswith("--"):
        return False
    return any(letter in "dDmMcCu" for letter in token[1:])

def _git_remote_command(args: list[str]) -> tuple[str, list[str]]:
    index = 0
    while index < len(args) and args[index] in {"-v", "--verbose"}:
        index += 1
    if index >= len(args):
        return "", []
    return args[index], args[index + 1 :]

def _git_uses_network(subcommand: str, args: list[str]) -> bool:
    if subcommand in _GIT_NETWORK_SUBCOMMANDS:
        return True
    if subcommand != "remote":
        return False
    action, remote_args = _git_remote_command(args)
    if action == "show":
        return not _has_option_before_terminator(remote_args, {"-n", "--no-query"})
    if action == "add":
        return _has_option_before_terminator(remote_args, {"-f", "--fetch"})
    if action == "set-head":
        return _has_option_before_terminator(remote_args, {"-a", "--auto"})
    return action in {"prune", "update"}

def _subcommand_after_options(args: list[str], value_options: set[str]) -> tuple[str, list[str]]:
    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            index += 1
            break
        if token in value_options:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        break
    if index >= len(args):
        return "", []
    return args[index], args[index + 1 :]

def _tokens_before_separator(args: list[str]) -> list[str]:
    try:
        return args[: args.index("--")]
    except ValueError:
        return args

def _has_short_flag(args: list[str], flag: str) -> bool:
    return any(token.startswith("-") and not token.startswith("--") and flag in token[1:] for token in args)

def _matches_eval_flag(token: str, flags: set[str]) -> bool:
    for flag in flags:
        if token == flag:
            return True
        if flag.startswith("--") and token.startswith(flag + "="):
            return True
        if flag.startswith("-") and not flag.startswith("--") and token.startswith(flag) and len(token) > len(flag):
            return True
    return False

def _is_shell_eval_flag(token: str) -> bool:
    return token.startswith("-") and not token.startswith("--") and "c" in token[1:]

def _segment_findings(tokens: list[str], depth: int = 0) -> list[dict[str, str]]:
    executable, args, wrappers = _unwrap_command(tokens)
    findings: list[dict[str, str]] = []
    if wrappers & _PRIVILEGE_WRAPPERS:
        findings.append(_finding("privilege_escalation", "medium"))
    if wrappers & {"nohup", "setsid"}:
        findings.append(_finding("background_process", "medium"))
    if "env_split" in wrappers:
        findings.append(_finding("shell_indirection", "medium"))
    if "sensitive_environment" in wrappers:
        findings.append(_finding("execution_environment_override", "medium"))
    if not executable:
        return findings
    findings.extend(_windows_segment_findings(executable, args, depth=depth))

    if executable == "rg" and any(token == "--pre" or token.startswith("--pre=") for token in args):
        findings.append(_finding("rg_preprocessor"))

    if executable == "rm":
        recursive = "--recursive" in args or _has_short_flag(args, "r") or _has_short_flag(args, "R")
        if recursive:
            findings.append(_finding("rm_recursive"))

    if executable == "git":
        subcommand, git_args, dynamic_config = _git_command(args)
        if dynamic_config:
            findings.append(_finding("git_dynamic_config", "medium"))
        if any(
            token in _GIT_SCOPE_FLAGS
            or any(token.startswith(prefix + "=") for prefix in _GIT_SCOPE_FLAGS)
            for token in args
        ):
            findings.append(_finding("git_scope_override", "medium"))
        if any(token == "--exec-path" or token.startswith("--exec-path=") for token in args):
            findings.append(_finding("git_external_helper", "medium"))
        if any(token in {"--ext-diff", "--textconv"} for token in git_args):
            findings.append(_finding("git_external_helper", "medium"))
        if not _git_is_read_only(subcommand, git_args, dynamic_config):
            findings.append(_finding("git_non_read_only", "medium"))
        if _git_uses_network(subcommand, git_args):
            findings.append(_finding("git_network", "medium"))
        if subcommand == "push":
            findings.append(_finding("git_push", "medium"))
            force = _has_short_flag(git_args, "f") or any(
                token == "--force" or token.startswith("--force-with-lease") for token in git_args
            )
            if force:
                findings.append(_finding("force_push"))
        if subcommand == "reset" and "--hard" in git_args:
            findings.append(_finding("git_reset_hard"))
        if subcommand == "clean":
            force = "--force" in git_args or _has_short_flag(git_args, "f")
            destructive = _has_short_flag(git_args, "d") or _has_short_flag(git_args, "x")
            if force and destructive:
                findings.append(_finding("git_clean_force"))

    if executable == "gh" and len(args) >= 2:
        if args[:2] == ["repo", "create"]:
            findings.append(_finding("github_network", "medium"))
            findings.append(_finding("github_repo_create", "medium"))
            if "--public" in args or "--internal" in args:
                findings.append(_finding("github_non_private_repo", "high"))
        elif args[:2] == ["repo", "clone"]:
            findings.append(_finding("github_network", "medium"))
            findings.append(_finding("git_non_read_only", "medium"))

    eval_flags = _INTERPRETER_EVAL_FLAGS.get(executable, set())
    if eval_flags and (
        not args
        or any(_matches_eval_flag(token, eval_flags) for token in args)
        or any(token in {"-", "/dev/stdin"} for token in args)
    ):
        findings.append(_finding("dynamic_eval", "medium"))
    if executable == "eval":
        findings.append(_finding("shell_indirection", "medium"))

    if executable in _SHELL_EVAL:
        if not args or any(token in {"-", "-s"} for token in args):
            findings.append(_finding("dynamic_eval", "medium"))
        for index, token in enumerate(args):
            if _is_shell_eval_flag(token):
                findings.append(_finding("dynamic_eval", "medium"))
                if depth == 0 and index + 1 < len(args):
                    findings.extend(_structured_command_findings(args[index + 1], depth=1))
                break

    if executable in {"npm", "pnpm", "yarn"}:
        package_command, _ = _subcommand_after_options(args, _PACKAGE_VALUE_OPTIONS)
        package_tokens = _tokens_before_separator(args)
        script_command = package_command in {"run", "run-script", "test", "start"}
        if not script_command and (
            package_command in _PACKAGE_INSTALL_SUBCOMMANDS
            or any(token in _PACKAGE_INSTALL_SUBCOMMANDS for token in package_tokens)
        ):
            findings.append(_finding("package_install", "medium"))
        if not script_command and (
            package_command in _PACKAGE_RUNNER_SUBCOMMANDS
            or any(token in _PACKAGE_RUNNER_SUBCOMMANDS for token in package_tokens)
        ):
            findings.append(_finding("package_runner", "medium"))
    if executable in {"pip", "pip3"}:
        package_command, _ = _subcommand_after_options(args, _PACKAGE_VALUE_OPTIONS)
        if package_command == "install" or "install" in _tokens_before_separator(args):
            findings.append(_finding("package_install", "medium"))
    if executable in {"npx", "bunx"}:
        findings.append(_finding("package_runner", "medium"))
    if executable == "pipx":
        if any(token in {"install", "run", "runpip"} for token in _tokens_before_separator(args)):
            findings.append(_finding("package_runner", "medium"))
    if executable in {"uv", "uvx"}:
        if executable == "uvx":
            findings.append(_finding("package_runner", "medium"))
        package_tokens = _tokens_before_separator(args)
        package_command, package_args = _subcommand_after_options(args, _PACKAGE_VALUE_OPTIONS)
        nested_command, _ = _subcommand_after_options(package_args, _PACKAGE_VALUE_OPTIONS)
        if (
            "install" in package_tokens
            and any(token in {"pip", "tool"} for token in package_tokens)
        ) or (package_command in {"pip", "tool"} and nested_command == "install"):
            findings.append(_finding("package_install", "medium"))
    if executable in _SYSTEM_PACKAGE_ACTIONS:
        actions = _SYSTEM_PACKAGE_ACTIONS[executable]
        package_tokens = _tokens_before_separator(args)
        package_command, _ = _subcommand_after_options(args, _SYSTEM_PACKAGE_VALUE_OPTIONS)
        pacman_mutation = executable == "pacman" and any(
            token in {"--remove", "--sync", "--upgrade"}
            or (
                token.startswith("-")
                and not token.startswith("--")
                and any(operation in token[1:] for operation in "SRU")
            )
            for token in package_tokens
        )
        apt_mutation = executable in {"apt", "apt-get", "aptitude"} and package_command.casefold() in actions
        other_mutation = executable not in {"apt", "apt-get", "aptitude"} and any(
            token in actions or token.casefold() in actions for token in package_tokens
        )
        if pacman_mutation or apt_mutation or other_mutation:
            findings.append(_finding("package_install", "medium"))

    if executable in {"py", "python", "python3", "pythonw"}:
        for index, token in enumerate(args[:-1]):
            if token != "-m" or args[index + 1].split(".", 1)[0] not in {"pip", "pip3"}:
                continue
            module_args = args[index + 2 :]
            package_command, _ = _subcommand_after_options(module_args, _PACKAGE_VALUE_OPTIONS)
            if package_command == "install" or "install" in _tokens_before_separator(module_args):
                findings.append(_finding("package_install", "medium"))
            break
        for index, token in enumerate(args[:-1]):
            if token == "-m" and args[index + 1] == "ensurepip":
                findings.append(_finding("package_install", "medium"))
                break

    if executable in {"xargs", "parallel", "watch"}:
        findings.append(_finding("indirect_execution", "medium"))
    if executable in {"busybox", "toybox"}:
        findings.append(_finding("indirect_execution", "medium"))
    if executable == "find" and any(token in {"-exec", "-execdir", "-delete"} for token in args):
        findings.append(_finding("indirect_execution", "medium"))

    if executable == "chmod" and "777" in args and ("-R" in args or "--recursive" in args):
        findings.append(_finding("recursive_world_writable", "medium"))

    for index, token in enumerate(tokens[:-1]):
        if token not in {">", ">>"}:
            continue
        target = tokens[index + 1]
        if target.startswith("/etc/") or target.endswith(("/.zshrc", "/.bashrc", "/.profile")):
            findings.append(_finding("profile_persistence", "medium"))

    return findings

def _structured_command_findings(command: str, depth: int = 0) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if _has_shell_indirection(command):
        findings.append(_finding("shell_indirection", "medium"))
    tokens = _shell_tokens(command)
    if not tokens:
        if command.strip():
            findings.append(_finding("command_parse_error"))
        return _dedupe_findings(findings)
    commands, operators = _split_shell_commands(
        tokens, windows_style=_looks_like_windows_command(command)
    )
    findings.extend(finding for segment in commands for finding in _segment_findings(segment, depth=depth))
    if "&" in operators:
        findings.append(_finding("background_process", "medium"))
    for index, operator in enumerate(operators):
        if operator != "|" or index + 1 >= len(commands):
            continue
        left, _, _ = _unwrap_command(commands[index])
        right, _, _ = _unwrap_command(commands[index + 1])
        if left in {"curl", "wget"} and right in _SHELL_EVAL | {"python", "python3"}:
            findings.append(_finding("curl_pipe_shell"))
    return _dedupe_findings(findings)

def _dedupe_findings(items: list[dict[str, str]]) -> list[dict[str, str]]:
    deduped: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in items:
        key = (item["severity"], item["category"], item["code"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped

def _fallback_scan_text(text: str) -> list[dict[str, str]]:
    return [
        {"severity": "high", "category": "secret", "code": code}
        for code, pattern in _SECRET_PATTERNS
        if pattern.search(text)
    ]

def _scan_text(text: str, *, source: str) -> list[dict[str, str]]:
    del source
    return _fallback_scan_text(text)

def _is_reparse_info(info: os.stat_result) -> bool:
    attributes = int(getattr(info, "st_file_attributes", 0))
    marker = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))
    return bool(marker and attributes & marker)

def _matches_policy_values(text: str, values: Sequence[str]) -> bool:
    return any(re.search(re.escape(value), text, re.IGNORECASE) for value in values)

def _session_id(event: dict[str, Any]) -> str:
    session_id = str(event.get("session_id") or "").strip()
    if not session_id:
        raise ValueError("session_id is required")
    return session_id

def _secret_found(findings: list[dict[str, str]]) -> bool:
    return any(item["category"] == "secret" for item in findings)

def _dangerous_codes(findings: list[dict[str, str]]) -> set[str]:
    return {
        item["code"]
        for item in findings
        if item["category"] == "dangerous_command"
        and SEVERITY_ORDER.get(item["severity"], 0) >= SEVERITY_ORDER["medium"]
    }

def _command_hash(command: str, cwd: str) -> str:
    if _has_unquoted_shell_comment(command):
        return ""
    tokens = _shell_tokens(command)
    if not tokens:
        return ""
    normalized_cwd = _normalized_cwd(cwd)
    executable, args, wrappers = _unwrap_command(tokens)
    canonical = normalized_cwd + "\0" + "\0".join(tokens)
    if executable == "git":
        scope, canonical_args = _git_scope_and_args(args, normalized_cwd)
        subcommand, git_args, dynamic_config = _git_command(canonical_args)
        if subcommand == "push":
            if wrappers or dynamic_config or not _trusted_executable_token(tokens[0], "git"):
                return ""
            push_remote = _exact_push_remote(git_args)
            if push_remote is None:
                return ""
            _, exact_git_args, _ = _git_command(args)
            global_arg_count = len(args) - len(exact_git_args) - 1
            if global_arg_count < 0:
                return ""
            exact_global_args = [
                _normalize_git_global_arg(token)
                for token in args[:global_arg_count]
            ]
            if any(
                token == "--exec-path" or token.startswith("--exec-path=")
                for token in exact_global_args
            ):
                return ""
            remote_identities = _git_remote_identities(
                normalized_cwd,
                push_remote,
                exact_global_args=exact_global_args,
            )
            if len(remote_identities) != 1:
                return ""
            canonical += "\0push-target\0" + remote_identities[0]
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()

def _normalized_cwd(cwd: str) -> str:
    resolved = os.path.realpath(os.path.abspath(os.path.expanduser(cwd or ".")))
    return os.path.normcase(resolved)

def _git_repo_root(cwd: str) -> str:
    normalized = Path(_normalized_cwd(cwd))
    start = normalized.parent if normalized.is_file() else normalized
    for candidate in (start, *start.parents):
        if (candidate / ".git").exists():
            return _normalized_cwd(str(candidate))
    return _normalized_cwd(str(start))

def _scope_identity(cwd: str, *, exact: bool = False) -> str:
    return _normalized_cwd(cwd) if exact else _git_repo_root(cwd)

def _scope_hash(cwd: str, *, exact: bool = False) -> str:
    identity = _scope_identity(cwd, exact=exact)
    return hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()

def _git_scope_and_args(args: list[str], cwd: str) -> tuple[str, list[str]]:
    scope = _normalized_cwd(cwd)
    canonical: list[str] = []
    index = 0
    while index < len(args):
        token = args[index]
        if token == "-C":
            if index + 1 >= len(args):
                return scope, list(args)
            target = os.path.expanduser(args[index + 1])
            scope = _normalized_cwd(target if os.path.isabs(target) else os.path.join(scope, target))
            index += 2
            continue
        if token in _GIT_GLOBAL_FLAGS:
            canonical.append(token)
            index += 1
            continue
        if token in _GIT_GLOBAL_VALUE_FLAGS:
            if index + 1 >= len(args):
                return scope, list(args)
            canonical.extend((token, args[index + 1]))
            index += 2
            continue
        if any(token.startswith(prefix + "=") for prefix in _GIT_GLOBAL_VALUE_FLAGS if prefix.startswith("--")):
            canonical.append(token)
            index += 1
            continue
        canonical.extend(args[index:])
        break
    return scope, canonical

def _normalize_git_global_arg(token: str) -> str:
    for option in _GIT_GLOBAL_VALUE_FLAGS:
        if not option.startswith("--"):
            continue
        prefix = option + "="
        if not token.startswith(prefix):
            continue
        value = token[len(prefix) :]
        return prefix + _strip_token_quotes(value)
    return token

def _safe_branch_name(refspec: str) -> str:
    if refspec.startswith("refs/") and not refspec.startswith("refs/heads/"):
        return ""
    branch = refspec.removeprefix("refs/heads/")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", branch):
        return ""
    if any(item in branch for item in ("..", "//", "@{", "\\", "~", "^", ":", "?", "*", "[")):
        return ""
    if branch.endswith(("/", ".", ".lock")):
        return ""
    return branch

def _safe_clone_branch(refspec: str) -> str:
    branch = _safe_branch_name(refspec)
    if not branch:
        return ""
    components = branch.split("/")
    if any(component.startswith(".") or component.endswith(".lock") for component in components):
        return ""
    return branch

def _github_https_clone_target(source: str) -> str:
    if (
        not source
        or not source.isascii()
        or "%" in source
        or "\\" in source
        or any(ord(char) < 0x21 or ord(char) == 0x7F for char in source)
    ):
        return ""
    try:
        parsed = urlsplit(source)
    except ValueError:
        return ""
    if (
        parsed.scheme.casefold() != "https"
        or parsed.netloc.casefold() != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return ""
    path_parts = parsed.path.split("/")
    if len(path_parts) != 3 or path_parts[0]:
        return ""
    owner, repo = path_parts[1:]
    if repo.endswith(".git"):
        repo = repo[:-4]
    owner_pattern = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?"
    repo_pattern = r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}"
    if not re.fullmatch(owner_pattern, owner) or not re.fullmatch(repo_pattern, repo):
        return ""
    return f"{owner}/{repo}"

def _path_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False

def _clone_path_has_sensitive_component(path: str) -> bool:
    return any(
        part.casefold() in _CONSTRAINED_CLONE_SENSITIVE_COMPONENTS
        for part in Path(path).parts
    )

def _clone_path_is_system_sensitive(path: str) -> bool:
    normalized = _normalized_cwd(path)
    if os.name == "nt":
        anchor = _normalized_cwd(str(Path(normalized).anchor))
        return normalized == anchor or _clone_path_has_sensitive_component(normalized)
    broad_roots = {_normalized_cwd(item) for item in _CONSTRAINED_CLONE_POSIX_BROAD_ROOTS}
    system_roots = tuple(_normalized_cwd(item) for item in _CONSTRAINED_CLONE_POSIX_SYSTEM_ROOTS)
    return normalized in broad_roots or any(
        normalized == root or _path_within(normalized, root) for root in system_roots
    )

def _clone_workspace_root(cwd: str) -> str:
    root = _normalized_cwd(cwd)
    if not os.path.isdir(root) or _clone_path_has_sensitive_component(root):
        return ""
    try:
        info = Path(root).lstat()
    except OSError:
        return ""
    if Path(root).is_symlink() or _is_reparse_info(info):
        return ""
    home = _normalized_cwd(str(Path.home()))
    if root == home or _clone_path_is_system_sensitive(root):
        return ""
    return root

def _clone_parent_access_mode() -> int:
    # Windows directory traversal does not use a POSIX executable bit.
    return os.W_OK if os.name == "nt" else os.W_OK | os.X_OK

def _clone_destination_allowed(destination: str, workspace_cwd: str) -> bool:
    if (
        not destination
        or not os.path.isabs(destination)
        or "\x00" in destination
        or any(char in _CONSTRAINED_CLONE_DESTINATION_META for char in destination)
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in destination)
    ):
        return False
    lexical_parts = Path(destination).parts
    if any(part in {".", ".."} for part in lexical_parts):
        return False
    if _clone_path_has_sensitive_component(destination) or os.path.lexists(destination):
        return False

    lexical_parent = Path(os.path.abspath(os.path.expanduser(destination))).parent
    while not os.path.lexists(lexical_parent):
        if lexical_parent.parent == lexical_parent:
            return False
        lexical_parent = lexical_parent.parent
    try:
        lexical_info = lexical_parent.lstat()
    except OSError:
        return False
    if lexical_parent.is_symlink() or _is_reparse_info(lexical_info):
        return False

    resolved = _normalized_cwd(destination)
    if _clone_path_has_sensitive_component(resolved) or _clone_path_is_system_sensitive(resolved):
        return False
    workspace_root = _clone_workspace_root(workspace_cwd)
    if not workspace_root or resolved == workspace_root or not _path_within(
        resolved, workspace_root
    ):
        return False
    return (
        lexical_parent.is_dir()
        and stat.S_ISDIR(lexical_info.st_mode)
        and os.access(lexical_parent, _clone_parent_access_mode())
    )

def _constrained_github_clone_candidate(
    command: str,
    *,
    effective_cwd: str,
    workspace_cwd: str,
) -> dict[str, str] | None:
    workspace_root = _clone_workspace_root(workspace_cwd)
    normalized_effective_cwd = _normalized_cwd(effective_cwd)
    if (
        not workspace_root
        or not (
            normalized_effective_cwd == workspace_root
            or _path_within(normalized_effective_cwd, workspace_root)
        )
        or not command.strip()
        or "$" in command
        or _SHELL_CONTROL_RE.search(command)
        or _has_shell_indirection(command)
        or _has_unquoted_shell_comment(command)
    ):
        return None
    tokens = _shell_tokens(command)
    if not tokens or any(token in _CONTROL_TOKENS for token in tokens):
        return None
    executable, args, wrappers = _unwrap_command(tokens)
    if (
        executable != "git"
        or wrappers
        or not _trusted_executable_token(tokens[0], "git")
        or not args
        or args[0] != "clone"
    ):
        return None

    clone_args = args[1:]
    seen_options: set[str] = set()
    index = 0
    while index < len(clone_args):
        token = clone_args[index]
        if token == "--":
            index += 1
            break
        if not token.startswith("-"):
            break
        if token in _CONSTRAINED_CLONE_BOOLEAN_OPTIONS:
            option = token
            value = ""
            index += 1
        elif token in {"--depth", "--branch"}:
            option = token
            if index + 1 >= len(clone_args):
                return None
            value = clone_args[index + 1]
            index += 2
        elif token.startswith("--depth=") or token.startswith("--branch="):
            option, value = token.split("=", 1)
            index += 1
        else:
            return None
        if option in seen_options:
            return None
        seen_options.add(option)
        if option == "--depth" and value != "1":
            return None
        if option == "--branch" and not _safe_clone_branch(value):
            return None

    positionals = clone_args[index:]
    if not {"--depth", "--no-checkout"}.issubset(seen_options) or len(positionals) != 2:
        return None
    source, destination = positionals
    target = _github_https_clone_target(source)
    if not target or not _clone_destination_allowed(destination, workspace_cwd):
        return None
    return {
        "source": source,
        "target": target,
        "destination": _normalized_cwd(destination),
    }

def _exact_github_clone_candidate(
    command: str,
    *,
    effective_cwd: str,
    workspace_cwd: str,
) -> dict[str, str] | None:
    """Parse a full GitHub clone that is eligible only for exact authorization."""
    workspace_root = _clone_workspace_root(workspace_cwd)
    normalized_effective_cwd = _normalized_cwd(effective_cwd)
    if (
        not workspace_root
        or not (
            normalized_effective_cwd == workspace_root
            or _path_within(normalized_effective_cwd, workspace_root)
        )
        or not command.strip()
        or "$" in command
        or _SHELL_CONTROL_RE.search(command)
        or _has_shell_indirection(command)
        or _has_unquoted_shell_comment(command)
    ):
        return None
    tokens = _shell_tokens(command)
    if not tokens or any(token in _CONTROL_TOKENS for token in tokens):
        return None
    executable, args, wrappers = _unwrap_command(tokens)
    if (
        executable != "git"
        or wrappers
        or not _trusted_executable_token(tokens[0], "git")
        or len(args) != 3
        or args[0] != "clone"
    ):
        return None
    source, destination = args[1:]
    target = _github_https_clone_target(source)
    if not target or not _clone_destination_allowed(destination, workspace_cwd):
        return None
    return {
        "source": source,
        "target": target,
        "destination": _normalized_cwd(destination),
    }

def _looks_like_git_clone(destination: str) -> bool:
    root = Path(destination)
    return bool(
        root.is_dir()
        and (
            (root / ".git").exists()
            or (
                (root / "HEAD").is_file()
                and (root / "objects").is_dir()
                and (root / "refs").is_dir()
            )
        )
    )

def _tracked_clone_roots(state: dict[str, Any]) -> tuple[str, ...]:
    roots = state.get("untrusted_clone_roots")
    paths = list(roots) if isinstance(roots, dict) else []
    pending = state.get("pending_constrained_clones")
    if isinstance(pending, dict):
        for item in pending.values():
            if not isinstance(item, dict):
                continue
            destination = str(item.get("destination") or "")
            if destination and _looks_like_git_clone(destination):
                paths.append(destination)
    return tuple(
        _normalized_cwd(path)
        for path in _ordered_unique(paths)
        if isinstance(path, str) and os.path.isabs(path)
    )

def _command_path_candidates(command: str, cwd: str) -> tuple[str, ...]:
    paths: list[str] = []
    for token in _shell_tokens(command):
        values = [token]
        if token.startswith("-") and "=" in token:
            values.append(token.split("=", 1)[1])
        for value in values:
            if (
                not value
                or value.startswith("-")
                or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value)
                or value.startswith("git@")
                or not (
                    os.path.isabs(value)
                    or value.startswith((".", "~"))
                    or "/" in value
                    or "\\" in value
                )
            ):
                continue
            expanded = os.path.expanduser(value)
            candidate = expanded if os.path.isabs(expanded) else os.path.join(cwd, expanded)
            paths.append(_normalized_cwd(candidate))
    return tuple(_ordered_unique(paths))

def _command_uses_untrusted_clone(command: str, cwd: str, roots: tuple[str, ...]) -> bool:
    if not roots or _is_strictly_read_only_command(command):
        return False
    normalized_cwd = _normalized_cwd(cwd)
    if any(_path_within(normalized_cwd, root) for root in roots):
        return True
    return any(
        _path_within(path, root)
        for path in _command_path_candidates(command, normalized_cwd)
        for root in roots
    )

def _safe_push_target(git_args: list[str]) -> tuple[str, str] | None:
    ignored = _SCOPED_PUSH_OPTIONS | {"--"}
    positionals = [token for token in git_args if token not in ignored]
    if any(token.startswith("-") for token in positionals):
        return None
    if len(positionals) != 2:
        return None
    remote, refspec = positionals
    if remote != "origin":
        return None
    branch = _safe_branch_name(refspec)
    return (remote, branch) if branch else None

def _exact_push_remote(git_args: list[str]) -> str | None:
    positionals: list[str] = []
    options_done = False
    index = 0
    while index < len(git_args):
        token = git_args[index]
        if options_done:
            positionals.append(token)
            index += 1
            continue
        if token == "--":
            options_done = True
            index += 1
            continue
        if token in _EXACT_PUSH_BOOLEAN_OPTIONS:
            index += 1
            continue
        if re.fullmatch(r"-[46fnquv]+", token):
            index += 1
            continue
        if token.startswith("-o") and token != "-o":
            index += 1
            continue
        if token in _EXACT_PUSH_VALUE_OPTIONS:
            if index + 1 >= len(git_args):
                return None
            index += 2
            continue
        if token.startswith(_EXACT_PUSH_VALUE_PREFIXES):
            index += 1
            continue
        if token.startswith(_EXACT_PUSH_OPTIONAL_VALUE_PREFIXES):
            index += 1
            continue
        if token.startswith("-"):
            return None
        positionals.append(token)
        index += 1

    if len(positionals) != 2:
        return None
    remote, refspec = positionals
    if remote != "origin" or not _safe_branch_name(refspec):
        return None
    return remote

def _github_target_from_remote(url: str) -> str:
    patterns = (
        r"git@github\.com:(?P<target>[A-Za-z0-9][A-Za-z0-9.-]*/[A-Za-z0-9][A-Za-z0-9._-]*)(?:\.git)?/?$",
        r"ssh://git@github\.com/(?P<target>[A-Za-z0-9][A-Za-z0-9.-]*/[A-Za-z0-9][A-Za-z0-9._-]*)(?:\.git)?/?$",
        r"https://github\.com/(?P<target>[A-Za-z0-9][A-Za-z0-9.-]*/[A-Za-z0-9][A-Za-z0-9._-]*)(?:\.git)?/?$",
    )
    for pattern in patterns:
        match = re.fullmatch(pattern, url.strip(), re.IGNORECASE)
        if match:
            return match.group("target").removesuffix(".git")
    return ""

def _git_remote_urls(
    scope: str,
    remote: str,
    *,
    exact_global_args: list[str] | None = None,
    environment: dict[str, str] | None = None,
) -> tuple[str, ...]:
    if not remote or remote.startswith("-"):
        return ()
    if exact_global_args is None:
        command = ["git", "-C", scope, "remote", "get-url", "--push", "--all", remote]
        run_cwd = None
    else:
        command = [
            "git",
            *exact_global_args,
            "remote",
            "get-url",
            "--push",
            "--all",
            remote,
        ]
        run_cwd = scope
    try:
        completed = subprocess.run(
            command,
            cwd=run_cwd,
            env=environment,
            text=True,
            capture_output=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ()
    if completed.returncode != 0:
        return ()
    return tuple(
        line.strip() for line in completed.stdout.splitlines() if line.strip()
    )

def _git_remote_targets(
    scope: str,
    remote: str,
    *,
    exact_global_args: list[str] | None = None,
    urls: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    if remote != "origin":
        return ()
    captured_urls = urls
    if captured_urls is None:
        captured_urls = _git_remote_urls(
            scope,
            remote,
            exact_global_args=exact_global_args,
        )
    targets = tuple(_github_target_from_remote(url) for url in captured_urls)
    return targets if targets and all(targets) else ()

def _git_config_values(
    scope: str,
    key: str,
    *,
    exact_global_args: list[str] | None = None,
    environment: dict[str, str] | None = None,
) -> tuple[str, ...] | None:
    if exact_global_args is None:
        command = ["git", "-C", scope, "config", "--get-all", key]
        run_cwd = None
    else:
        command = ["git", *exact_global_args, "config", "--get-all", key]
        run_cwd = scope
    try:
        completed = subprocess.run(
            command,
            cwd=run_cwd,
            env=environment,
            text=True,
            capture_output=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode == 1:
        return ()
    if completed.returncode != 0:
        return None
    return tuple(
        line.strip() for line in completed.stdout.splitlines() if line.strip()
    )

def _safe_git_push_url(url: str) -> str:
    value = url.strip()
    if not value or any(character.isspace() or ord(character) < 32 for character in value):
        return ""
    scp_match = re.fullmatch(
        r"[A-Za-z0-9._-]+@(?:[A-Za-z0-9][A-Za-z0-9.-]*|\[[0-9A-Fa-f:]+\]):(?P<path>.+)",
        value,
    )
    if scp_match:
        path = scp_match.group("path")
        return value if path and not path.startswith("-") else ""
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return ""
    scheme = parsed.scheme.casefold()
    if scheme not in {"https", "ssh"} or not parsed.hostname:
        return ""
    if parsed.query or parsed.fragment or not parsed.path or parsed.path == "/":
        return ""
    if parsed.password is not None:
        return ""
    if scheme == "https" and parsed.username is not None:
        return ""
    if scheme == "ssh" and parsed.username and not re.fullmatch(
        r"[A-Za-z0-9._-]+", parsed.username
    ):
        return ""
    return value

def _git_push_url_identity(url: str) -> str:
    safe_url = _safe_git_push_url(url)
    if not safe_url:
        return ""
    return hashlib.sha256(
        ("git-push-url\0" + safe_url).encode("utf-8", errors="replace")
    ).hexdigest()

def _git_remote_identities(
    scope: str,
    remote: str,
    *,
    exact_global_args: list[str] | None = None,
    urls: tuple[str, ...] | None = None,
    environment: dict[str, str] | None = None,
) -> tuple[str, ...]:
    if remote != "origin":
        return ()
    for key in (
        f"remote.{remote}.vcs",
        f"remote.{remote}.receivepack",
    ):
        values = _git_config_values(
            scope,
            key,
            exact_global_args=exact_global_args,
            environment=environment,
        )
        if values is None or values:
            return ()
    recurse_values = _git_config_values(
        scope,
        "push.recurseSubmodules",
        exact_global_args=exact_global_args,
        environment=environment,
    )
    if recurse_values is None or any(
        value.casefold() not in {"0", "false", "no", "off"}
        for value in recurse_values
    ):
        return ()
    captured_urls = urls
    if captured_urls is None:
        captured_urls = _git_remote_urls(
            scope,
            remote,
            exact_global_args=exact_global_args,
            environment=environment,
        )
    safe_urls = tuple(_safe_git_push_url(url) for url in captured_urls)
    if not safe_urls or not all(safe_urls):
        return ()
    if any(url.startswith("ssh://") or re.match(r"^[^@]+@[^:]+:", url) for url in safe_urls):
        ssh_command = _git_config_values(
            scope,
            "core.sshCommand",
            exact_global_args=exact_global_args,
            environment=environment,
        )
        git_environment = os.environ if environment is None else environment
        if (
            ssh_command is None
            or ssh_command
            or git_environment.get("GIT_SSH")
            or git_environment.get("GIT_SSH_COMMAND")
        ):
            return ()
    return tuple(_git_push_url_identity(url) for url in safe_urls)

def _scoped_git_candidate(
    command: str, cwd: str, dangerous: set[str]
) -> dict[str, Any] | None:
    if _SHELL_CONTROL_RE.search(command) or _has_shell_indirection(command):
        return None
    tokens = _shell_tokens(command)
    executable, args, wrappers = _unwrap_command(tokens)
    if (
        executable != "git"
        or wrappers
        or not tokens
        or not _trusted_executable_token(tokens[0], "git")
    ):
        return None
    scope, canonical_args = _git_scope_and_args(args, cwd)
    if "--bare" in canonical_args or any(
        token in _GIT_SCOPE_FLAGS
        or any(token.startswith(flag + "=") for flag in _GIT_SCOPE_FLAGS)
        for token in canonical_args
    ):
        return None
    subcommand, git_args, dynamic_config = _git_command(canonical_args)
    if dynamic_config or subcommand not in _SCOPED_GIT_OPERATIONS:
        return None
    branch = ""
    push_target: tuple[str, str] | None = None
    base_dangerous = dangerous - {"downloaded_code_execution"}
    if subcommand == "init":
        if base_dangerous != {"git_non_read_only"}:
            return None
        index = 0
        while index < len(git_args):
            token = git_args[index]
            if token in {"-b", "--initial-branch"}:
                if index + 1 >= len(git_args):
                    return None
                branch = git_args[index + 1]
                index += 2
                continue
            if token.startswith("--initial-branch="):
                branch = token.split("=", 1)[1]
                index += 1
                continue
            return None
        branch = _safe_branch_name(branch)
        if not branch:
            return None
    elif subcommand == "add":
        if base_dangerous != {"git_non_read_only"}:
            return None
        pathspecs = [token for token in git_args if token != "--"]
        if not pathspecs or any(token.startswith("-") for token in pathspecs):
            return None
    elif subcommand == "commit":
        if base_dangerous != {"git_non_read_only"}:
            return None
        has_message = False
        index = 0
        while index < len(git_args):
            token = git_args[index]
            if token == "-m":
                if index + 1 >= len(git_args):
                    return None
                has_message = True
                index += 2
                continue
            if token.startswith("--message=") or (token.startswith("-m") and token != "-m"):
                has_message = True
                index += 1
                continue
            return None
        if not has_message:
            return None
    else:
        if base_dangerous != {"git_non_read_only", "git_network", "git_push"}:
            return None
        push_target = _safe_push_target(git_args)
        if push_target is None:
            return None
    scope = _scope_identity(scope, exact=subcommand == "init")
    candidate: dict[str, Any] = {
        "digest": _command_hash(command, cwd),
        "operation": subcommand,
        "scope": scope,
        "scope_hash": _scope_hash(scope, exact=True),
        "codes": sorted(dangerous),
    }
    if subcommand == "add":
        candidate["pathspecs"] = pathspecs
    elif subcommand == "push" and push_target is not None:
        candidate["remote"], candidate["refspec"] = push_target
        remote_urls = _git_remote_urls(scope, candidate["remote"])
        candidate["remote_urls"] = list(remote_urls)
        candidate["remote_targets"] = list(
            _git_remote_targets(scope, candidate["remote"], urls=remote_urls)
        )
        candidate["remote_identities"] = list(
            _git_remote_identities(scope, candidate["remote"], urls=remote_urls)
        )
    elif subcommand == "init":
        candidate["branch"] = branch
    return candidate

def _parse_github_create_candidate(
    command: str, cwd: str, dangerous: set[str]
) -> tuple[dict[str, Any], str] | None:
    if (
        dangerous != {"github_network", "github_repo_create"}
        or _SHELL_CONTROL_RE.search(command)
        or _has_shell_indirection(command)
    ):
        return None
    tokens = _shell_tokens(command)
    executable, args, wrappers = _unwrap_command(tokens)
    if (
        executable != "gh"
        or wrappers
        or not tokens
        or len(args) < 3
        or args[:2] != ["repo", "create"]
    ):
        return None
    target = args[2]
    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9.-]*/[A-Za-z0-9][A-Za-z0-9._-]*", target
    ):
        return None
    source = ""
    remote = ""
    private = False
    index = 3
    while index < len(args):
        token = args[index]
        if token == "--private":
            private = True
            index += 1
            continue
        if token in {"--source", "--remote", "--description"}:
            if index + 1 >= len(args):
                return None
            value = args[index + 1]
            if token == "--source":
                source = value
            elif token == "--remote":
                remote = value
            index += 2
            continue
        if token.startswith("--source="):
            source = token.split("=", 1)[1]
            index += 1
            continue
        if token.startswith("--remote="):
            remote = token.split("=", 1)[1]
            index += 1
            continue
        if token.startswith("--description="):
            index += 1
            continue
        return None
    if not private or not source or remote != "origin":
        return None
    source_path = source if os.path.isabs(source) else os.path.join(cwd, source)
    scope = _git_repo_root(source_path)
    return (
        {
            "digest": _command_hash(command, cwd),
            "operation": "repo_create",
            "scope": scope,
            "scope_hash": _scope_hash(scope, exact=True),
            "codes": sorted(dangerous),
            "target": target,
            "visibility": "private",
            "remote": remote,
        },
        tokens[0],
    )

def _prompt_github_create_candidate(
    command: str, cwd: str, dangerous: set[str]
) -> dict[str, Any] | None:
    parsed = _parse_github_create_candidate(command, cwd, dangerous)
    if not parsed:
        return None
    candidate, executable_token = parsed
    raw = _strip_token_quotes(executable_token)
    if any(separator in raw for separator in ("/", "\\")):
        return None
    return candidate

def _ordered_unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(item for item in items if item))

def _authorization_clauses(
    prompt: str, approval_pattern: re.Pattern[str], *, git_continuations: bool = False
) -> list[str]:
    clauses: list[str] = []
    active = False
    for raw_clause in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        clause = raw_clause.strip()
        if not clause:
            active = False
            continue
        explicit = bool(approval_pattern.match(clause) and not _AUTH_NEGATED_RE.search(clause))
        if explicit:
            active = True
        elif not active:
            continue
        elif _NEGATED_AUTH_COMMENT_RE.match(clause):
            return []
        elif not _pure_authorization_command_candidates(clause) and not (
            git_continuations and _AUTH_GIT_CONTINUATION_RE.match(clause)
        ):
            active = False
            continue
        clauses.append(clause)
    return clauses

def _git_authorization_text(prompt: str) -> str:
    return "\n".join(
        _authorization_clauses(
            prompt, _LOCAL_GIT_APPROVAL_RE, git_continuations=True
        )
    )

def _prompt_clone_candidates(prompt: str, cwd: str) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen_destinations: set[str] = set()
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            candidate = _exact_github_clone_candidate(
                command,
                effective_cwd=cwd,
                workspace_cwd=cwd,
            ) or _constrained_github_clone_candidate(
                command,
                effective_cwd=cwd,
                workspace_cwd=cwd,
            )
            if not candidate:
                continue
            destination = candidate["destination"]
            if destination in seen_destinations:
                continue
            seen_destinations.add(destination)
            candidates.append(candidate)
    return candidates

def _prompt_git_operation_digests(
    prompt: str, cwd: str
) -> dict[str, dict[str, str]] | None:
    bindings: dict[str, dict[str, str]] = {}
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        code_spans = re.findall(r"`([^`\n]+)`", segment)
        commands = (
            _authorization_command_candidates(segment)
            if code_spans
            else _pure_authorization_command_candidates(segment)
        )
        for command in commands:
            dangerous = _dangerous_codes(_structured_command_findings(command))
            candidate = _scoped_git_candidate(command, cwd, dangerous)
            if not candidate:
                operation = _transaction_operation_from_command(command, cwd)
                if operation in _SCOPED_GIT_OPERATIONS:
                    return None
                continue
            scope_hash = str(candidate["scope_hash"])
            operation = str(candidate["operation"])
            digest = str(candidate["digest"])
            existing = bindings.setdefault(scope_hash, {}).get(operation)
            if existing and existing != digest:
                return None
            bindings[scope_hash][operation] = digest
    return bindings

def _prompt_absolute_paths(prompt: str) -> list[str]:
    matches: list[tuple[int, int, str]] = []
    occupied: list[tuple[int, int]] = []
    uri_spans = [(match.start(), match.end()) for match in _URI_SPAN_RE.finditer(prompt)]
    for match in _QUOTED_ABSOLUTE_PATH_RE.finditer(prompt):
        if any(start <= match.start() < end for start, end in uri_spans):
            continue
        path = match.group("path").strip().rstrip(")]}>、")
        matches.append((match.start(), match.end(), path))
        occupied.append((match.start(), match.end()))
    for pattern in (_ABSOLUTE_PATH_RE, _WINDOWS_ABSOLUTE_PATH_RE):
        for match in pattern.finditer(prompt):
            if any(
                start <= match.start() < end
                for start, end in (*occupied, *uri_spans)
            ):
                continue
            path = match.group(1).strip("\"'").rstrip(")]}>、")
            matches.append((match.start(), match.end(), path))
    return _ordered_unique([_normalized_cwd(item[2]) for item in sorted(matches)])

def _prompt_command_scopes(
    prompt: str, cwd: str, *, include_implicit_cwd: bool = False
) -> list[str]:
    scopes: list[str] = []
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            tokens = _shell_tokens(command)
            executable, args, wrappers = _unwrap_command(tokens)
            if (
                executable == "git"
                and not wrappers
                and tokens
                and _trusted_executable_token(tokens[0], "git")
            ):
                if "-C" not in args and not include_implicit_cwd:
                    continue
                scope, canonical_args = _git_scope_and_args(args, cwd)
                subcommand, _, dynamic_config = _git_command(canonical_args)
                if not dynamic_config and subcommand in _SCOPED_GIT_OPERATIONS:
                    scopes.append(_scope_identity(scope, exact=subcommand == "init"))
                continue
            candidate = _prompt_github_create_candidate(
                command, cwd, {"github_network", "github_repo_create"}
            )
            if candidate:
                scopes.append(str(candidate["scope"]))
    return _ordered_unique(scopes)

def _pending_git_usable(pending: dict[str, Any] | None) -> bool:
    if not isinstance(pending, dict) or pending.get("ambiguous") or not pending.get("digest"):
        return False
    created_at = pending.get("created_at")
    return isinstance(created_at, (int, float)) and (
        0 <= time.time() - float(created_at) <= _PENDING_GIT_TTL_SECONDS
    )

def _prompt_git_scopes(
    prompt: str,
    cwd: str,
    pending: dict[str, Any] | None,
    operations: set[str],
) -> list[str]:
    command_scopes = _prompt_command_scopes(prompt, cwd)
    if command_scopes:
        return command_scopes
    paths = _prompt_absolute_paths(prompt)
    if paths:
        return [_scope_identity(paths[0], exact="init" in operations)]
    if _CURRENT_REPO_RE.search(prompt):
        return [_scope_identity(cwd, exact="init" in operations)]
    if _PENDING_COMMAND_REFERENCE_RE.search(prompt) and _pending_git_usable(pending):
        scope = str(pending.get("scope") or "")
        if scope:
            return [
                _scope_identity(scope, exact=str(pending.get("operation") or "") == "init")
            ]
    return []

def _prompt_push_target(
    prompt: str, cwd: str, pending: dict[str, Any] | None
) -> tuple[str, str] | None:
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            candidate = _scoped_git_candidate(
                command, cwd, {"git_network", "git_non_read_only", "git_push"}
            )
            if candidate and candidate.get("operation") == "push":
                return str(candidate["remote"]), str(candidate["refspec"])
    for clause in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        match = re.search(
            r"(?i)(?:推送|(?<![A-Za-z0-9_])push\b)\s+"
            r"(?P<arguments>\S+(?:\s+\S+)?)\s*$",
            clause.strip(),
        )
        if not match:
            continue
        arguments = match.group("arguments").split()
        if len(arguments) == 1:
            if arguments[0].casefold() == "origin":
                return None
            refspec = arguments[0]
        elif len(arguments) == 2 and arguments[0].casefold() == "origin":
            refspec = arguments[1]
        else:
            return None
        branch = _safe_branch_name(refspec)
        return ("origin", branch) if branch else None
    if (
        _PENDING_COMMAND_REFERENCE_RE.search(prompt)
        and _pending_git_usable(pending)
        and str(pending.get("operation") or "") == "push"
    ):
        remote = str(pending.get("remote") or "")
        refspec = str(pending.get("refspec") or "")
        if remote and refspec:
            return remote, refspec
    return None

def _prompt_init_branch(prompt: str, cwd: str, pending: dict[str, Any] | None) -> str:
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            candidate = _scoped_git_candidate(command, cwd, {"git_non_read_only"})
            if candidate and candidate.get("operation") == "init":
                return str(candidate.get("branch") or "")
    if (
        _PENDING_COMMAND_REFERENCE_RE.search(prompt)
        and _pending_git_usable(pending)
        and str(pending.get("operation") or "") == "init"
    ):
        return str(pending.get("branch") or "")
    return ""

def _prompt_github_targets(prompt: str) -> list[str]:
    targets = [match.group("target") for match in _GITHUB_CREATE_COMMAND_RE.finditer(prompt)]
    owner_match = _GITHUB_OWNER_CONTEXT_RE.search(prompt)
    if owner_match and _GITHUB_CREATE_INTENT_RE.search(prompt):
        owner = owner_match.group("owner")
        intent_match = re.search(
            r"(?is)(?:创建|create)(?P<body>.{0,500}?)(?:private\s+"
            r"(?:repositories|repository|repos?|repo)|私有仓库)",
            prompt,
        )
        body = intent_match.group("body") if intent_match else ""
        for name in _GITHUB_REPO_NAME_RE.findall(body):
            if name != owner:
                targets.append(f"{owner}/{name}")
    return _ordered_unique(targets)

def _prompt_github_mappings(prompt: str, cwd: str) -> dict[str, str]:
    mappings: dict[str, str] = {}
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            candidate = _prompt_github_create_candidate(
                command, cwd, {"github_network", "github_repo_create"}
            )
            if candidate:
                mappings[str(candidate["scope_hash"])] = str(candidate["target"])
    return mappings

def _authorization_prose(text: str) -> str:
    prose = re.sub(r"`[^`\r\n]*`", " ", text)
    prose = re.sub(r"(?P<quote>['\"])[^'\"\r\n]*?(?P=quote)", " ", prose)
    return _QUOTED_ABSOLUTE_PATH_RE.sub(" ", prose)

def _explicit_git_operation_list(text: str) -> set[str]:
    candidate = text.strip()
    match = _GIT_OPERATION_LIST_RE.search(candidate)
    if (
        not match
        or match.start() != 0
        or candidate[match.end() :].strip(" `。；.!?")
    ):
        return set()
    return {
        item.casefold()
        for item in re.findall(
            r"(?i)(?:init|add|commit|push)", match.group("operations")
        )
    }

def _prompt_git_operations(prompt: str, cwd: str) -> set[str]:
    operations: set[str] = set()
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        commands = _authorization_command_candidates(segment)
        if commands:
            for command in commands:
                tokens = _shell_tokens(command)
                executable, args, wrappers = _unwrap_command(tokens)
                if (
                    executable != "git"
                    or wrappers
                    or not tokens
                    or not _trusted_executable_token(tokens[0], "git")
                ):
                    continue
                _, canonical_args = _git_scope_and_args(args, cwd)
                subcommand, _, dynamic_config = _git_command(canonical_args)
                if not dynamic_config and subcommand in _SCOPED_GIT_OPERATIONS:
                    operations.add(subcommand)
                if not dynamic_config:
                    operations.update(
                        _explicit_git_operation_list(
                            "git " + " ".join(canonical_args)
                        )
                    )
            continue
        for match in _GIT_OPERATION_LIST_RE.finditer(_authorization_prose(segment)):
            operations.update(
                item.casefold()
                for item in re.findall(
                    r"(?i)(?:init|add|commit|push)", match.group("operations")
                )
            )

    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        if _authorization_command_candidates(segment):
            continue
        for match in _CHINESE_GIT_OPERATION_LIST_RE.finditer(
            _authorization_prose(segment)
        ):
            operations.update(
                _CHINESE_GIT_OPERATION_MAP[item]
                for item in re.findall(
                    r"初始化|暂存|提交|推送", match.group("operations")
                )
            )
    return operations

def _local_git_grant_from_prompt(
    prompt: str,
    cwd: str,
    turn_id: str,
    pending: dict[str, Any] | None,
    session_id: str = "",
) -> dict[str, Any] | None:
    policy = policy_store.load_policy()
    if not (
        policy.enable_natural_language_approvals
        and policy.enable_scoped_git_transactions
    ):
        return None
    authorization_text = _git_authorization_text(prompt)
    if (
        not authorization_text
        or _AUTHORIZATION_REVOCATION_RE.search(prompt)
        or _AUTH_NEGATED_RE.search(authorization_text)
        or _NEGATED_GIT_OPERATION_RE.search(authorization_text)
    ):
        return None
    operations = _prompt_git_operations(authorization_text, cwd)
    operation_digests = _prompt_git_operation_digests(authorization_text, cwd)
    if operation_digests is None:
        return None
    parsed_push_target = _prompt_push_target(authorization_text, cwd, pending)
    if parsed_push_target is not None:
        operations.add("push")
    github_targets = _prompt_github_targets(authorization_text)
    if github_targets:
        operations.add("repo_create")
    pending_reference = bool(
        _PENDING_COMMAND_REFERENCE_RE.search(authorization_text) and _pending_git_usable(pending)
    )
    if not operations and pending_reference:
        operation = str(pending.get("operation") or "")
        if operation in _SCOPED_TRANSACTION_OPERATIONS:
            operations.add(operation)
    if not github_targets and pending_reference:
        pending_target = str(pending.get("target") or "")
        if not pending_target and "push" in operations:
            remote_targets = pending.get("remote_targets")
            if isinstance(remote_targets, list) and len(remote_targets) == 1:
                pending_target = str(remote_targets[0] or "")
        if pending_target:
            github_targets = [pending_target]
    scopes = _prompt_git_scopes(authorization_text, cwd, pending, operations)
    push_target = parsed_push_target if "push" in operations else None
    clone_candidates = _prompt_clone_candidates(authorization_text, cwd)
    clone_bindings = {
        _scope_hash(candidate["destination"], exact=True): candidate
        for candidate in clone_candidates
    }
    if "push" in operations and not github_targets and len(scopes) == 1:
        scope_hash = _scope_hash(scopes[0], exact=True)
        clone_binding = clone_bindings.get(scope_hash)
        if clone_binding:
            github_targets = [clone_binding["target"]]
        elif push_target and push_target[0] == "origin":
            remote_targets = _git_remote_targets(scopes[0], "origin")
            if len(remote_targets) == 1:
                github_targets = [remote_targets[0]]
    if (
        not operations
        or not scopes
        or ("push" in operations and (push_target is None or not github_targets))
    ):
        return None
    init_branch = _prompt_init_branch(authorization_text, cwd, pending) or (
        push_target[1] if push_target else ""
    )
    if "init" in operations and not init_branch:
        return None
    explicit_mappings = _prompt_github_mappings(authorization_text, cwd)
    scope_hashes = {_scope_hash(scope, exact=True) for scope in scopes}
    requires_explicit_mapping = len(scopes) > 1 or len(github_targets) > 1
    if requires_explicit_mapping and (
        set(explicit_mappings) != scope_hashes
        or len(set(explicit_mappings.values())) != len(explicit_mappings)
        or set(explicit_mappings.values()) != set(github_targets)
    ):
        return None
    if github_targets and len(github_targets) != len(scopes):
        return None
    bindings: dict[str, dict[str, Any]] = {}
    for scope in scopes:
        scope_hash = _scope_hash(scope, exact=True)
        target = explicit_mappings.get(scope_hash, "")
        if not target and len(scopes) == 1 and len(github_targets) == 1:
            target = github_targets[0]
        remote_identity = ""
        if push_target:
            clone_binding = clone_bindings.get(scope_hash)
            if clone_binding and clone_binding.get("target") == target:
                remote_identity = _git_push_url_identity(clone_binding["source"])
            else:
                remote_identities = _git_remote_identities(scope, push_target[0])
                if len(remote_identities) > 1:
                    return None
                if remote_identities:
                    remote_identity = remote_identities[0]
        bindings[scope_hash] = {
            "scope": scope,
            "target": target,
            "remote": push_target[0] if push_target else "",
            "remote_identity": remote_identity,
            "init_branch": init_branch,
            "push_branch": push_target[1] if push_target else "",
            "operation_digests": dict(operation_digests.get(scope_hash) or {}),
        }
    if github_targets and {item["target"] for item in bindings.values()} != set(github_targets):
        return None
    if "push" in operations and any(not item["target"] for item in bindings.values()):
        return None
    pending_digest = ""
    if (
        pending_reference
        and not _prompt_command_scopes(authorization_text, cwd)
        and not _prompt_absolute_paths(authorization_text)
        and not _CURRENT_REPO_RE.search(authorization_text)
    ):
        pending_digest = str(pending.get("digest") or "")
    session_hash = hashlib.sha256(
        session_id.encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    authorization_cwd = _normalized_cwd(cwd)
    issued_at = time.time()
    grant = {
        "turn_id": turn_id,
        "issued_turn_id": turn_id,
        "session_hash": session_hash,
        "authorization_cwd": authorization_cwd,
        "bindings": bindings,
        "operations": sorted(operations),
        "consumed_operations": {},
        "pending_digest": pending_digest,
        "issued_at": issued_at,
    }
    transaction_material = json.dumps(
        {
            "issued_turn_id": turn_id,
            "session_hash": session_hash,
            "authorization_cwd": authorization_cwd,
            "bindings": bindings,
            "operations": grant["operations"],
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    grant["transaction_id"] = hashlib.sha256(
        transaction_material.encode("utf-8")
    ).hexdigest()[:16]
    return grant

def _git_transaction_resume_requested(prompt: str) -> bool:
    policy = policy_store.load_policy()
    authorization_text = _git_authorization_text(prompt)
    return bool(
        policy.enable_natural_language_approvals
        and policy.enable_scoped_git_transactions
        and authorization_text
        and _AUTHORIZED_TRANSACTION_CONTINUATION_RE.search(authorization_text)
        and not _AUTHORIZATION_REVOCATION_RE.search(prompt)
        and not _AUTH_NEGATED_RE.search(authorization_text)
        and not _NEGATED_GIT_OPERATION_RE.search(authorization_text)
    )

def _authorized_git_command_scopes(prompt: str, cwd: str) -> list[str]:
    scopes: list[str] = []
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            tokens = _shell_tokens(command)
            executable, args, wrappers = _unwrap_command(tokens)
            if (
                executable != "git"
                or wrappers
                or not tokens
                or not _trusted_executable_token(tokens[0], "git")
            ):
                continue
            scope, _ = _git_scope_and_args(args, cwd)
            scopes.append(_scope_identity(scope, exact=True))
    return _ordered_unique(scopes)

def _is_repository_identity_config_command(command: str, cwd: str) -> bool:
    tokens = _shell_tokens(command)
    executable, args, wrappers = _unwrap_command(tokens)
    if (
        not tokens
        or wrappers
        or executable != "git"
        or not _trusted_executable_token(tokens[0], "git")
    ):
        return False
    _, canonical_args = _git_scope_and_args(args, cwd)
    subcommand, git_args, dynamic_config = _git_command(canonical_args)
    global_arg_count = len(canonical_args) - len(git_args) - 1
    return bool(
        not dynamic_config
        and subcommand == "config"
        and global_arg_count == 0
        and len(git_args) == 3
        and git_args[0] == "--local"
        and git_args[1] in {"user.name", "user.email"}
        and git_args[2]
    )

def _is_strict_identity_amend_command(command: str, cwd: str) -> bool:
    tokens = _shell_tokens(command)
    executable, args, wrappers = _unwrap_command(tokens)
    if (
        not tokens
        or wrappers
        or executable != "git"
        or not _trusted_executable_token(tokens[0], "git")
    ):
        return False
    _, canonical_args = _git_scope_and_args(args, cwd)
    subcommand, git_args, dynamic_config = _git_command(canonical_args)
    global_arg_count = len(canonical_args) - len(git_args) - 1
    return bool(
        not dynamic_config
        and subcommand == "commit"
        and global_arg_count == 0
        and len(git_args) == 3
        and set(git_args) == {"--amend", "--no-edit", "--reset-author"}
    )

def _git_transaction_continuation_commands_safe(prompt: str, cwd: str) -> bool:
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            tokens = _shell_tokens(command)
            executable, args, wrappers = _unwrap_command(tokens)
            if executable == "git":
                if (
                    not tokens
                    or wrappers
                    or not _trusted_executable_token(tokens[0], "git")
                ):
                    return False
                _, canonical_args = _git_scope_and_args(args, cwd)
                subcommand, git_args, dynamic_config = _git_command(canonical_args)
                if subcommand in {"", "transaction"} and not dynamic_config:
                    continue
                if _is_repository_identity_config_command(command, cwd):
                    continue
                if subcommand in _SCOPED_GIT_OPERATIONS and not dynamic_config:
                    if subcommand == "commit" and "--amend" in git_args:
                        if not _is_strict_identity_amend_command(command, cwd):
                            return False
                    continue
                return False
            if executable == "gh":
                if wrappers or not _prompt_github_create_candidate(
                    command,
                    cwd,
                    {"github_network", "github_repo_create"},
                ):
                    return False
                continue
            if _dangerous_codes(_structured_command_findings(command)):
                return False
    return True

def _git_grant_effective_operations(
    grant: dict[str, Any], scope_hash: str
) -> set[str]:
    operations = {
        str(item)
        for item in grant.get("operations") or ()
        if str(item) in _SCOPED_TRANSACTION_OPERATIONS
    }
    bindings = grant.get("bindings")
    if not operations or not isinstance(bindings, dict):
        return set()
    binding = bindings.get(scope_hash)
    if not isinstance(binding, dict):
        return set()

    exact_operations: set[str] = set()
    local_exact_operations: set[str] = set()
    for item_scope_hash, item in bindings.items():
        if not isinstance(item, dict):
            return set()
        operation_digests = item.get("operation_digests")
        if operation_digests is None:
            operation_digests = {}
        if not isinstance(operation_digests, dict):
            return set()
        for operation, digest in operation_digests.items():
            operation = str(operation)
            if operation not in operations:
                continue
            exact_operations.add(operation)
            if (
                item_scope_hash == scope_hash
                and isinstance(digest, str)
                and digest
            ):
                local_exact_operations.add(operation)

    return (operations - exact_operations) | local_exact_operations

def _git_grant_usable(
    grant: dict[str, Any] | None,
    expected_session_hash: str = "",
) -> bool:
    if not isinstance(grant, dict) or not grant.get("transaction_id"):
        return False
    issued_at = grant.get("issued_at")
    if not isinstance(issued_at, (int, float)) or isinstance(issued_at, bool):
        return False
    if not 0 <= time.time() - float(issued_at) <= _SCOPED_GIT_TRANSACTION_TTL_SECONDS:
        return False
    if (
        not grant.get("issued_turn_id")
        or not grant.get("authorization_cwd")
        or not grant.get("session_hash")
        or (expected_session_hash and grant.get("session_hash") != expected_session_hash)
    ):
        return False
    bindings = grant.get("bindings")
    consumed = grant.get("consumed_operations") or {}
    if not isinstance(bindings, dict) or not bindings:
        return False
    return any(
        _git_grant_effective_operations(grant, scope_hash).difference(
            set(consumed.get(scope_hash) or [])
        )
        for scope_hash in bindings
    )

def _continued_git_grant_from_prompt(
    prompt: str,
    cwd: str,
    session_id: str,
    turn_id: str,
    prior: dict[str, Any] | None,
) -> dict[str, Any] | None:
    authorization_text = _git_authorization_text(prompt)
    expected_session_hash = hashlib.sha256(
        session_id.encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    if (
        not _git_transaction_resume_requested(prompt)
        or not _git_grant_usable(prior, expected_session_hash)
        or prior.get("pending_digest")
        or _normalized_cwd(cwd) != prior.get("authorization_cwd")
        or re.search(r"(?i)--(?:public|internal|force(?:-with-lease)?)\b", authorization_text)
        or not _git_transaction_continuation_commands_safe(authorization_text, cwd)
    ):
        return None

    prior_bindings = prior.get("bindings")
    if not isinstance(prior_bindings, dict):
        return None
    prior_operations = set(prior.get("operations") or [])
    if len(prior_operations) < 2 or not prior_operations.intersection({"push", "repo_create"}):
        return None
    prior_scope_hashes = set(prior_bindings)
    explicit_scopes = _ordered_unique(
        [
            *_prompt_command_scopes(authorization_text, cwd),
            *_authorized_git_command_scopes(authorization_text, cwd),
        ]
    )
    if not explicit_scopes:
        explicit_scopes = _prompt_git_scopes(
            authorization_text,
            cwd,
            None,
            prior_operations,
        )
    explicit_scope_hashes = {
        _scope_hash(scope, exact=True) for scope in explicit_scopes
    }
    if explicit_scope_hashes and not explicit_scope_hashes.issubset(prior_scope_hashes):
        return None

    github_targets = set(_prompt_github_targets(authorization_text))
    allowed_targets = {
        str(binding.get("target") or "")
        for binding in prior_bindings.values()
        if isinstance(binding, dict) and binding.get("target")
    }
    if github_targets and not github_targets.issubset(allowed_targets):
        return None

    push_target = _prompt_push_target(authorization_text, cwd, None)
    allowed_push_targets = {
        (
            str(binding.get("remote") or ""),
            str(binding.get("push_branch") or ""),
        )
        for binding in prior_bindings.values()
        if isinstance(binding, dict) and binding.get("remote") and binding.get("push_branch")
    }
    if push_target and push_target not in allowed_push_targets:
        return None

    init_branch = _prompt_init_branch(authorization_text, cwd, None)
    allowed_init_branches = {
        str(binding.get("init_branch") or "")
        for binding in prior_bindings.values()
        if isinstance(binding, dict) and binding.get("init_branch")
    }
    if init_branch and init_branch not in allowed_init_branches:
        return None

    consumed = prior.get("consumed_operations") or {}
    return {
        **prior,
        "turn_id": turn_id,
        "bindings": {
            scope_hash: dict(binding)
            for scope_hash, binding in prior_bindings.items()
        },
        "consumed_operations": {
            scope_hash: list(items)
            for scope_hash, items in consumed.items()
        },
    }

def _authorization_command_candidates(segment: str) -> list[str]:
    code_spans = [item.strip() for item in re.findall(r"`([^`\n]+)`", segment) if item.strip()]
    if code_spans:
        return [
            item
            for item in code_spans
            if (
                ((match := _COMMAND_START_RE.search(item)) is not None and match.start(1) == 0)
                or _QUOTED_WINDOWS_EXECUTABLE_RE.match(item) is not None
            )
        ]

    quoted_windows = _QUOTED_WINDOWS_EXECUTABLE_RE.search(segment)
    approval = _DANGEROUS_APPROVAL_RE.match(segment)
    if quoted_windows:
        prefix_start = approval.end() if approval else 0
        prefix = segment[prefix_start : quoted_windows.start()].strip()
        if prefix not in {"", "&"}:
            return []
    if quoted_windows:
        prefix = segment[: quoted_windows.start()].rstrip()
        call_operator = "& " if re.search(r"(?:^|\s)&\s*$", prefix) else ""
        remainder = segment[quoted_windows.end() :].strip(" `")
        candidate = call_operator + quoted_windows.group(0)
        if remainder:
            candidate += " " + remainder
        return [candidate] if _shell_tokens(candidate) else []

    match = _COMMAND_START_RE.search(segment)
    if not match:
        return []
    candidate = segment[match.start(1) :].strip(" `")
    prefix = segment[: match.start(1)].rstrip()
    opening_quote = prefix[-1:] if prefix[-1:] in {"'", '"'} else ""
    if opening_quote:
        if candidate.endswith(opening_quote):
            unwrapped = candidate[:-1].rstrip()
            if _shell_tokens(unwrapped):
                return [unwrapped]
        reconstructed = opening_quote + candidate
        if _shell_tokens(reconstructed):
            return [reconstructed]
        return []
    if _shell_tokens(candidate):
        return [candidate]
    if candidate.endswith(("'", '"')):
        unwrapped = candidate[:-1].rstrip()
        if _shell_tokens(unwrapped):
            return [unwrapped]
    return [candidate]

def _pure_authorization_command_candidates(segment: str) -> list[str]:
    stripped = segment.strip()
    if not stripped or _COMMAND_NEGATION_RE.search(stripped):
        return []
    if stripped.startswith("`") and stripped.endswith("`") and not stripped.startswith("```"):
        stripped = stripped[1:-1].strip()
    match = _COMMAND_START_RE.search(stripped)
    quoted_windows = _QUOTED_WINDOWS_EXECUTABLE_RE.match(stripped)
    if (not match or match.start(1) != 0) and quoted_windows is None:
        return []
    return _authorization_command_candidates(stripped)

def _transaction_operation_from_command(command: str, cwd: str) -> str:
    dangerous = _dangerous_codes(_structured_command_findings(command))
    candidate = _scoped_git_candidate(command, cwd, dangerous)
    if candidate:
        return str(candidate.get("operation") or "")
    tokens = _shell_tokens(command)
    executable, args, wrappers = _unwrap_command(tokens)
    if (
        tokens
        and not wrappers
        and executable == "git"
        and _trusted_executable_token(tokens[0], "git")
    ):
        _, canonical_args = _git_scope_and_args(args, cwd)
        subcommand, _, _ = _git_command(canonical_args)
        if _is_strict_identity_amend_command(command, cwd):
            return ""
        if subcommand in _SCOPED_GIT_OPERATIONS:
            return subcommand
    if (
        tokens
        and not wrappers
        and executable == "gh"
        and len(args) >= 2
        and args[:2] == ["repo", "create"]
        and not any(separator in _strip_token_quotes(tokens[0]) for separator in ("/", "\\"))
    ):
        return "repo_create"
    candidate = _prompt_github_create_candidate(
        command,
        cwd,
        {"github_network", "github_repo_create"},
    )
    return "repo_create" if candidate else ""

def _prompt_has_unresolved_git_scope_override(prompt: str, cwd: str) -> bool:
    for segment in _AUTH_SEGMENT_SPLIT_RE.split(prompt):
        for command in _authorization_command_candidates(segment):
            tokens = _shell_tokens(command)
            executable, args, wrappers = _unwrap_command(tokens)
            if (
                executable != "git"
                or wrappers
                or not tokens
                or not _trusted_executable_token(tokens[0], "git")
            ):
                continue
            _, canonical_args = _git_scope_and_args(args, cwd)
            subcommand, git_args, _ = _git_command(canonical_args)
            if not subcommand:
                continue
            global_arg_count = len(canonical_args) - len(git_args) - 1
            if global_arg_count < 0:
                return True
            global_args = canonical_args[:global_arg_count]
            if "--bare" in global_args or any(
                token in _GIT_SCOPE_FLAGS
                or any(token.startswith(flag + "=") for flag in _GIT_SCOPE_FLAGS)
                for token in global_args
            ):
                return True
    return False

def _dangerous_authorization_hashes(
    prompt: str,
    cwd: str,
    untrusted_roots: tuple[str, ...] = (),
    *,
    skip_scoped_candidates: bool = False,
) -> dict[str, list[str]]:
    policy = policy_store.load_policy()
    if (
        not policy.enable_natural_language_approvals
        or _AUTHORIZATION_REVOCATION_RE.search(prompt)
    ):
        return {}
    authorized: dict[str, set[str]] = {}
    for clause in _authorization_clauses(prompt, _DANGEROUS_APPROVAL_RE):
        candidates = (
            _authorization_command_candidates(clause)
            if _DANGEROUS_APPROVAL_RE.match(clause)
            else _pure_authorization_command_candidates(clause)
        )
        for candidate in candidates:
            digest = _command_hash(candidate, cwd)
            if not digest:
                continue
            dangerous = _dangerous_codes(_structured_command_findings(candidate))
            if _command_uses_untrusted_clone(candidate, cwd, untrusted_roots):
                dangerous.add("downloaded_code_execution")
            if (
                skip_scoped_candidates
                and policy.enable_scoped_git_transactions
                and _transaction_operation_from_command(candidate, cwd)
            ):
                continue
            for code in dangerous:
                authorized.setdefault(code, set()).add(digest)
    return {code: sorted(digests) for code, digests in sorted(authorized.items())}

def _explicit_expand(prompt: str) -> bool:
    if _EXPANSION_NEGATED_RE.search(prompt):
        return False
    return bool(_CURRENT_EXPANSION_RE.search(prompt) or _CURRENT_EXPANSION_AUTH_RE.search(prompt))

def _nested_allowed(prompt: str) -> bool:
    if _EXPANSION_NEGATED_RE.search(prompt):
        return False
    return bool(_NESTED_AUTH_RE.search(prompt))

def _sensitive_context(text: str) -> bool:
    policy = policy_store.load_policy()
    return bool(
        policy.markers
        and policy.terms
        and _matches_policy_values(text, policy.markers)
        and _matches_policy_values(text, policy.terms)
    )

def _bounded_term_source(term: str) -> str:
    return rf"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])"

def _external_target_scope_from_prompt(text: str) -> tuple[set[str], str | None]:
    mcp_targets: set[str] = set()
    exact_tool_hashes: set[str] = set()
    for match in _MCP_TARGET_CANDIDATE_RE.finditer(text):
        if not _prompt_target_start_is_delimited(text, match.start()):
            return set(), None
        token = match.group(0).rstrip(_MCP_TARGET_TRAILING_PUNCTUATION)
        if not _MCP_TARGET_TOKEN_RE.fullmatch(token):
            return set(), None
        targets = _external_targets_from_tool_name(token)
        if not targets:
            return set(), None
        mcp_targets.update(targets)
        if len(token.split("__", 2)) == 3:
            exact_tool_hashes.add(_policy_value_hash(token))
    if len(exact_tool_hashes) > 1:
        return set(), None
    natural_text = _MCP_TARGET_CANDIDATE_RE.sub(" ", text)
    natural_targets = {
        name
        for name, pattern in _PROMPT_EXTERNAL_TARGET_PATTERNS
        if any(
            (
                name == "web"
                and match.group(0).casefold().startswith(("http://", "https://"))
                and _prompt_target_start_is_delimited(natural_text, match.start())
            )
            or (
                not match.group(0).casefold().startswith(("http://", "https://"))
                and _prompt_target_match_is_delimited(natural_text, match.start(), match.end())
            )
            for match in pattern.finditer(natural_text)
        )
    }
    exact_tool_hash = next(iter(exact_tool_hashes)) if exact_tool_hashes else None
    return mcp_targets | natural_targets, exact_tool_hash

def _prompt_target_start_is_delimited(text: str, start: int) -> bool:
    return bool(
        start == 0
        or text[start - 1].isspace()
        or text[start - 1] in "([{\"'`（【「『"
    )

def _prompt_target_match_is_delimited(text: str, start: int, end: int) -> bool:
    if not _prompt_target_start_is_delimited(text, start):
        return False
    if end == len(text) or text[end].isspace():
        return True
    cursor = end
    if text[cursor] not in _PROMPT_TARGET_TERMINAL_PUNCTUATION:
        return False
    while cursor < len(text) and text[cursor] in _PROMPT_TARGET_TERMINAL_PUNCTUATION:
        cursor += 1
    return cursor == len(text) or text[cursor].isspace()

def _external_targets_from_tool_name(tool_name: str) -> set[str]:
    normalized = tool_name.casefold()
    if not normalized.startswith("mcp__"):
        return {name for name, pattern in _EXTERNAL_TARGET_PATTERNS if pattern.search(tool_name)}
    parts = normalized.split("__", 2)
    if len(parts) < 2:
        return set()
    server = parts[1].casefold()
    direct_target = _TRUSTED_MCP_SERVER_TARGETS.get(server)
    if direct_target:
        return {direct_target}
    if len(parts) < 3:
        return set()
    operation = parts[2].casefold()
    for prefix, target in _TRUSTED_MCP_MULTIPLEXER_TARGET_PREFIXES.get(server, ()):
        if operation == prefix.removesuffix("_") or operation.startswith(prefix):
            return {target}
    return set()

def _policy_value_hash(value: str) -> str:
    return hashlib.sha256(value.casefold().encode("utf-8", errors="replace")).hexdigest()

def _matching_grant_term_hashes(text: str) -> set[str]:
    matched: set[str] = set()
    for term in policy_store.load_policy().terms:
        mentions = list(re.finditer(_bounded_term_source(term), text, re.IGNORECASE))
        if not mentions:
            continue
        if any(
            _TERM_NEGATION_SUFFIX_RE.search(text[max(0, item.start() - 48) : item.start()])
            or _TERM_NEGATION_POSTFIX_RE.search(text[item.end() : item.end() + 48])
            for item in mentions
        ):
            continue
        matched.add(_policy_value_hash(term))
    return matched

def _sensitive_disclosure_grant(prompt: str, turn_id: str) -> dict[str, Any] | None:
    policy = policy_store.load_policy()
    if (
        not policy.enable_sensitive_disclosure_approvals
        or not policy.markers
        or not policy.terms
        or not turn_id
    ):
        return None
    sentences = [
        item.strip()
        for item in re.split(r"(?:[。！？；]+|[!?;]+(?=\s|$)|\n+)", prompt)
        if item.strip()
    ]
    if any(_SENSITIVE_NEGATION_RE.search(item) and _SENSITIVE_EXTERNAL_VERB_RE.search(item) for item in sentences):
        return None
    for item in sentences:
        targets, exact_tool_hash = _external_target_scope_from_prompt(item)
        term_hashes = _matching_grant_term_hashes(item)
        if all(
            (
                _SENSITIVE_EXPLICIT_AUTH_RE.search(item),
                _matches_policy_values(item, policy.markers),
                term_hashes,
                _SENSITIVE_EXTERNAL_VERB_RE.search(item),
                len(targets) == 1,
            )
        ):
            grant = {
                "turn_id": turn_id,
                "target": next(iter(targets)),
                "term_hashes": sorted(term_hashes),
            }
            if exact_tool_hash:
                grant["tool_name_hash"] = exact_tool_hash
            return grant
    return None

def _sed_delimited_end(text: str, start: int, delimiter: str) -> int | None:
    escaped = False
    for index in range(start, len(text)):
        character = text[index]
        if escaped:
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == delimiter:
            return index
    return None

def _sed_command_body(script: str) -> str | None:
    text = script.strip()
    if not text or any(separator in text for separator in (";", "\n", "\r")):
        return None
    position = 0
    addresses = 0
    while addresses < 2:
        while position < len(text) and text[position].isspace():
            position += 1
        if position >= len(text):
            return None
        if text[position].isdigit():
            while position < len(text) and text[position].isdigit():
                position += 1
        elif text[position] == "$":
            position += 1
        elif text[position] == "/":
            end = _sed_delimited_end(text, position + 1, "/")
            if end is None:
                return None
            position = end + 1
        else:
            break
        addresses += 1
        while position < len(text) and text[position].isspace():
            position += 1
        if position < len(text) and text[position] in {"+", "~"}:
            position += 1
            if position >= len(text) or not text[position].isdigit():
                return None
            while position < len(text) and text[position].isdigit():
                position += 1
        while position < len(text) and text[position].isspace():
            position += 1
        if addresses == 1 and position < len(text) and text[position] == ",":
            position += 1
            continue
        break
    while position < len(text) and text[position].isspace():
        position += 1
    if position < len(text) and text[position] == "!":
        position += 1
    body = text[position:].lstrip()
    return body or None

def _sed_substitution_is_read_only(body: str) -> bool:
    if len(body) < 4 or body[0] != "s":
        return False
    delimiter = body[1]
    if delimiter.isalnum() or delimiter.isspace() or delimiter == "\\":
        return False
    pattern_end = _sed_delimited_end(body, 2, delimiter)
    if pattern_end is None:
        return False
    replacement_end = _sed_delimited_end(body, pattern_end + 1, delimiter)
    if replacement_end is None:
        return False
    flags = body[replacement_end + 1 :].strip()
    return bool(re.fullmatch(r"(?:[gIpPmM]|[1-9][0-9]*)*", flags))

def _sed_script_is_strictly_read_only(script: str) -> bool:
    body = _sed_command_body(script)
    if not body:
        return False
    if body[0] == "s":
        return _sed_substitution_is_read_only(body)
    if body[0] in {"p", "P", "d", "D", "l", "n", "N", "=", "x", "g", "G", "h", "H"}:
        return not body[1:].strip()
    if body[0] in {"q", "Q"}:
        return not body[1:].strip() or bool(re.fullmatch(r"\s*[0-9]+", body[1:]))
    return False

def _sed_is_strictly_read_only(args: list[str]) -> bool:
    scripts: list[str] = []
    has_expression = False
    positional_script_consumed = False
    options_active = True
    index = 0
    while index < len(args):
        token = args[index]
        if options_active and token == "--":
            options_active = False
            index += 1
            continue
        if options_active and token.startswith("--"):
            if token in {"--file", "--in-place"} or token.startswith(
                ("--file=", "--in-place=")
            ):
                return False
            if token in {"--expression"}:
                index += 1
                if index >= len(args):
                    return False
                has_expression = True
                scripts.append(args[index])
            elif token.startswith("--expression="):
                has_expression = True
                scripts.append(token.split("=", 1)[1])
            elif token not in {
                "--quiet",
                "--silent",
                "--regexp-extended",
                "--separate",
                "--unbuffered",
                "--null-data",
                "--posix",
                "--sandbox",
            }:
                return False
            index += 1
            continue
        if options_active and token.startswith("-") and token != "-":
            cluster = token[1:]
            offset = 0
            while offset < len(cluster):
                option = cluster[offset]
                if option in {"i", "f"}:
                    return False
                if option == "e":
                    has_expression = True
                    inline = cluster[offset + 1 :]
                    if inline:
                        scripts.append(inline)
                    else:
                        index += 1
                        if index >= len(args):
                            return False
                        scripts.append(args[index])
                    break
                if option not in {"n", "E", "r", "s", "u", "z"}:
                    return False
                offset += 1
            index += 1
            continue
        if not has_expression and not positional_script_consumed:
            scripts.append(token)
            positional_script_consumed = True
        index += 1
    return bool(scripts) and all(_sed_script_is_strictly_read_only(script) for script in scripts)

def _is_strictly_read_only_command(command: str) -> bool:
    if not command.strip() or _SHELL_CONTROL_RE.search(command) or _has_shell_indirection(command):
        return False
    tokens = _shell_tokens(command)
    if not tokens or any(token in _CONTROL_TOKENS for token in tokens):
        return False
    executable, args, wrappers = _unwrap_command(tokens)
    if wrappers & {"sudo", "nohup", "setsid"}:
        return False
    if executable == "rg":
        return not any(token == "--pre" or token.startswith("--pre=") for token in args)
    if executable == "git":
        subcommand, git_args, dynamic_config = _git_command(args)
        scope_override = any(
            token in _GIT_SCOPE_FLAGS
            or any(token.startswith(prefix + "=") for prefix in _GIT_SCOPE_FLAGS)
            for token in args
        )
        external_helper = any(token == "--exec-path" or token.startswith("--exec-path=") for token in args)
        return not scope_override and not external_helper and _git_is_read_only(subcommand, git_args, dynamic_config)
    if executable == "sed":
        return _sed_is_strictly_read_only(args)
    return executable in _READ_ONLY_COMMANDS

def _context(event_name: str, message: str, *, system_message: str | None = None) -> dict[str, Any]:
    output: dict[str, Any] = {
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "additionalContext": message,
        }
    }
    if system_message:
        output["systemMessage"] = system_message
    return output

def handle_user_prompt_submit(event: dict[str, Any]) -> dict[str, Any]:
    prompt = str(event.get("prompt") or "")
    cwd = str(event.get("cwd") or ".")
    if _secret_found(_scan_text(prompt, source="user_prompt")):
        return {
            "decision": "block",
            "reason": "Potential credential detected in the prompt. Redact it before sending.",
        }

    session_id = _session_id(event)
    turn_id = str(event.get("turn_id") or "")
    expand = _explicit_expand(prompt)
    nested = _nested_allowed(prompt)
    sensitive = _sensitive_context(prompt)
    disclosure_grant = _sensitive_disclosure_grant(prompt, turn_id)
    def mutate(state: dict[str, Any]) -> None:
        pending = state.get("pending_local_git")
        prior_grant = state.get("local_git_grant")
        if _git_transaction_resume_requested(prompt):
            grant = _continued_git_grant_from_prompt(
                prompt,
                cwd,
                session_id,
                turn_id,
                prior_grant if isinstance(prior_grant, dict) else None,
            )
        else:
            grant = _local_git_grant_from_prompt(
                prompt,
                cwd,
                turn_id,
                pending if isinstance(pending, dict) else None,
                session_id=session_id,
            )
        authorization_text = _git_authorization_text(prompt)
        transaction_scopes = _ordered_unique(
            _prompt_command_scopes(
                authorization_text,
                cwd,
                include_implicit_cwd=True,
            )
            + _prompt_absolute_paths(authorization_text)
        )
        transaction_targets = _prompt_github_targets(authorization_text)
        declared_clone_roots = tuple(
            candidate["destination"]
            for candidate in _prompt_clone_candidates(authorization_text, cwd)
        )
        transaction_intent_requires_grant = bool(
            transaction_targets
            and (
                len(transaction_scopes) > 1
                or len(transaction_targets) > 1
                or _prompt_has_unresolved_git_scope_override(
                    authorization_text,
                    cwd,
                )
            )
        )
        authorization_hashes = _dangerous_authorization_hashes(
            prompt,
            cwd,
            tuple(
                _ordered_unique(
                    [*_tracked_clone_roots(state), *declared_clone_roots]
                )
            ),
            skip_scoped_candidates=(
                grant is not None or transaction_intent_requires_grant
            ),
        )
        state["current_turn_id"] = turn_id
        state["explicit_expand"] = expand
        state["nested_allowed"] = nested
        state["sensitive_context"] = sensitive or bool(state.get("sensitive_context"))
        state["sensitive_disclosure_grant"] = disclosure_grant
        state["dangerous_authorizations"] = sorted(authorization_hashes)
        state["dangerous_authorization_hashes"] = authorization_hashes
        state["pending_permission_authorizations"] = {}
        state["local_git_grant"] = grant
        if grant is not None:
            state["pending_local_git"] = None
        elif _AUTHORIZATION_REVOCATION_RE.search(prompt) or _AUTH_NEGATED_RE.search(
            authorization_text
        ) or (
            isinstance(pending, dict)
            and (
                not _pending_git_usable(pending)
                or not _PENDING_COMMAND_REFERENCE_RE.search(prompt)
            )
        ):
            state["pending_local_git"] = None

    state_store.mutate_session(session_id, mutate)

    if sensitive:
        return _context(
            "UserPromptSubmit",
            "Configured sensitive-business context is present. Keep concrete values local; "
            "aggregate or redact before durable or external use.",
        )
    return {}
