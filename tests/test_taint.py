"""Taint analysis of tool handlers (source/taint_*.py): injection, not capability.

A tool argument spliced into a command, query or URL host, or joined to a base directory without
a containment check, is reported; the argument used whole (a shell tool running `command`) is the
tool's purpose and isn't.
"""

import pytest

from mcpiranha.core.models import SourceHit
from mcpiranha.source import taint_javascript as tjs
from mcpiranha.source import taint_python as tpy


def _py(body: str, decorator: str = "@server.tool()") -> list[SourceHit]:
    code = f"{decorator}\ndef handler(arg, ctx=None):\n" + "".join(
        f"    {line}\n" for line in body.splitlines()
    )
    return tpy.analyze("server.py", "import os, subprocess\n" + code)


def _kinds(hits: list[SourceHit]) -> set[str]:
    return {h.kind for h in hits}


@pytest.mark.parametrize(
    ("body", "kind"),
    [
        ('subprocess.run(f"git log {arg}", shell=True)', "shell_injection"),
        ('os.system("git checkout " + arg)', "shell_injection"),
        ('cmd = "tar -xf %s" % arg\nsubprocess.check_output(cmd, shell=True)', "shell_injection"),
        ('subprocess.run(["sh", "-c", f"ls {arg}"])', "shell_injection"),
        ('subprocess.getoutput("ping -c 1 {}".format(arg))', "shell_injection"),
        ("db.execute(f\"SELECT * FROM t WHERE name = '{arg}'\")", "sql_injection"),
        ('cur.execute("DELETE FROM t WHERE id = " + arg)', "sql_injection"),
        ("open(os.path.join(ROOT, arg)).read()", "path_traversal"),
        ("(ROOT / arg).read_text()", "path_traversal"),
        ("p = os.path.join(BASE, arg)\nos.remove(p)", "path_traversal"),
        ('requests.get(f"http://{arg}/status")', "ssrf"),
        ('urllib.request.urlopen("https://" + arg + "/x")', "ssrf"),
    ],
)
def test_python_injection(body: str, kind: str) -> None:
    assert kind in _kinds(_py(body))


@pytest.mark.parametrize(
    "body",
    [
        'subprocess.run(["git", "log", arg])',  # no shell
        'subprocess.run(f"git log {shlex.quote(arg)}", shell=True)',  # quoted
        "subprocess.run(arg, shell=True)",  # a shell tool: capability, not injection
        'db.execute("SELECT * FROM t WHERE name = ?", (arg,))',  # parameterized
        "db.execute(arg)",  # a SQL tool
        "open(arg).read()",  # a file tool
        "p = (ROOT / arg).resolve()\nif not p.is_relative_to(ROOT): raise ValueError\n"
        "p.read_text()",
        'requests.get(f"https://api.example.invalid/v1/{arg}")',  # input in the path only
        "requests.get(arg)",  # a fetch tool
        'subprocess.run(f"ls {int(arg)}", shell=True)',  # cast
        "name = os.path.basename(arg)\n"
        'if name not in {"daily.txt", "weekly.txt"}: raise ValueError()\n'
        "open(os.path.join(ROOT, name))",  # basename needs a real filename restriction
    ],
)
def test_python_not_injection(body: str) -> None:
    assert _py(body) == []


def test_python_needs_a_tool_handler() -> None:
    code = 'import os\ndef helper(arg):\n    os.system("git checkout " + arg)\n'
    assert tpy.analyze("m.py", code) == []  # not reachable from a tool


def test_python_follows_helpers_and_low_level_handlers() -> None:
    code = (
        "import os\n"
        "def run(b):\n    os.system('git checkout ' + b)\n"
        "@server.tool()\ndef checkout(branch):\n    run(branch)\n"
        "@server.call_tool()\nasync def call(name, arguments):\n"
        "    subprocess.run(f\"ls {arguments['dir']}\", shell=True)\n"
    )
    hits = tpy.analyze("m.py", code)
    assert [(h.kind, h.line) for h in hits] == [("shell_injection", 3), ("shell_injection", 9)]
    assert "argument dir" in hits[1].detail and "tool checkout" in hits[0].detail


def test_python_add_tool_registration() -> None:
    code = "def grep(pattern):\n    os.system('grep ' + pattern)\nserver.add_tool(grep)\n"
    assert _kinds(tpy.analyze("m.py", code)) == {"shell_injection"}


def _js(handler: str) -> set[str]:
    code = f'server.tool("t", {{}}, async ({{ arg }}) => {{ {handler} }});'
    return _kinds(tjs.analyze("index.ts", code.encode()))


@pytest.mark.parametrize(
    ("handler", "kind"),
    [
        ("execSync(`git log ${arg}`);", "shell_injection"),
        ('exec("git checkout " + arg);', "shell_injection"),
        ('spawn("sh", ["-c", `ls ${arg}`]);', "shell_injection"),
        ("spawn(`ls ${arg}`, { shell: true });", "shell_injection"),
        ("db.query(`SELECT * FROM t WHERE name = '${arg}'`);", "sql_injection"),
        ('prisma.$queryRawUnsafe("SELECT * FROM t WHERE id = " + arg);', "sql_injection"),
        ("const f = path.join(ROOT, arg); return fs.readFileSync(f);", "path_traversal"),
        ("fetch(`http://${arg}/status`);", "ssrf"),
        ('axios.get("https://" + arg + "/x");', "ssrf"),
    ],
)
def test_javascript_injection(handler: str, kind: str) -> None:
    assert kind in _js(handler)


@pytest.mark.parametrize(
    "handler",
    [
        'execFile("git", ["log", arg]);',
        "execSync(`git log ${shellQuote(arg)}`);",
        "exec(arg);",
        'db.query("SELECT * FROM t WHERE name = $1", [arg]);',
        "db.query(arg);",
        "fs.readFileSync(arg);",
        "const base = path.resolve(ROOT); const f = path.resolve(ROOT, arg); "
        "if (!f.startsWith(base + path.sep)) throw 1; fs.readFileSync(f);",
        "fetch(`https://api.example.invalid/v1/${arg}`);",
        "fetch(arg);",
        "execSync(`echo ${Number(arg)}`);",
    ],
)
def test_javascript_not_injection(handler: str) -> None:
    assert _js(handler) == set()


def test_javascript_handler_shapes() -> None:
    code = b"""
function checkout(b) { exec("git checkout " + b); }
server.registerTool("a", {}, async (args) => exec(`ls ${args.dir}`));
server.tool("b", {}, async ({ branch }) => { checkout(branch); });
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  exec(`cat ${request.params.arguments.file}`);
});
mcp.addTool({ name: "c", execute: async (input) => { exec("ping " + input.host); } });
"""
    hits = tjs.analyze("index.js", code)
    details = sorted(h.detail.split(":")[0] + " " + h.detail.split("argument ")[1].split()[0]
                     for h in hits)  # fmt: skip
    assert details == ["tool a dir", "tool b branch", "tool c host", "tool call_tool file"]


def test_containment_in_a_caller_covers_the_helper() -> None:
    # loki-mode: the tool rejects separators, a helper opens the file (calibration)
    code = (
        "import os\n"
        "def read_events(path):\n    return open(path).read()\n"
        "@server.tool()\ndef status(run_id):\n"
        "    if '/' in run_id or '\\\\' in run_id or run_id.startswith('.'):\n"
        "        return 'invalid'\n"
        "    return read_events(os.path.join(RUNS, run_id, 'events.jsonl'))\n"
    )
    assert tpy.analyze("m.py", code) == []
    unchecked = code.replace(
        "    if '/' in run_id or '\\\\' in run_id or run_id.startswith('.'):\n"
        "        return 'invalid'\n",
        "",
    )
    assert _kinds(tpy.analyze("m.py", unchecked)) == {"path_traversal"}


def test_package_wide_flows_and_exec_aliases() -> None:
    # mcp-server-kubernetes < 2.5.0 / ios-simulator-mcp < 1.3.3 shapes (CVE-2025-53355, -52573)
    index = b"""
import { kubectlGet } from "./tools/kubectl-get.js";
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const input = request.params.arguments;
  return kubectlGet(manager, input);
});
"""
    tool = b"""
export async function kubectlGet(manager, input) {
  let command = "kubectl get";
  command += " " + input.resourceType;
  return execSync(command);
}
"""
    sim = b"""
const execAsync = (0, util_1.promisify)(child_process_1.exec);
server.tool("ui_type", "Type", {}, async ({ text }) => execAsync(`idb ui text ${text}`));
"""
    hits = tjs.analyze_package([("index.js", index), ("tools/kubectl-get.js", tool),
                                ("sim.js", sim)])  # fmt: skip
    assert sorted((h.file, h.kind) for h in hits) == [
        ("sim.js", "shell_injection"),
        ("tools/kubectl-get.js", "shell_injection"),
    ]
