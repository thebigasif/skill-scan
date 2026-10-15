// Rules and grading: the same code mcp.market runs on every public skill (https://mcp.market/skills).

/** The YAML frontmatter fields a skill needs (name, description), and the markdown after it. */
export function parseSkillMd(md) {
  const m = /^\u{FEFF}?---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/u.exec(md);
  if (!m) return { name: null, description: null, body: md };
  const fields = {};
  const lines = m[1].split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const kv = /^([A-Za-z_][\w-]*):\s*(.*)$/.exec(lines[i]);
    if (!kv) continue;
    let v = kv[2].trim();
    // Folded or literal block (description: > / |): the indented lines that follow.
    if (/^[>|][-+]?$/.test(v)) {
      const block = [];
      while (i + 1 < lines.length && /^\s+\S/.test(lines[i + 1])) block.push(lines[++i].trim());
      v = block.join(v.startsWith(">") ? " " : "\n");
    }
    fields[kv[1].toLowerCase()] = v.replace(/^(["'])([\s\S]*)\1$/, "$2").trim();
  }
  return { name: fields.name || null, description: fields.description || null, body: m[2] };
}

const INVISIBLE = /[\u{E0000}-\u{E007F}]/u;
const HIDDEN = /[\u{200B}-\u{200D}\u{2060}-\u{2064}\u{202A}-\u{202E}\u{2066}-\u{2069}]/u;

/** Line rules. `scripts: true` limits a rule to code files, where a phrase is an action rather than prose. */
export const SKILL_RULES = [
  { id: "remote-exec", severity: "high", note: "Downloads a script and runs it in one step, so what runs is whatever that server sends that day. Common for installers, and still worth a look at the address.",
    test: /\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(iex|Invoke-Expression)\b[^\n]*\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b|\beval\s+"?\$\((curl|wget)\b/i },
  { id: "decode-exec", severity: "critical", note: "Decodes hidden content and executes it: the real instructions are not readable in the file.",
    test: /(base64\s+(-d|--decode)|b64decode|atob\(|Buffer\.from\([^)]*['"]base64['"]\))[^\n]*(\|\s*(ba)?sh\b|\bexec\b|\beval\b|\bFunction\()|\b(exec|eval)\s*\([^)]*(b64decode|atob|base64)/i },
  { id: "secret-read", severity: "high", note: "Reads credential files (SSH keys, cloud or package-manager tokens) that a skill has no normal reason to touch.",
    test: /(~|\$HOME|\/root|\/home\/\w+)\/\.(ssh\/(id_\w+|authorized_keys)|aws\/credentials|config\/gcloud|kube\/config|docker\/config\.json|npmrc|pypirc|netrc|git-credentials)\b|\/etc\/(shadow|passwd)\b/i, scripts: true },
  { id: "exfil-endpoint", severity: "high", note: "Sends data to a throwaway collection endpoint (request bins, webhooks, tunnels).",
    test: /https?:\/\/[^\s'"]*(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|interact\.sh|oast\.(fun|pro|live)|burpcollaborator|discord(app)?\.com\/api\/webhooks|hooks\.slack\.com\/services)/i },
  { id: "env-exfil", severity: "high", note: "Collects environment variables or secrets and posts them over the network.",
    test: /\b(printenv|env|set)\b\s*\|\s*(curl|wget|nc)\b|\b(curl|wget)\b[^\n]*(-d|--data(-binary|-raw)?|-F|--upload-file)\s*[^\n]*(\$\(?(printenv|env)\b|@?~?\/?\.env\b|@\/etc\/|id_rsa)|os\.environ[^\n]*(requests\.(post|put)|urlopen)|process\.env[^\n]*fetch\([^)]*method:\s*['"]POST/i },
  { id: "override-instructions", severity: "high", note: "Tells the agent to set aside its instructions, hide what it does from the user, or switch off safety checks.",
    test: /\b(ignore|disregard|forget|override)\b[^.\n]{0,30}\b(all\s+)?(previous|prior|above|earlier|system|your)\s+(instructions|prompts?|rules|guidelines)\b|\b(do\s+not|don'?t|never)\s+(tell|inform|mention\s+(this\s+)?to|reveal\s+(this\s+)?to|show)\s+the\s+user\b|\bwithout\s+(telling|informing|asking|notifying)\s+the\s+user\b|\b(disable|bypass|turn\s+off|skip)\s+(all\s+)?(safety|security)\s+(checks|guardrails|filters|measures|warnings)\b/i },
  { id: "destructive", severity: "high", note: "Deletes the home or root directory, or wipes a disk.",
    test: /\brm\s+-(rf|fr|r\s+-f|f\s+-r)\s+(--no-preserve-root\s+)?("?(\/|~|\$HOME)"?\/?\*?)(\s|$|;|")|\bmkfs(\.\w+)?\s+\/dev\/|\bdd\s+if=\/dev\/(zero|random|urandom)\s+of=\/dev\/[sh]d/i, scripts: true },
  { id: "download-binary", severity: "medium", note: "Downloads a file and makes it executable: a binary nobody here can read.",
    test: /\b(curl|wget)\b[^\n]*(-o|-O|--output)\s*[^\n]*(&&|;)\s*chmod\s+(\+x|[0-7]?7[0-7][0-7])\b/i },
  { id: "obfuscated-blob", severity: "medium", note: "A long encoded blob (base64 or escaped hex) that cannot be read as it stands.",
    test: /[A-Za-z0-9+/]{400,}={0,2}|(\\x[0-9a-fA-F]{2}){40,}/ },
  { id: "persistence", severity: "medium", note: "Edits shell startup files, cron or launch agents, so something runs again after the skill is done.",
    test: /(>>?|tee\s+-a)\s*~?\/?[^\s]*\.(bashrc|zshrc|bash_profile|profile)\b|\bcrontab\s+-[^l\s]*\s|\bLaunchAgents\/[^\s]+\.plist|\bsystemctl\s+(--user\s+)?enable\b/i, scripts: true },
];

const SCRIPT_EXT = /\.(sh|bash|zsh|py|js|mjs|cjs|ts|rb|pl|ps1|php|go|rs)$/i;

/** Findings for one file. The line kept is trimmed and capped, so a finding never reprints a whole file. */
export function scanSkillFile(path, text) {
  const out = [];
  const script = SCRIPT_EXT.test(path) || /^#!/.test(text);
  const lines = text.split(/\r?\n/);
  const seen = new Set();
  const add = (f) => { const k = `${f.rule}:${f.file}`; if (seen.has(k)) return; seen.add(k); out.push(f); };
  lines.forEach((line, i) => {
    if (INVISIBLE.test(line)) add({ rule: "invisible-text", severity: "critical", file: path, line: i + 1, text: visible(line), note: "Contains Unicode tag characters: text the agent reads but a person looking at the file cannot see." });
    else if (HIDDEN.test(line)) add({ rule: "hidden-characters", severity: "medium", file: path, line: i + 1, text: visible(line), note: "Contains zero-width or text-direction characters, which can make a line read differently from what it does." });
    for (const r of SKILL_RULES) {
      if (r.scripts && !script && !/^\s*(\$|>|sudo\s)/.test(line) && !inCodeFence(lines, i)) continue;
      if (r.test.test(line)) add({ rule: r.id, severity: r.severity, file: path, line: i + 1, text: visible(line), note: r.note });
    }
  });
  return out;
}

function inCodeFence(lines, i) {
  let open = false;
  for (let j = 0; j < i; j++) if (/^\s*(```|~~~)/.test(lines[j])) open = !open;
  return open;
}

/** The line as a reader should see it: invisible characters shown as codes, and at most 200 characters. */
function visible(line) {
  const shown = line.trim().replace(/[\u{E0000}-\u{E007F}\u{200B}-\u{200D}\u{2060}-\u{2064}\u{202A}-\u{202E}\u{2066}-\u{2069}]/gu, (c) => `<U+${c.codePointAt(0).toString(16).toUpperCase()}>`);
  return shown.length > 200 ? `${shown.slice(0, 197)}...` : shown;
}

const PENALTY = { critical: 60, high: 30, medium: 10, low: 3 };

/** Quality notes about the SKILL.md itself: the fields every agent needs to decide when to load the skill. */
export function metaFindings(meta, file = "SKILL.md") {
  const out = [];
  if (!meta.name || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(meta.name)) out.push({ rule: "name-format", severity: "low", file, line: 1, text: meta.name ?? "(missing)", note: "The name should be 1 to 64 lowercase letters, digits or hyphens." });
  if (!meta.description) out.push({ rule: "no-description", severity: "low", file, line: 1, text: "(missing)", note: "No description, so an agent cannot tell when to use the skill." });
  else if (meta.description.length > 1024) out.push({ rule: "long-description", severity: "low", file, line: 1, text: `${meta.description.length} characters`, note: "The description is over 1,024 characters, the limit agents read." });
  return out;
}

/** Score and grade from findings. Any critical finding is an F whatever else is true. */
export function gradeSkill(findings) {
  const score = Math.max(0, 100 - findings.reduce((s, f) => s + PENALTY[f.severity], 0));
  if (findings.some((f) => f.severity === "critical")) return { score: Math.min(score, 30), grade: "F" };
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";
  return { score, grade };
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

/** Scan a whole skill folder: every file's findings plus the SKILL.md quality notes, worst first. */
export function scanSkill(files, skillMd) {
  const meta = parseSkillMd(skillMd);
  const findings = [...files.flatMap((f) => scanSkillFile(f.path, f.text)), ...metaFindings(meta)]
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return { findings, ...gradeSkill(findings), meta };
}
