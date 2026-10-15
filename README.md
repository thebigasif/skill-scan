# skill-scan

Check a Claude or agent skill before you install it.

A skill is a folder of instructions and scripts your agent follows with your permissions. `skill-scan` reads every text file in it and flags what hides in text:

- invisible Unicode tag characters (text the agent reads but you can't see)
- decoded payloads that get executed (`base64 -d | sh`, `eval(atob(...))`)
- remote scripts piped to a shell (`curl ... | bash`)
- reads of SSH keys, cloud credentials and package tokens
- data posted to request bins, webhooks and tunnels
- lines like "ignore previous instructions" or "without telling the user"
- `rm -rf ~`, disk wipes, edits to shell startup files and cron

Every finding shows the file, the line and why it matters. A finding is a reason to read that line, not a verdict on the author.

## Use

```bash
npx github:thebigasif/skill-scan ./my-skill          # one skill
npx github:thebigasif/skill-scan ~/.claude/skills     # every skill under a folder
npx github:thebigasif/skill-scan ./my-skill --json    # for CI
```

Exit code is 1 when any skill grades F, so it works as a CI gate. No dependencies, Node 18+.

## Grades

Each skill starts at 100. A critical finding is an F. High findings cost 30, medium 10, a missing or malformed `name`/`description` 3. A 90+, B 75+, C 60+, D 40+.

## Already graded

The same rules run on every public skill we can find on GitHub, more than 5,000 so far, re-checked whenever a skill changes: **[mcp.market/skills](https://mcp.market/skills)**. Anthropic's official set: [mcp.market/skills/by/anthropics](https://mcp.market/skills/by/anthropics).

For MCP servers, every server in the official registry is graded at [mcp.market](https://mcp.market). Live numbers: [mcp.market/mcp-security](https://mcp.market/mcp-security).

## License

MIT
