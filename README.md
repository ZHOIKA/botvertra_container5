# BotVertra Container 5

Quinto container VertraCloud, com 10 bots lógicos em um único shared worker e bridge WebSocket concorrente.

Variáveis na VertraCloud:

- `CONTROLLER_URL=wss://botvertra-controller.onrender.com/ws/agent`
- `CONTROLLER_TOKEN=<mesmo token do controller Render>`
- `CONTAINER_NAME=container5`
- `BOT_COUNT_TARGET=10`

Start:

```bash
python3 start.py
```

Inclui Tor local compartilhado, isolamento de rota por bot, auditoria de IP,
rotação de rota, escrita atômica das respostas locais e os comandos remotos
permitidos pelo controller.

Comandos: `ping`, `status`, `uptime`, `hostname`, `disk`, `memory`, `echo`,
`logs`, `internet`, `public_ip`, `exec`, `shell`.

O comando `exec` (ou `shell`) executa shell livre no bot — `ls -la`,
`curl -s ifconfig.me`, `ps aux` — herdando a rota de IP do bot (proxy/Tor).
Campos extras: `command_line`, `timeout` (default 30s, teto 300s), `cwd`,
`stdin`, `shell`. Implementado em `shell_exec.py`.

Observação: este container sobe 10 bots por padrão (`BOT_COUNT=10`); ajuste a
variável de ambiente `BOT_COUNT` para alterar.
