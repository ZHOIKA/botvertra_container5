# BotVertra Container 5

Quinto container VertraCloud, com 40 bots lógicos em um único shared worker e bridge WebSocket concorrente.

Variáveis na VertraCloud:

- `CONTROLLER_URL=wss://botvertra-controller.onrender.com/ws/agent`
- `CONTROLLER_TOKEN=<mesmo token do controller Render>`
- `CONTAINER_NAME=container5`
- `BOT_COUNT_TARGET=40`

Start:

```bash
python3 start.py
```

Inclui Tor local compartilhado, isolamento de rota por bot, auditoria de IP, rotação de rota, escrita atômica das respostas locais e os comandos remotos permitidos pelo controller.
