"""Live events over WebSocket. Officials receive investigation events; citizens receive only public events and
notifications addressed to them."""
import json
import time

from fastapi import WebSocket

from raqeeb import auth


class Hub:
    def __init__(self):
        self.clients: dict[WebSocket, dict | None] = {}

    async def join(self, ws: WebSocket, token: str | None):
        await ws.accept()
        self.clients[ws] = auth.user_for_token(token)

    def leave(self, ws: WebSocket):
        self.clients.pop(ws, None)

    async def send(self, event: str, data: dict, audience: str | int = "officials"):
        """audience: 'all' (public events), 'officials', or a user id."""
        msg = json.dumps({"event": event, "data": data, "ts": time.time()}, ensure_ascii=False, default=str)
        dead = []
        for ws, user in list(self.clients.items()):
            official = bool(user and user["role"] in auth.OFFICIAL_ROLES)
            if audience == "officials" and not official:
                continue
            if isinstance(audience, int) and not (user and user["id"] == audience):
                continue
            try:
                await ws.send_text(msg)
            except Exception:  # noqa: BLE001
                dead.append(ws)
        for ws in dead:
            self.leave(ws)


hub = Hub()
