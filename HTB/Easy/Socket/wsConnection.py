#!/usr/bin/env python3

import json
from websocket import create_connection

ws_server = "ws://qreader.htb:5789/version"
def send_ws():
	ws = create_connection(ws_server)
	message = "\'"
	data = '{"version":"\\ d"}'
	data = '{"version":"%s"}' % message

	ws.send(data)
	resp = ws.recv()
	ws.close()

	if resp:
		return resp
	else:
		return ''

print(send_ws())
