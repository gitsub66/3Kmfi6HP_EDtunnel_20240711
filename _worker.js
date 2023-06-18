// ../node_modules/uuid/dist/esm-browser/regex.js
var regex_default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;

// ../node_modules/uuid/dist/esm-browser/validate.js
function validate(uuid) {
	return typeof uuid === "string" && regex_default.test(uuid);
}
var validate_default = validate;

// ../node_modules/uuid/dist/esm-browser/stringify.js
var byteToHex = [];
for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}
function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}
function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!validate_default(uuid)) {
		throw TypeError("Stringified UUID is invalid");
	}
	return uuid;
}
var stringify_default = stringify;

// vless-js/lib/vless-js.ts
var WS_READY_STATE_OPEN = 1;
function makeReadableWebSocketStream(ws, earlyDataHeader, log) {
	let readableStreamCancel = false;
	return new ReadableStream({
		start(controller) {
			ws.addEventListener("message", async (e) => {
				if (readableStreamCancel) {
					return;
				}
				const vlessBuffer = e.data;
				controller.enqueue(vlessBuffer);
			});
			ws.addEventListener("error", (e) => {
				log("socket has error");
				readableStreamCancel = true;
				controller.error(e);
			});
			ws.addEventListener("close", () => {
				try {
					log("webSocket is close");
					if (readableStreamCancel) {
						return;
					}
					controller.close();
				} catch (error2) {
					log(`websocketStream can't close DUE to `, error2);
				}
			});
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				log(`earlyDataHeader has invaild base64`);
				safeCloseWebSocket(ws);
				return;
			}
			if (earlyData) {
				controller.enqueue(earlyData);
			}
		},
		pull(controller) {
		},
		cancel(reason) {
			log(`websocketStream is cancel DUE to `, reason);
			if (readableStreamCancel) {
				return;
			}
			readableStreamCancel = true;
			safeCloseWebSocket(ws);
		}
	});
}
function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { error: null };
	}
	try {
		base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { error };
	}
}
function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN) {
			socket.close();
		}
	} catch (error) {
		console.error("safeCloseWebSocket error", error);
	}
}
function processVlessHeader(vlessBuffer, userID) {
	if (vlessBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: "invalid data"
		};
	}
	const version = new Uint8Array(vlessBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	if (stringify_default(new Uint8Array(vlessBuffer.slice(1, 17))) === userID) {
		isValidUser = true;
	}
	if (!isValidUser) {
		return {
			hasError: true,
			message: "invalid user"
		};
	}
	const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
	const command = new Uint8Array(
		vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];
	if (command === 1) {
	} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
	const portRemote = new DataView(portBuffer).getInt16(0);
	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		vlessBuffer.slice(addressIndex, addressIndex + 1)
	);
	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = "";
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join(".");
			break;
		case 2:
			addressLength = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(":");
			break;
		default:
			console.log(`invild  addressType is ${addressType}`);
	}
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`
		};
	}
	return {
		hasError: false,
		addressType,
		addressRemote: addressValue,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		vlessVersion: version,
		isUDP
	};
}

// index.ts
import { connect } from "cloudflare:sockets";

// dns.ts
var doh = "https://security.cloudflare-dns.com/dns-query";
var contype = "application/dns-json";
var dns = async (domain, type) => {
	const response = await fetch(`${doh}?name=${domain}&type=${type}&ct=application/dns-json`, {
		method: "GET",
		headers: {
			"Accept": contype
		}
	});
	const data = await response.json();
	return data?.Answer?.[0]?.data;
};
var isCloudFlareIP = (ip) => {
	const CFIP = [
		[1729491968, 22],
		[1729546240, 22],
		[1730085888, 22],
		[1745879040, 13],
		[1746403328, 14],
		[1822605312, 18],
		[2197833728, 22],
		[2372222976, 18],
		[2728263680, 15],
		[2889875456, 13],
		[2918526976, 20],
		[3161612288, 20],
		[3193827328, 20],
		[3320508416, 22],
		[3324608512, 17]
	];
	const isIp4InCidr = (ip2) => (cidr) => {
		const ip4ToInt = (ip3) => ip3.split(".").reduce((sum, part) => (sum << 8) + parseInt(part, 10), 0) >>> 0;
		const [range, bits] = cidr;
		const mask = ~(2 ** (32 - bits) - 1);
		return (ip4ToInt(ip2) & mask) === (range & mask);
	};
	return CFIP.some((cidr) => isIp4InCidr(ip)(cidr));
};

// index.ts
var HTML404 = "404";
function delay2(ms) {
	return new Promise((resolve, rej) => {
		setTimeout(resolve, ms);
	});
}
var workers_default = {
	async fetch(request, env, ctx) {
		let address = "";
		let portWithRandomLog = "";
		const userID = env.UUID || "7f14e42a-f453-4c39-a762-019ee493237d";
		const log = (info, event) => {
			console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
		};
		const upgradeHeader = request.headers.get("Upgrade");
		if (!upgradeHeader || upgradeHeader !== "websocket") {
			return new Response(HTML404, {
				status: 404,
				headers: new Headers({ "Content-Type": "text/html" })
			});
		}
		const webSocketPair = new WebSocketPair();
		const [client, webSocket] = Object.values(webSocketPair);
		const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
		let remoteSocket = null;
		webSocket.accept();
		const readableWebSocketStream = makeReadableWebSocketStream(
			webSocket,
			earlyDataHeader,
			log
		);
		let vlessResponseHeader = new Uint8Array([0, 0]);
		let remoteConnectionReadyResolve;
		readableWebSocketStream.pipeTo(
			new WritableStream({
				async write(chunk, controller) {
					if (remoteSocket) {
						const writer2 = remoteSocket.writable.getWriter();
						await writer2.write(chunk);
						writer2.releaseLock();
						return;
					}
					const {
						hasError,
						message,
						portRemote,
						addressType,
						addressRemote,
						rawDataIndex,
						vlessVersion,
						isUDP,
						while: while2
					} = processVlessHeader(chunk, userID);
					address = addressRemote || "";
					portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "} `;
					if (isUDP && portRemote != 53) {
						controller.error("UDP proxy only enable for DNS which is port 53");
						webSocket.close();
						return;
					}
					if (hasError) {
						controller.error(message);
						webSocket.close();
						return;
					}
					vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
					const rawClientData = chunk.slice(rawDataIndex);
					let queryip = "";
					if (addressType === 2) {
						queryip = await dns(addressRemote, "A");
						while (queryip?.slice(-1) === ".") {
							queryip = await dns(queryip, "A");
						}
						if (queryip && isCloudFlareIP(queryip)) {
							// queryip = "edgetunnel.anycast.eu.org";
							queryip = "cdn-ips-test-global.xn--b6gac.eu.org";
						}
						console.log(
							`connected to domain: ${addressRemote} ip: ${queryip}`
						);
					}
					remoteSocket = connect({
						hostname: queryip ? queryip : addressRemote,
						port: portRemote
					});
					log(`connected`);
					const writer = remoteSocket.writable.getWriter();
					await writer.write(rawClientData);
					writer.releaseLock();
					remoteConnectionReadyResolve(remoteSocket);
				},
				close() {
					console.log(
						`[${address}:${portWithRandomLog}] readableWebSocketStream is close`
					);
				},
				abort(reason) {
					console.log(
						`[${address}:${portWithRandomLog}] readableWebSocketStream is abort`,
						JSON.stringify(reason)
					);
				}
			})
		);
		(async () => {
			await new Promise((resolve) => remoteConnectionReadyResolve = resolve);
			let count = 0;
			remoteSocket.readable.pipeTo(
				new WritableStream({
					start() {
						if (webSocket.readyState === WebSocket.READY_STATE_OPEN) {
							webSocket.send(vlessResponseHeader);
						}
					},
					async write(chunk, controller) {
						if (webSocket.readyState === WebSocket.READY_STATE_OPEN) {
							if (count++ > 2e4) {
								await delay2(1);
							}
							webSocket.send(chunk);
						} else {
							controller.error(
								"webSocket.readyState is not open, maybe close"
							);
						}
					},
					close() {
						console.log(
							`[${address}:${portWithRandomLog}] remoteConnection!.readable is close`
						);
					},
					abort(reason) {
						console.error(
							`[${address}:${portWithRandomLog}] remoteConnection!.readable abort`,
							reason
						);
					}
				})
			).catch((error) => {
				console.error(
					`[${address}:${portWithRandomLog}] processWebSocket has exception `,
					error.stack || error
				);
				safeCloseWebSocket2(webSocket);
			});
		})();
		return new Response(null, {
			status: 101,
			webSocket: client
		});
	}
};
function safeCloseWebSocket2(ws) {
	try {
		if (ws.readyState !== WebSocket.READY_STATE_CLOSED) {
			ws.close();
		}
	} catch (error) {
		console.error("safeCloseWebSocket error", error);
	}
}
export {
	workers_default as default
};
//# sourceMappingURL=index.js.map
