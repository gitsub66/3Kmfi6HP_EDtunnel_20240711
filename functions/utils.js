// @ts-nocheck

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
// [Linux] Run uuidgen in terminal

/** @type {import("./workers").GlobalConfig} */
export const globalConfig = {
	userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',

	/** Time to wait before an outbound Websocket connection is considered timeout, in ms. */
	openWSOutboundTimeout: 10000,

	/**
	 * Since Cloudflare Worker does not support UDP outbound, we may try DNS over TCP.
	 * Set to an empty string to disable UDP to TCP forwarding for DNS queries.
	 */
	dnsTCPServer: "8.8.4.4",

	/** The order controls where to send the traffic after the previous one fails. */
	outbounds: [
		{
			protocol: "freedom"	// Compulsory, outbound locally.
		}
	]
};

/**
 * If you use this file as an ES module, you should set all fields below.
 * @type {import("./workers").PlatformAPI}
 */
export const platformAPI = {
	// @ts-expect-error
	connect: null,

	// @ts-expect-error
	newWebSocket: null,

	associate: null,

	processor: null,
}

/**
 * Writes the first chunk of data to a writable stream.
 *
 * @param {WritableStream} writableStream - The writable stream to write to.
 * @param {Uint8Array} firstChunk - The first chunk of data to write.
 */
async function writeFirstChunk(writableStream, firstChunk) {
	const writer = writableStream.getWriter();
	await writer.write(firstChunk); // First write, normally is tls client hello
	writer.releaseLock();
}

/** 
 * Implementation map for different outbound protocols.
 * Key: protocol name, Value: function that returns an async outbound handler function.
 */
/** @type {Object.<string, (...args: any[]) => import('./workers').OutboundHandler>} */
const outboundImpl = {
	'freedom': () => async (vlessRequest, context) => {
		if (context.enforceUDP) {
			// TODO: Check what will happen if addressType == VlessAddrType.DomainName and that domain only resolves to a IPv6
			const udpClient = await /** @type {NonNullable<typeof platformAPI.associate>} */(platformAPI.associate)(vlessRequest.addressType == VlessAddrType.IPv6);
			const writableStream = makeWritableUDPStream(udpClient, vlessRequest.addressRemote, vlessRequest.portRemote, context.log);
			const readableStream = makeReadableUDPStream(udpClient, context.log);
			context.log(`Connected to UDP://${vlessRequest.addressRemote}:${vlessRequest.portRemote}`);
			await writeFirstChunk(writableStream, context.firstChunk);
			return {
				readableStream,
				writableStream: /** @type {WritableStream<Uint8Array>} */ (writableStream)
			};
		}

		let addressTCP = vlessRequest.addressRemote;
		if (context.forwardDNS) {
			addressTCP = globalConfig.dnsTCPServer;
			context.log(`Redirect DNS request sent to UDP://${vlessRequest.addressRemote}:${vlessRequest.portRemote}`);
		}

		const tcpSocket = await platformAPI.connect(addressTCP, vlessRequest.portRemote);
		tcpSocket.closed.catch(error => context.log('[freedom] tcpSocket closed with error: ', error.message));
		context.log(`Connecting to tcp://${addressTCP}:${vlessRequest.portRemote}`);
		await writeFirstChunk(tcpSocket.writable, context.firstChunk);
		return {
			readableStream: tcpSocket.readable,
			writableStream: tcpSocket.writable
		};
	},

	'forward': (/** @type {import('./workers').ForwardInstanceArgs} */ args) => async (vlessRequest, context) => {
		let portDest = vlessRequest.portRemote;
		if (typeof args.portMap === "object" && args.portMap[vlessRequest.portRemote] !== undefined) {
			portDest = args.portMap[vlessRequest.portRemote];
		}

		const tcpSocket = await platformAPI.connect(args.proxyServer, portDest);
		tcpSocket.closed.catch(error => context.log('[forward] tcpSocket closed with error: ', error.message));
		context.log(`Forwarding tcp://${vlessRequest.addressRemote}:${vlessRequest.portRemote} to ${args.proxyServer}:${portDest}`);
		await writeFirstChunk(tcpSocket.writable, context.firstChunk);
		return {
			readableStream: tcpSocket.readable,
			writableStream: tcpSocket.writable
		};
	},

	// TODO: known problem, if we send an unreachable request to a valid socks5 server, it will wait indefinitely
	// TODO: Add support for proxying UDP via socks5 on runtimes that support UDP outbound
	'socks': (/** @type {import('./workers').Socks5InstanceArgs} */ socks) => async (vlessRequest, context) => {
		const tcpSocket = await platformAPI.connect(socks.address, socks.port);
		tcpSocket.closed.catch(error => context.log('[socks] tcpSocket closed with error: ', error.message));
		context.log(`Connecting to ${vlessRequest.isUDP ? 'UDP' : 'TCP'}://${vlessRequest.addressRemote}:${vlessRequest.portRemote} via socks5 ${socks.address}:${socks.port}`);
		await socks5Connect(tcpSocket, socks.user, socks.pass, vlessRequest.addressType, vlessRequest.addressRemote, vlessRequest.portRemote, context.log);
		await writeFirstChunk(tcpSocket.writable, context.firstChunk);
		return {
			readableStream: tcpSocket.readable,
			writableStream: tcpSocket.writable
		};
	},

	/**
	 * Start streaming traffic to a remote vless server.
	 * The first message must contain the query header plus part of the payload!
	 * The vless server responds to it with a response header plus part of the response from the destination.
	 * After the first message exchange, in the case of TCP, the streams in both directions carry raw TCP streams.
	 * Fragmentation won't cause any problem after the first message exchange.
	 * In the case of UDP, a 16-bit big-endian length field is prepended to each UDP datagram and then send through the streams.
	 * The first message exchange still applies.
	 */
	'vless': (/** @type {import('./workers').VlessInstanceArgs} */ vless) => async (vlessRequest, context) => {
		checkVlessConfig(vless.address, vless.streamSettings);

		let wsURL = vless.streamSettings.security === 'tls' ? 'wss://' : 'ws://';
		wsURL = wsURL + vless.address + ':' + vless.port;
		if (vless.streamSettings.wsSettings && vless.streamSettings.wsSettings.path) {
			wsURL = wsURL + vless.streamSettings.wsSettings.path;
		}
		context.log(`Connecting to ${vlessRequest.isUDP ? 'UDP' : 'TCP'}://${vlessRequest.addressRemote}:${vlessRequest.portRemote} via vless ${wsURL}`);

		const wsToVlessServer = platformAPI.newWebSocket(wsURL);
		/** @type {Promise<void>} */
		const openPromise = new Promise((resolve, reject) => {
			wsToVlessServer.onopen = () => resolve();
			wsToVlessServer.onclose = (event) =>
				reject(new Error(`Closed with code ${event.code}, reason: ${event.reason}`));
			wsToVlessServer.onerror = (error) => reject(error);
			setTimeout(() => {
				reject(new Error("Cannot open Websocket connection, open connection timeout"));
			}, globalConfig.openWSOutboundTimeout);
		});

		// Wait for the connection to open
		try {
			await openPromise;
		} catch (err) {
			wsToVlessServer.close();
			throw new err;
		}

		/** @type {WritableStream<Uint8Array>} */
		const writableStream = new WritableStream({
			async write(chunk) {
				wsToVlessServer.send(chunk);
			},
			close() {
				context.log(`Vless Websocket closed`);
			},
			abort(reason) {
				console.error(`Vless Websocket aborted`, reason);
			},
		});

		/** @type {(firstChunk : Uint8Array) => Uint8Array} */
		const headerStripper = (firstChunk) => {
			if (firstChunk.length < 2) {
				throw new Error('Too short vless response');
			}

			const responseVersion = firstChunk[0];
			const addtionalBytes = firstChunk[1];

			if (responseVersion > 0) {
				context.log('Warning: unexpected vless version: ${responseVersion}, only supports 0.');
			}

			if (addtionalBytes > 0) {
				context.log('Warning: ignored ${addtionalBytes} byte(s) of additional information in the response.');
			}

			return firstChunk.slice(2 + addtionalBytes);
		};

		const readableStream = makeReadableWebSocketStream(wsToVlessServer, null, headerStripper, context.log);
		const vlessReqHeader = makeVlessReqHeader(vlessRequest.isUDP ? VlessCmd.UDP : VlessCmd.TCP, vlessRequest.addressType, vlessRequest.addressRemote, vlessRequest.portRemote, vless.uuid);
		// Send the first packet (header + rawClientData), then strip the response header with headerStripper
		await writeFirstChunk(writableStream, joinUint8Array(vlessReqHeader, context.firstChunk));
		return {
			readableStream,
			writableStream
		};
	}
};

/**
 * Retrieves the next outbound configuration based on the current position.
 *
 * @param {{index: number, serverIndex: number}} curPos - The current position object containing the index and serverIndex.
 * @returns {Object} - The next outbound configuration.
 */
function getOutbound(curPos) {
	if (curPos.index >= globalConfig.outbounds.length) {
		// End of the outbounds array, return null
		return null;
	}

	const outbound = globalConfig.outbounds[curPos.index];
	let serverCount = 0;

	let outboundHandlerArgs;
	switch (outbound.protocol) {
		case 'freedom':
			outboundHandlerArgs = undefined;
			break;

		case 'forward': {
			/** @type {import("./workers").ForwardOutbound} */
			// @ts-ignore: type casting
			const forwardOutbound = outbound;
			outboundHandlerArgs = /** @type {import("./workers").ForwardInstanceArgs} */ ({
				proxyServer: forwardOutbound.address,
				portMap: forwardOutbound.portMap,
			});
			break;
		}

		case 'socks': {
			/** @type {import("./workers").Socks5Outbound} */
			// @ts-ignore: type casting
			const socks5Outbound = outbound;
			const servers = socks5Outbound.settings.servers;
			serverCount = servers.length;

			const curServer = servers[curPos.serverIndex];

			outboundHandlerArgs = /** @type {import("./workers").Socks5InstanceArgs} */ ({
				address: curServer.address,
				port: curServer.port,
			});

			if (curServer.users && curServer.users.length > 0) {
				const firstUser = curServer.users[0];
				outboundHandlerArgs.user = firstUser.user;
				outboundHandlerArgs.pass = firstUser.pass;
			}
			break;
		}

		case 'vless': {
			/** @type {import("./workers").VlessWsOutbound} */
			// @ts-ignore: type casting
			const vlessOutbound = outbound;
			const servers = vlessOutbound.settings.vnext;
			serverCount = servers.length;

			const curServer = servers[curPos.serverIndex];
			outboundHandlerArgs = /** @type {import("./workers").VlessInstanceArgs} */ ({
				address: curServer.address,
				port: curServer.port,
				uuid: curServer.users[0].id,
				streamSettings: vlessOutbound.streamSettings,
			});
			break;
		}

		default:
			throw new Error(`Unknown outbound protocol: ${outbound.protocol}`);
	}

	curPos.serverIndex++;
	if (curPos.serverIndex >= serverCount) {
		// End of the vnext array, reset serverIndex and move to the next outbound
		curPos.serverIndex = 0;
		curPos.index++;
	}

	return {
		protocol: outbound.protocol,
		handler: outboundImpl[outbound.protocol](outboundHandlerArgs),
	};
}

/**
 * Checks if a given protocol supports UDP outbound.
 *
 * @param {string} protocolName - The name of the protocol.
 * @returns {boolean} - true if the protocol supports UDP outbound, false otherwise.
 */
function canOutboundUDPVia(protocolName) {
	switch (protocolName) {
		case 'freedom':
			return platformAPI.associate != null;
		case 'vless':
			return true;
	}
	return false;
}

export const cn_hostnames = [
	'weibo.com',                // Weibo - A popular social media platform
	'www.baidu.com',            // Baidu - The largest search engine in China
	'www.qq.com',               // QQ - A widely used instant messaging platform
	'www.taobao.com',           // Taobao - An e-commerce website owned by Alibaba Group
	'www.jd.com',               // JD.com - One of the largest online retailers in China
	'www.sina.com.cn',          // Sina - A Chinese online media company
	'www.sohu.com',             // Sohu - A Chinese internet service provider
	'www.tmall.com',            // Tmall - An online retail platform owned by Alibaba Group
	'www.163.com',              // NetEase Mail - One of the major email providers in China
	'www.zhihu.com',            // Zhihu - A popular question-and-answer website
	'www.youku.com',            // Youku - A Chinese video sharing platform
	'www.xinhuanet.com',        // Xinhua News Agency - Official news agency of China
	'www.douban.com',           // Douban - A Chinese social networking service
	'www.meituan.com',          // Meituan - A Chinese group buying website for local services
	'www.toutiao.com',          // Toutiao - A news and information content platform
	'www.ifeng.com',            // iFeng - A popular news website in China
	'www.autohome.com.cn',      // Autohome - A leading Chinese automobile online platform
	'www.360.cn',               // 360 - A Chinese internet security company
	'www.douyin.com',           // Douyin - A Chinese short video platform
	'www.kuaidi100.com',        // Kuaidi100 - A Chinese express delivery tracking service
	'www.wechat.com',           // WeChat - A popular messaging and social media app
	'www.csdn.net',             // CSDN - A Chinese technology community website
	'www.imgo.tv',              // ImgoTV - A Chinese live streaming platform
	'www.aliyun.com',           // Alibaba Cloud - A Chinese cloud computing company
	'www.eyny.com',             // Eyny - A Chinese multimedia resource-sharing website
	'www.mgtv.com',             // MGTV - A Chinese online video platform
	'www.xunlei.com',           // Xunlei - A Chinese download manager and torrent client
	'www.hao123.com',           // Hao123 - A Chinese web directory service
	'www.bilibili.com',         // Bilibili - A Chinese video sharing and streaming platform
	'www.youth.cn',             // Youth.cn - A China Youth Daily news portal
	'www.hupu.com',             // Hupu - A Chinese sports community and forum
	'www.youzu.com',            // Youzu Interactive - A Chinese game developer and publisher
	'www.panda.tv',             // Panda TV - A Chinese live streaming platform
	'www.tudou.com',            // Tudou - A Chinese video-sharing website
	'www.zol.com.cn',           // ZOL - A Chinese electronics and gadgets website
	'www.toutiao.io',           // Toutiao - A news and information app
	'www.tiktok.com',           // TikTok - A Chinese short-form video app
	'www.netease.com',          // NetEase - A Chinese internet technology company
	'www.cnki.net',             // CNKI - China National Knowledge Infrastructure, an information aggregator
	'www.zhibo8.cc',            // Zhibo8 - A website providing live sports streams
	'www.zhangzishi.cc',        // Zhangzishi - Personal website of Zhang Zishi, a public intellectual in China
	'www.xueqiu.com',           // Xueqiu - A Chinese online social platform for investors and traders
	'www.qqgongyi.com',         // QQ Gongyi - Tencent's charitable foundation platform
	'www.ximalaya.com',         // Ximalaya - A Chinese online audio platform
	'www.dianping.com',         // Dianping - A Chinese online platform for finding and reviewing local businesses
	'www.suning.com',           // Suning - A leading Chinese online retailer
	'www.zhaopin.com',          // Zhaopin - A Chinese job recruitment platform
	'www.jianshu.com',          // Jianshu - A Chinese online writing platform
	'www.mafengwo.cn',          // Mafengwo - A Chinese travel information sharing platform
	'www.51cto.com',            // 51CTO - A Chinese IT technical community website
	'www.qidian.com',           // Qidian - A Chinese web novel platform
	'www.ctrip.com',            // Ctrip - A Chinese travel services provider
	'www.pconline.com.cn',      // PConline - A Chinese technology news and review website
	'www.cnzz.com',             // CNZZ - A Chinese web analytics service provider
	'www.telegraph.co.uk',      // The Telegraph - A British newspaper website	
	'www.ynet.com',             // Ynet - A Chinese news portal
	'www.ted.com',              // TED - A platform for ideas worth spreading
	'www.renren.com',           // Renren - A Chinese social networking service
	'www.pptv.com',             // PPTV - A Chinese online video streaming platform
	'www.liepin.com',           // Liepin - A Chinese online recruitment website
	'www.881903.com',           // 881903 - A Hong Kong radio station website
	'www.aipai.com',            // Aipai - A Chinese online video sharing platform
	'www.ttpaihang.com',        // Ttpaihang - A Chinese celebrity popularity ranking website
	'www.quyaoya.com',          // Quyaoya - A Chinese online ticketing platform
	'www.91.com',               // 91.com - A Chinese software download website
	'www.dianyou.cn',           // Dianyou - A Chinese game information website
	'www.tmtpost.com',          // TMTPost - A Chinese technology media platform
	'www.douban.com',           // Douban - A Chinese social networking service
	'www.guancha.cn',           // Guancha - A Chinese news and commentary website
	'www.so.com',               // So.com - A Chinese search engine
	'www.58.com',               // 58.com - A Chinese classified advertising website
	'www.google.com',           // Google - A multinational technology company
	'www.cnblogs.com',          // Cnblogs - A Chinese technology blog community
	'www.cntv.cn',              // CCTV - China Central Television official website
	'www.secoo.com',            // Secoo - A Chinese luxury e-commerce platform
];
/**
 * Sets the configuration from the environment variables.
 *
 * @param {Object} env - The environment variables object.
 */
export function setConfigFromEnv(request, env) {
	// Parse the URL of the incoming request
	const url = new URL(request.url);
	const query = url.searchParams; // Get the query parameters from the URL

	// Get the VLESS URL, Proxy IP and SOCKS5 from query parameters or environment variables
	const vlessParam = decodeURIComponent(query.get('vless')) || env.VLESS;
	const proxyIPParam = decodeURIComponent(query.get('proxyip')) || env.PROXYIP || "cdn.xn--b6gac.eu.org";
	const socks5Param = decodeURIComponent(query.get('socks5')) || env.SOCKS5;

	globalConfig.userID = env.UUID || globalConfig.userID;

	globalConfig.outbounds = [
		{
			protocol: "freedom" // Compulsory, outbound locally.
		}
	];

	if (proxyIPParam) {
		/** @type {import("./workers").ForwardOutbound} */
		const forward = {
			protocol: "forward",
			address: proxyIPParam
		};

		globalConfig['outbounds'].push(forward);
	}

	if (socks5Param) {
		try {
			const {
				username,
				password,
				hostname,
				port,
			} = socks5AddressParser(socks5Param);

			/** @type {import("./workers").Socks5Server} */
			const socks = {
				"address": hostname,
				"port": port
			}

			if (typeof username !== 'undefined' && typeof password !== 'undefined') {
				socks.users = [
					{
						"user": username,
						"pass": password
					}
				]
			}

			// Add the SOCKS5 server to the outbounds array
			globalConfig['outbounds'].push({
				protocol: "socks",
				settings: {
					"servers": [socks]
				}
			});
		} catch (err) {
			console.log(err.toString()); // Log and handle any parsing errors
		}
	}

	if (vlessParam) {
		try {
			// Parse the VLESS URL into its components
			const {
				uuid,
				remoteHost,
				remotePort,
				queryParams
			} = parseVlessString(vlessParam);

			/** @type {import("./workers").VlessServer} */
			const vless = {
				"address": remoteHost,
				"port": remotePort,
				"users": [
					{
						"id": uuid
					}
				]
			};

			// TODO: Validate vless here
			/** @type {import("./workers").StreamSettings} */
			const streamSettings = {
				"network": queryParams['type'],
				"security": queryParams['security'],
			}

			if (queryParams['type'] == 'ws') {
				streamSettings.wsSettings = {
					"headers": {
						"Host": remoteHost
					},
					"path": decodeURIComponent(queryParams['path'])
				};
			}

			if (queryParams['security'] == 'tls') {
				streamSettings.tlsSettings = {
					"serverName": remoteHost,
					"allowInsecure": false
				};
			}

			/** @type {import("./workers").VlessWsOutbound} */
			const vlessOutbound = {
				protocol: "vless",
				settings: {
					"vnext": [vless]
				},
				streamSettings: streamSettings
			};

			globalConfig['outbounds'].push(vlessOutbound);
		} catch (err) {
			console.log(err.toString()); // Log and handle any parsing errors
		}
	}
}


// Cloudflare Workers entry
export default {
	/**
	 * @param {Request} request
	 * @param {{UUID: string, PROXYIP: string}} env
	 * @param {ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env) {
		if (env.LOGPOST) {
			redirectConsoleLog(env.LOGPOST, crypto.randomUUID());
		}

		try {
			setConfigFromEnv(env);
			const upgradeHeader = request.headers.get('Upgrade');

			// Check if the request is not a WebSocket upgrade request
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				const url = new URL(request.url);
				const userAgentRegex = /bot|robot|BOT|Bot/;
				// Handle different URL paths
				switch (url.pathname) {
					case '/cf':
						// Check if the request has a matching user-agent pattern
						if (!userAgentRegex.test(request.headers.get('User-Agent'))) {
							// Return a response with the Cloudflare information in JSON format
							return new Response(JSON.stringify(request.cf), { status: 200 });
						}
						// Return an error response with a forbidden status code
						return new Response('Access Forbidden', { status: 403 });
					case `/${globalConfig.userID}`:
						// Check if the request has a matching user-agent pattern
						if (!userAgentRegex.test(request.headers.get('User-Agent'))) {
							// Get VLESS config based on the Host header and return it as a response
							const vlessConfig = getVLESSConfig(request.headers.get('Host'));
							return new Response(`${vlessConfig}`, {
								status: 200,
								headers: {
									"Content-Type": "text/plain;charset=utf-8",
								}
							});
						}
						// Return an error response with a forbidden status code
						return new Response('Access Forbidden', { status: 403 });
					default:
						const randomHostname = cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
						const newHeaders = new Headers(request.headers);
						newHeaders.set('cf-connecting-ip', '1.2.3.4');
						newHeaders.set('x-forwarded-for', '1.2.3.4');
						newHeaders.set('x-real-ip', '1.2.3.4');
						newHeaders.set('referer', 'https://www.google.com/search?q=edtunnel');
						// Use fetch to proxy the request to 15 different domains
						const proxyUrl = 'https://' + randomHostname + url.pathname + url.search;
						let modifiedRequest = new Request(proxyUrl, {
							method: request.method,
							headers: newHeaders,
							body: request.body,
							redirect: 'manual',
						});
						const proxyResponse = await fetch(modifiedRequest, { redirect: 'manual' });
						// Check for 302 or 301 redirect status and return an error response
						if ([301, 302].includes(proxyResponse.status)) {
							return new Response(`Redirects to ${randomHostname} are not allowed.`, {
								status: 403,
								statusText: 'Forbidden',
							});
						}
						// Return the response from the proxy server
						return proxyResponse;
				}
			} else {
				/** 
				 * Accept WebSocket connection and handle VLESS over WebSocket.
				 * Returns a response with the appropriate status code and the client WebSocket.
				 */
				const webSocketPair = new WebSocketPair();
				const [client, webSocket] = Object.values(webSocketPair);

				// Accept the WebSocket connection
				webSocket.accept();

				// Get the value of the 'sec-websocket-protocol' header for early data
				const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

				// Handle VLESS over WebSocket and get the status code
				const statusCode = vlessOverWSHandler(webSocket, earlyDataHeader);

				// Return a response with the appropriate status code and the client WebSocket
				return new Response(null, {
					status: statusCode,
					webSocket: client,
				});
			}
		} catch (err) {
			let e = /** @type {Error} */ err;
			// If an error occurs during execution, return a response with the error message
			return new Response(e.toString());
		}
	},
};


/** @type {import("./workers").redirectConsoleLog} */
// This line denotes a type annotation indicating that this code is using the 'redirectConsoleLog' function from a separate module named './workers'.

export function redirectConsoleLog(logServer, instanceId) {
	// Define the 'redirectConsoleLog' function with two parameters: 'logServer' and 'instanceId'

	let logID = 0;
	// Initialize a variable 'logID' to keep track of the log message ID

	const oldConsoleLog = console.log;
	// Store the original 'console.log' function in a variable 'oldConsoleLog'

	console.log = async (data) => {
		// Override the 'console.log' function with an asynchronous function that takes 'data' as a parameter

		oldConsoleLog(data);
		// Call the original 'console.log' function with 'data'

		if (data == null) {
			return;
		}
		// If 'data' is null or undefined, return early and don't proceed further

		let msg;
		// Declare a variable 'msg' to store the formatted log message

		if (data instanceof Object) {
			msg = JSON.stringify(data);
		} else {
			msg = String(data);
		}
		// Check if 'data' is an object, stringify it using JSON.stringify, otherwise convert it to string using String()

		try {
			await fetch(logServer, {
				method: 'POST',
				headers: {
					'Content-Type': 'text/plain;charset=UTF-8',
					'X-Instance-ID': instanceId,
					'X-Log-ID': logID.toString()
				},
				body: msg
			});
			logID++; // Increment the logID after a successful request
		} catch (err) {
			oldConsoleLog(err.message);
		}
		// Send an HTTP POST request to 'logServer' with the log message in the request body.
		// Include 'instanceId' in the 'X-Instance-ID' header and 'logID' in the 'X-Log-ID' header.
		// If an error occurs during the fetch request, catch it and call 'oldConsoleLog' to log the error message.
	};
}
// End of the 'redirectConsoleLog' function definition

try {
	// Dynamically import the 'cloudflare:sockets' module
	const module = await import('cloudflare:sockets');

	// Override the 'connect' function of the 'platformAPI' object with an asynchronous function
	platformAPI.connect = async (address, port) => {
		// Call the 'connect' function from the imported module and return the result
		return module.connect({ hostname: address, port: port });
	};

	// Define a new function 'newWebSocket' in the 'platformAPI' object
	platformAPI.newWebSocket = (url) => new WebSocket(url);
} catch (error) {
	// If an error occurs during the import, log the message 'Not on Cloudflare Workers!'
	console.log('Not on Cloudflare Workers!');
}

/** @type {import('./workers').vlessOverWSHandler} */
// Type annotation indicating that this function is using the 'vlessOverWSHandler' type from a separate module named './workers'.
export function vlessOverWSHandler(webSocket, earlyDataHeader) {
	// Handler function that takes 'webSocket' and 'earlyDataHeader' as parameters

	let logPrefix = '';
	// Variable to store a log prefix

	/** @type {import('./workers').LogFunction} */
	// Type annotation indicating that the 'log' variable should have the type 'LogFunction'
	const log = (...args) => {
		console.log(`[${logPrefix}]`, args);
	};
	// Function to log messages with a specific log prefix

	// for ws 0rtt
	const earlyData = base64ToUint8Array(earlyDataHeader);
	// Convert 'earlyDataHeader' from base64 to Uint8Array
	if (!(earlyData instanceof Uint8Array)) {
		return 500;
	}
	// If 'earlyData' is not an instance of Uint8Array, return 500

	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyData, null, log);
	// Create a readable WebSocket stream using 'webSocket', 'earlyData', null fragmentation, and the 'log' function

	/** @type {null | (() => TransformStream<Uint8Array, Uint8Array>)} */
	// Type annotation indicating that the 'vlessResponseProcessor' variable can be null or a function returning a TransformStream
	let vlessResponseProcessor = null;
	let vlessTrafficData = readableWebSocketStream;
	if (platformAPI.processor != null) {
		// Check if 'platformAPI.processor' is not null
		const processor = platformAPI.processor(log);
		vlessResponseProcessor = processor.response;
		vlessTrafficData = readableWebSocketStream.pipeThrough(processor.request);
	}
	// If 'platformAPI.processor' is not null, create a processor and update 'vlessResponseProcessor' and 'vlessTrafficData'

	/** @type {import('./workers').ProcessedVlessHeader | null} */
	// Type annotation indicating that the 'vlessHeader' variable can be of type 'ProcessedVlessHeader' or null
	let vlessHeader = null;
	// Variable to store the processed Vless header

	// This source stream only contains raw traffic from the client
	// The vless header is stripped and parsed first.
	/** @type {TransformStream<Uint8Array, Uint8Array>} */
	// Type annotation for 'vlessHeaderProcessor', a TransformStream that transforms Uint8Arrays to Uint8Arrays
	const vlessHeaderProcessor = new TransformStream({
		start() {
		},
		transform(chunk, controller) {
			// Function called for each chunk of data in the stream
			if (vlessHeader) {
				// If 'vlessHeader' already exists, enqueue the chunk as it is
				controller.enqueue(chunk);
			} else {
				// If 'vlessHeader' doesn't exist, process the chunk as the Vless header
				try {
					vlessHeader = processVlessHeader(chunk, globalConfig.userID);
				} catch (error) {
					controller.error(`Failed to process Vless header: ${error}`);
					controller.terminate();
					return;
				}

				const randTag = Math.round(Math.random() * 1000000).toString(16).padStart(5, '0');
				logPrefix = `${vlessHeader.addressRemote}:${vlessHeader.portRemote} ${randTag} ${vlessHeader.isUDP ? 'UDP' : 'TCP'}`;
				// Set the log prefix based on the extracted Vless header information
				const firstPayloadLen = chunk.byteLength - vlessHeader.rawDataIndex;
				log(`First payload length = ${firstPayloadLen}`);
				if (firstPayloadLen > 0) {
					controller.enqueue(chunk.slice(vlessHeader.rawDataIndex));
				}
				// Enqueue the remaining data in the chunk if there is any
			}
		},
		flush() {
		}
	});
	// TransformStream to process the Vless header from the client traffic stream

	const fromClientTraffic = vlessTrafficData.pipeThrough(vlessHeaderProcessor);
	// Apply the vlessHeaderProcessor to the client traffic stream to obtain the transformed stream without the Vless header

	/** @type {WritableStream<Uint8Array> | null}*/
	// Type annotation indicating that 'remoteTrafficSink' can be either a WritableStream of Uint8Arrays or null
	let remoteTrafficSink = null;

	// ws --> remote
	fromClientTraffic.pipeTo(new WritableStream({
		async write(chunk) {
			// Function called for each chunk of data in the stream

			if (remoteTrafficSink) {
				// If 'remoteTrafficSink' exists, send the chunk to the remote destination
				const writer = remoteTrafficSink.getWriter();
				await writer.ready;
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const header = /** @type {NonNullable<import("./workers").ProcessedVlessHeader>} */(vlessHeader);

			// ["version", "length of additional info"]
			const vlessResponseHeader = new Uint8Array([header.vlessVersion[0], 0]);

			// Need to ensure the outbound proxy (if any) is ready before proceeding.
			remoteTrafficSink = await handleOutBound(header, chunk, webSocket, vlessResponseHeader, vlessResponseProcessor, log);
			// Establish an outbound connection and assign the result to 'remoteTrafficSink'
		},
		close() {
			log(`readableWebSocketStream has been closed`);
		},
		abort(reason) {
			log(`readableWebSocketStream aborts`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream pipeTo error', err);
	});
	// Pipe the transformed client traffic stream to the remote destination via a WritableStream
	return 101;
}
/**
 * Handles outbound connections.
 * @param {import("./workers").ProcessedVlessHeader} vlessRequest - The processed Vless header containing information about the request.
 * @param {Uint8Array} rawClientData - The raw client data to write.
 * @param {WebSocket} webSocket - The WebSocket to pass the remote socket to.
 * @param {Uint8Array} vlessResponseHeader - Contains information to produce the Vless response, such as the header.
 * @param {null | (() => TransformStream<Uint8Array, Uint8Array>)} vlessResponseProcessor - An optional TransformStream to process the Vless response.
 * @param {import('./workers').LogFunction} log - The logger function.
 * @returns {Promise<WritableStream<Uint8Array> | null>} - A non-null fulfill indicates the success connection to the destination or the remote proxy server.
 */
async function handleOutBound(vlessRequest, rawClientData, webSocket, vlessResponseHeader, vlessResponseProcessor, log) {
	// Function that handles outbound connections

	const curOutBoundPtr = { index: 0, serverIndex: 0 };
	// Pointer object to keep track of the current outbound index and server index

	const forwardDNS = vlessRequest.isUDP && (vlessRequest.portRemote == 53) && (globalConfig.dnsTCPServer ? true : false);
	// Indicates if UDP DNS requests should be forwarded to a designated TCP DNS server

	const enforceUDP = vlessRequest.isUDP && !forwardDNS;
	// Indicates whether UDP should be enforced for the outbound connection

	async function connectAndWrite() {
		// Function to connect and write to an outbound server

		const outbound = getOutbound(curOutBoundPtr);
		// Get the outbound server based on the current outbound index and server index
		if (outbound == null) {
			log('Reached end of the outbound chain');
			return null;
		} else {
			log(`Trying outbound ${curOutBoundPtr.index}:${curOutBoundPtr.serverIndex}`);
		}

		if (enforceUDP && !canOutboundUDPVia(outbound.protocol)) {
			// If UDP is enforced but the outbound server doesn't support UDP, return null
			return null;
		}

		try {
			return await outbound.handler(vlessRequest, {
				enforceUDP,
				forwardDNS,
				log,
				firstChunk: rawClientData,
			});
			// Call the handler function for the outbound server and pass the necessary parameters
		} catch (error) {
			// If there is an error while connecting, log the error message and return null
			log(`Outbound ${outbound.protocol} failed with:`, error.message);
			return null;
		}
	}

	let destRWPair = null;
	// Variable to store the destination ReadableWritablePair

	while (curOutBoundPtr.index < globalConfig.outbounds.length) {
		// Loop through each outbound method until we find a working one or reach the end

		if (destRWPair == null) {
			destRWPair = await connectAndWrite();
			// Attempt to connect and write to the outbound server
		}

		if (destRWPair != null) {
			const hasIncomingData = await remoteSocketToWS(destRWPair.readableStream, webSocket, vlessResponseHeader, vlessResponseProcessor, log);
			// Pass the destination ReadableStream to the remote WebSocket and check if there are incoming data

			if (hasIncomingData) {
				return destRWPair.writableStream;
				// If there are incoming data, return the destination WritableStream
			}

			destRWPair = null;
			// Reset the destination RW pair if there are no incoming data
		}
	}

	log('No more available outbound chain, abort!');
	safeCloseWebSocket(webSocket);
	return null;
	// If there are no working outbound connections, log and close the WebSocket, then return null
}
/**
 * Make a source out of a UDP socket, wrap each datagram with vless UDP packing.
 * Each receive datagram will be prepended with a 16-bit big-endian length field.
 *
 * @param {import("./workers").NodeJSUDP} udpClient - The UDP client object.
 * @param {import('./workers').LogFunction} log - The logger function.
 * @returns {ReadableStream<Uint8Array>} - A readable stream where the received datagrams are wrapped and made available.
 */
function makeReadableUDPStream(udpClient, log) {
	// Function that creates a readable stream from a UDP socket

	return new ReadableStream({
		// Create a new ReadableStream object

		start(controller) {
			// Start the stream

			udpClient.onmessage((message, info) => {
				// Event handler for receiving messages on the UDP socket

				// log(`Received ${info.size} bytes from UDP://${info.address}:${info.port}`)
				// Uncomment if you want to log the received datagram size and address/port information

				const header = new Uint8Array([(info.size >> 8) & 0xff, info.size & 0xff]);
				// Create a Uint8Array containing the length header (big-endian) for the datagram

				const encodedChunk = joinUint8Array(header, message);
				// Join the length header and the original datagram into a single Uint8Array

				controller.enqueue(encodedChunk);
				// Enqueue the wrapped datagram for consumption by downstream consumers
			});

			udpClient.onerror((error) => {
				// Event handler for UDP errors

				log('UDP Error: ', error.message);
				// Log the error message

				controller.error(error);
				// Notify the controller of an error and propagate it downstream
			});
		},

		cancel(reason) {
			// Cancel the stream

			log(`UDP ReadableStream closed:`, reason);
			// Log the reason for closing the stream

			safeCloseUDP(udpClient);
			// Close the UDP socket safely
		},
	});
}

/**
 * Make a sink out of a UDP socket, the input stream assumes valid vless UDP packing.
 * Each datagram to be sent should be prepended with a 16-bit big-endian length field.
 *
 * @param {import("./workers").NodeJSUDP} udpClient - The UDP client object.
 * @param {string} addressRemote - The remote address to which to send the datagrams.
 * @param {number} portRemote - The remote port to which to send the datagrams.
 * @param {import('./workers').LogFunction} log - The logger function.
 * @returns {WritableStream<ArrayBuffer | Uint8Array>} - A writable stream to which data can be written to send via UDP.
 */
function makeWritableUDPStream(udpClient, addressRemote, portRemote, log) {
	// Function that creates a writable stream to send data via UDP

	/** @type {Uint8Array} */
	let leftoverData = new Uint8Array(0);
	// Variable to hold any leftover data from previous chunks

	return new WritableStream({
		// Create a new WritableStream object

		write(chunk, controller) {
			// Write function called when data is written to the stream

			let byteArray = new Uint8Array(chunk);
			// Convert the chunk to a Uint8Array

			if (leftoverData.byteLength > 0) {
				// If we have any leftover data from previous chunk, merge it first
				byteArray = joinUint8Array(leftoverData, byteArray);
			}

			let i = 0;
			// Initialize an index variable

			while (i < byteArray.length) {
				// Iterate over the byte array

				if (i + 1 >= byteArray.length) {
					// The length field is not intact
					leftoverData = byteArray.slice(i);
					// Save the remaining data for the next chunk
					break;
				}

				// Big-endian
				const datagramLen = (byteArray[i] << 8) | byteArray[i + 1];
				// Extract the length of the datagram from the big-endian bytes

				if (i + 2 + datagramLen > byteArray.length) {
					// This UDP datagram is not intact
					leftoverData = byteArray.slice(i);
					// Save the remaining data for the next chunk
					break;
				}

				udpClient.send(byteArray, i + 2, datagramLen, portRemote, addressRemote, (err) => {
					// Send the datagram via UDP

					if (err != null) {
						console.log('UDP send error', err);
						// Log the send error to the console

						controller.error(`Failed to send UDP packet !! ${err}`);
						// Notify the controller of an error and propagate it upstream

						safeCloseUDP(udpClient);
						// Close the UDP socket safely
					}
				});

				i += datagramLen + 2;
				// Increment the index by the datagram length plus the length field size
			}
		},
		close() {
			// Close the stream

			log(`UDP WritableStream closed`);
			// Log the closure of the stream
		},
		abort(reason) {
			// Abort the stream

			console.error(`UDP WritableStream aborted`, reason);
			// Log the abort reason to the console
		},
	});
}

/**
 * @param {import("./workers").NodeJSUDP} udpClient - The UDP client object.
 */
function safeCloseUDP(udpClient) {
	// Function to safely close the UDP socket

	try {
		udpClient.close();
		// Close the UDP socket
	} catch (error) {
		console.error('safeCloseUDP error', error);
		// Log any errors that occur during closing
	}
}

/**
 * Make a source out of a WebSocket connection.
 * A ReadableStream should be created before performing any kind of write operation.
 *
 * @param {WebSocket} webSocketServer - The WebSocket server object.
 * @param {Uint8Array | undefined | null} earlyData - Data received before the ReadableStream was created.
 * @param {null | ((firstChunk : Uint8Array) => Uint8Array)} headStripper - A function to strip a header from the first data chunk.
 * @param {import('./workers').LogFunction} log - The logger function.
 * @returns {ReadableStream<Uint8Array>} - A readable stream that emits Uint8Array chunks.
 */
function makeReadableWebSocketStream(webSocketServer, earlyData, headStripper, log) {
	// Function that creates a readable stream from a WebSocket

	let readableStreamCancel = false;
	let headStripped = false;
	// Variables to track the cancellation status and if the header has been stripped

	/** @type {ReadableStream<Uint8Array>} */
	const stream = new ReadableStream({
		// Create a new ReadableStream object

		start(controller) {
			// Start function called when the stream is started

			if (earlyData && earlyData.byteLength > 0) {
				controller.enqueue(earlyData);
				// Enqueue any early data received before the stream was created
			}

			webSocketServer.addEventListener('message', (event) => {
				// Listen for WebSocket messages

				if (readableStreamCancel) {
					return;
				}
				// If the stream is canceled, return without processing the message

				let message = new Uint8Array(event.data);
				// Convert the message data to a Uint8Array

				if (!headStripped) {
					headStripped = true;

					if (headStripper != null) {
						try {
							message = headStripper(message);
							// Strip the header from the first data chunk using the provided headStripper function
						} catch (err) {
							readableStreamCancel = true;
							controller.error(err);
							return;
							// If an error occurs while stripping the header, cancel the stream and propagate the error upstream
						}
					}
				}

				controller.enqueue(message);
				// Enqueue the message data to be emitted by the stream
			});

			webSocketServer.addEventListener('close', () => {
				// Handle WebSocket close event

				safeCloseWebSocket(webSocketServer);
				if (readableStreamCancel) {
					return;
				}
				controller.close();
				// Close the stream if it is not canceled
			});

			webSocketServer.addEventListener('error', (err) => {
				log('webSocketServer has error: ' + err.message);
				controller.error(err);
				// Log any WebSocket errors and propagate them upstream as stream errors
			});
		},

		pull() {
			// Pull function called when the stream wants more data
			// Not implemented in this code, so backpressure is not handled
		},

		cancel(reason) {
			// Cancel function called when the stream is canceled

			if (readableStreamCancel) {
				return;
			}
			// If the stream is already canceled, return without further processing

			log(`ReadableStream was canceled, due to ${reason}`);
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
			// Cancel the stream, close the WebSocket, and log the cancellation reason
		},
	});

	return stream;
	// Return the created readable stream
}
// Documentation references for Vless protocol
// https://xtls.github.io/development/protocols/vless.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * Process the Vless header from a Uint8Array buffer.
 *
 * @param {Uint8Array} vlessBuffer - The Vless header data in a Uint8Array buffer.
 * @param {string} userID - The expected userID.
 * @returns {import('./workers').ProcessedVlessHeader} - The processed Vless header object.
 * @throws {Error} - Error is thrown if the data is invalid or not as expected.
 */
function processVlessHeader(vlessBuffer, userID) {
	// Function to process the Vless header

	if (vlessBuffer.byteLength < 24) {
		throw new Error('Invalid data');
	}
	// Check if the buffer length is less than 24 bytes, which is the minimum required for a valid header

	const version = vlessBuffer.slice(0, 1);
	// Extract the version from the buffer (first byte)

	let isValidUser = false;
	let isUDP = false;
	// Variables to track whether the user is valid and if the protocol is UDP

	if (uuidFromBytesSafe(vlessBuffer.slice(1, 17)) === userID) {
		isValidUser = true;
	}
	// Check if the userID extracted from the buffer matches the expected userID

	if (!isValidUser) {
		throw new Error('Invalid user');
	}
	// Throw an error if the user is not valid

	// Skip optional data for now
	const optLength = vlessBuffer.slice(17, 18)[0];

	const command = vlessBuffer.slice(18 + optLength, 18 + optLength + 1)[0];
	// Extract the command from the buffer (19th byte)

	if (command === VlessCmd.UDP) {
		isUDP = true;
	} else if (command !== VlessCmd.TCP) {
		throw new Error(`Invalid command type: ${command}, only accepts: ${JSON.stringify(VlessCmd)}`);
	}
	const portIndex = 18 + optLength + 1;
	// port is big-Endian in raw data etc 80 == 0x0050
	const portRemote = (vlessBuffer[portIndex] << 8) | vlessBuffer[portIndex + 1];
	// Extract the remote port from the buffer (20th and 21st bytes)

	const addressIndex = portIndex + 2;
	const addressBuffer = vlessBuffer.slice(addressIndex, addressIndex + 1);
	// Extract the address type from the buffer (22nd byte)

	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	// Variables to store the address type, length, index, and value

	switch (addressType) {
		case VlessAddrType.IPv4:
			addressLength = 4;
			addressValue = vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength).join('.');
			break;
		// If the address type is IPv4, extract the address value as a string in dot-separated format

		case VlessAddrType.DomainName:
			addressLength = vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		// If the address type is DomainName, extract the address value as a string using TextDecoder

		case VlessAddrType.IPv6:
			addressLength = 16;
			const ipv6Bytes = vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength);
			// Extract the IPv6 address bytes from the buffer

			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const uint16_val = ipv6Bytes[i * 2] << 8 | ipv6Bytes[i * 2 + 1];
				ipv6.push(uint16_val.toString(16));
			}
			addressValue = '[' + ipv6.join(':') + ']';
			break;
		// If the address type is IPv6, extract the address value as a string in square bracket notation

		default:
			throw new Error(`Invalid address type: ${addressType}, only accepts: ${JSON.stringify(VlessAddrType)}`);
	}
	// Switch statement to handle different address types and extract the address value accordingly

	if (!addressValue) {
		throw new Error('Empty addressValue!');
	}
	// Throw an error if the address value is empty

	return {
		addressRemote: addressValue,
		addressType,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		vlessVersion: version,
		isUDP,
	};
	// Return the processed Vless header object with extracted data
}
/**
 * Stream data from the remote destination (any) to the client side (Websocket).
 *
 * @param {ReadableStream<Uint8Array>} remoteSocketReader - Readable stream from the remote destination.
 * @param {WebSocket} webSocket - WebSocket connection to the client side.
 * @param {Uint8Array} vlessResponseHeader - The Vless response header.
 * @param {null | (() => TransformStream<Uint8Array, Uint8Array>)} vlessResponseProcessor - An optional TransformStream to process the Vless response.
 * @param {import('./workers').LogFunction} log - Log function for debugging.
 * @returns {Promise<boolean>} - A promise that resolves to a boolean indicating whether there was incoming data.
 */
async function remoteSocketToWS(remoteSocketReader, webSocket, vlessResponseHeader, vlessResponseProcessor, log) {
	// This promise fulfills if:
	// 1. There is any incoming data
	// 2. The remoteSocketReader closes without any data
	/** @type {Promise<boolean>} */
	const toRemotePromise = new Promise((resolve) => {
		let headerSent = false;
		let hasIncomingData = false;
		// Variables to track if the response header is sent and if there is any incoming data

		// Add the response header and monitor if there is any traffic coming from the remote host.

		/** @type {TransformStream<Uint8Array, Uint8Array>} */
		const vlessResponseHeaderPrepender = new TransformStream({
			// Transform stream to prepend the response header to the data stream
			start() {
				// No actions needed at the start of the transform stream
			},
			transform(chunk, controller) {
				hasIncomingData = true;
				resolve(true);
				// Resolve the promise immediately if there is any data received from the remote host

				if (!headerSent) {
					controller.enqueue(joinUint8Array(vlessResponseHeader, chunk));
					headerSent = true;
				} else {
					controller.enqueue(chunk);
				}
				// Enqueue chunks to the controller, either with the response header or directly
			},
			flush() {
				log(`Response transformer flushed, hasIncomingData = ${hasIncomingData}`);
				// Log message when the transform stream is flushed (end of data)

				resolve(hasIncomingData);
				// Resolve the promise, indicating if there was any incoming data
			}
		});

		const toClientWsSink = new WritableStream({
			// Writable stream to send data to webSocket
			start() {
				// No actions needed at the start of the writable stream
			},
			write(chunk, controller) {
				// remoteChunkCount++;
				if (webSocket.readyState !== WS_READY_STATE_OPEN) {
					controller.error('webSocket.readyState is not open, maybe close');
				}
				// Check if the WebSocket connection is open before sending data

				webSocket.send(chunk);
				// Send the chunk of data to the WebSocket
			},
			close() {
				// Action to take when the writable stream is closed
			},
		});

		const vlessResponseWithHeader = remoteSocketReader.pipeThrough(vlessResponseHeaderPrepender);
		// Pipe the remoteSocketReader through the vlessResponseHeaderPrepender to prepend the response header

		const processedVlessResponse = vlessResponseProcessor == null ? vlessResponseWithHeader :
			vlessResponseWithHeader.pipeThrough(vlessResponseProcessor());
		// If vlessResponseProcessor is provided, pipe the response through it, otherwise use vlessResponseWithHeader directly

		processedVlessResponse.pipeTo(toClientWsSink)
			.catch((error) => {
				console.error(
					`remoteSocketToWS has exception, readyState = ${webSocket.readyState} :`,
					error.stack || error
				);
				safeCloseWebSocket(webSocket);
			});
		// Pipe the processed response to the WebSocket writable stream and handle any errors

	});

	return await toRemotePromise;
	// Wait for the promise to resolve and return the boolean indicating if there was incoming data
}

/**
 * Convert a base64 string to a Uint8Array.
 *
 * @param {string} base64Str - The base64 string to convert.
 * @returns {Uint8Array | any} - Returns a Uint8Array if the conversion is successful, otherwise an error will be returned.
 */
function base64ToUint8Array(base64Str) {
	// Function to convert a base64 string to Uint8Array

	if (!base64Str) {
		// If the base64 string is empty or null, return an empty Uint8Array
		return new Uint8Array(0);
	}

	try {
		// Replace characters in the base64 string to align with the URL rfc4648 specification
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		// Decodes the modified base64 string using the atob function
		const decode = atob(base64Str);
		// Convert the decoded string into a Uint8Array by mapping each character's charCodeAt value
		return Uint8Array.from(decode, (c) => c.charCodeAt(0));
	} catch (error) {
		// If any error occurs during the conversion, return the error object
		return error;
	}
}

/**
 * This is not real UUID validation.
 *
 * @param {string} uuid - The UUID string to validate.
 */
function isValidUUID(uuid) {
	// Regular expression for UUID format validation
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

/**
 * Convert ArrayBuffer to a UUID string and check it against isValidUUID().
 *
 * @param {ArrayBufferLike} buffer - The ArrayBuffer to convert into a UUID string.
 */
function uuidFromBytesSafe(buffer, offset = 0) {
	// Convert the ArrayBuffer to a UUID string
	const uuid = uuidStrFromBytes(buffer, offset);
	if (!isValidUUID(uuid)) {
		// Check if the converted UUID string is valid, throw an error if not
		throw TypeError("Stringified UUID is invalid");
	}
	return uuid;
}

/**
 * Convert ArrayBuffer to a UUID string.
 *
 * @param {ArrayBufferLike} buffer - The ArrayBuffer to convert into a UUID string.
 * @returns {string} - The UUID string in lower-case.
 */
function uuidStrFromBytes(buffer, offset = 0) {
	// Convert the ArrayBuffer to Uint8Array
	const bytes = new Uint8Array(buffer);
	let uuid = '';

	for (let i = 0; i < 16; i++) {
		let byteHex = bytes[i + offset].toString(16).toLowerCase();
		if (byteHex.length === 1) {
			byteHex = '0' + byteHex; // Ensure byte is always represented by two characters
		}
		uuid += byteHex;
		if (i === 3 || i === 5 || i === 7 || i === 9) {
			uuid += '-';
		}
	}

	return uuid;
}

// Constants for WebSocket ready states
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

/**
 * Normally, WebSocket will not have exceptions when closing.
 *
 * @param {WebSocket} socket - The WebSocket to safely close.
 */
function safeCloseWebSocket(socket) {
	try {
		// Check the ready state of the WebSocket and close it if open or closing
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		// Log any potential errors during WebSocket closure
		console.error('safeCloseWebSocket error', error);
	}
}
/**
 * Joins two Uint8Array arrays into one.
 *
 * @param {Uint8Array} array1 - The first array.
 * @param {Uint8Array} array2 - The second array.
 * @returns {Uint8Array} - The merged Uint8Array.
 */
function joinUint8Array(array1, array2) {
	// Create a new Uint8Array with the combined length of array1 and array2
	const result = new Uint8Array(array1.byteLength + array2.byteLength);
	result.set(array1); // Copy the contents of array1 to the beginning of result
	result.set(array2, array1.byteLength); // Copy the contents of array2 to the end of result
	return result;
}

/**
 * Establishes a SOCKS5 connection over a given socket.
 *
 * @param {import("./workers").CloudflareTCPConnection} socket - The socket connection.
 * @param {string | undefined} username - The username for authentication.
 * @param {string | undefined} password - The password for authentication.
 * @param {number} addressType - The type of destination address.
 * @param {string} addressRemote - The remote address.
 * @param {number} portRemote - The remote port.
 * @param {import('./workers').LogFunction} log - The logging function.
 * @throws {Error}
 */
async function socks5Connect(socket, username, password, addressType, addressRemote, portRemote, log) {
	const writer = socket.writable.getWriter();

	// Request head format (Worker -> Socks Server):
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+

	// https://en.wikipedia.org/wiki/SOCKS#SOCKS5
	// For METHODS:
	// 0x00 NO AUTHENTICATION REQUIRED
	// 0x02 USERNAME/PASSWORD https://datatracker.ietf.org/doc/html/rfc1929
	await writer.write(new Uint8Array([5, 2, 0, 2]));

	const reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	let res = (await reader.read()).value;
	if (!res) {
		throw new Error(`No response from the server`);
	}

	// Response format (Socks Server -> Worker):
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	if (res[0] !== 0x05) {
		throw new Error(`Wrong server version: ${res[0]} expected: 5`);
	}
	if (res[1] === 0xff) {
		throw new Error("No accepted authentication methods");
	}

	// if return 0x0502
	if (res[1] === 0x02) {
		log("Socks5: Server asks for authentication");
		if (!username || !password) {
			throw new Error("Please provide username/password");
		}
		// +----+------+----------+------+----------+
		// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		// +----+------+----------+------+----------+
		// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		// +----+------+----------+------+----------+
		const authRequest = new Uint8Array([
			1,
			username.length,
			...encoder.encode(username),
			password.length,
			...encoder.encode(password)
		]);
		await writer.write(authRequest);
		res = (await reader.read()).value;
		// expected 0x0100
		if (typeof res === 'undefined' || res[0] !== 0x01 || res[1] !== 0x00) {
			throw new Error("Authentication failed");
		}
	}

	// Request data format (Worker -> Socks Server):
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	// ATYP: address type of following address
	// 0x01: IPv4 address
	// 0x03: Domain name
	// 0x04: IPv6 address
	// DST.ADDR: desired destination address
	// DST.PORT: desired destination port in network octet order

	// addressType
	// 1--> ipv4  addressLength =4
	// 2--> domain name
	// 3--> ipv6  addressLength =16
	/** @type {Uint8Array?} */
	let DSTADDR;	// DSTADDR = ATYP + DST.ADDR
	switch (addressType) {
		case 1:
			DSTADDR = new Uint8Array(
				[1, ...addressRemote.split('.').map(Number)]
			);
			break;
		case 2:
			DSTADDR = new Uint8Array(
				[3, addressRemote.length, ...encoder.encode(addressRemote)]
			);
			break;
		case 3:
			DSTADDR = new Uint8Array(
				[4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
			);
			break;
		default:
			log(`invild  addressType is ${addressType}`);
			return;
	}
	const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
	await writer.write(socksRequest);
	log('Socks5: Sent request');

	res = (await reader.read()).value;
	// Response format (Socks Server -> Worker):
	//  +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	if (typeof res !== 'undefined' && res[1] === 0x00) {
		log("Socks5: Connection opened");
	} else {
		throw new Error("Connection failed");
	}
	writer.releaseLock();
	reader.releaseLock();
}

/**
 * Parses the SOCKS5 address.
 *
 * @param {string} address - The address to parse.
 * @throws {Error}
 */
function socks5AddressParser(address) {
	const [latter, former] = address.split("@").reverse();
	let username, password;
	if (former) {
		const formers = former.split(":");
		if (formers.length !== 2) {
			throw new Error('Invalid SOCKS address format');
		}
		[username, password] = formers;
	}
	const latters = latter.split(":");
	const port = Number(latters.pop());
	if (isNaN(port)) {
		throw new Error('Invalid SOCKS address format');
	}
	const hostname = latters.join(":");
	const regex = /^\[.*\]$/;
	if (hostname.includes(":") && !regex.test(hostname)) {
		throw new Error('Invalid SOCKS address format');
	}
	return {
		username,
		password,
		hostname,
		port,
	}
}

const VlessCmd = {
	TCP: 1,
	UDP: 2,
	MUX: 3,
};

const VlessAddrType = {
	IPv4: 1,		// 4-bytes
	DomainName: 2,	// The first byte indicates the length of the following domain name
	IPv6: 3,		// 16-bytes
};

/**
 * Generates a vless request header.
 *
 * @param {number} command - The command type (see VlessCmd).
 * @param {number} destType - The destination address type (see VlessAddrType).
 * @param {string} destAddr - The destination address.
 * @param {number} destPort - The destination port.
 * @param {string} uuid - The UUID.
 * @returns {Uint8Array} - The generated request header.
 * @throws {Error}
 */
function makeVlessReqHeader(command, destType, destAddr, destPort, uuid) {
	let addressFieldLength;
	let addressEncoded;
	switch (destType) {
		case VlessAddrType.IPv4:
			addressFieldLength = 4;
			break;
		case VlessAddrType.DomainName:
			addressEncoded = new TextEncoder().encode(destAddr);
			addressFieldLength = addressEncoded.length + 1;
			break;
		case VlessAddrType.IPv6:
			addressFieldLength = 16;
			break;
		default:
			throw new Error(`Unknown address type: ${destType}`);
	}

	const uuidString = uuid.replace(/-/g, '');
	const uuidOffset = 1;
	const vlessHeader = new Uint8Array(22 + addressFieldLength);

	// Protocol Version = 0
	vlessHeader[0] = 0x00;

	for (let i = 0; i < uuidString.length; i += 2) {
		vlessHeader[uuidOffset + i / 2] = parseInt(uuidString.substr(i, 2), 16);
	}

	// Additional Information Length M = 0
	vlessHeader[17] = 0x00;

	// Instruction
	vlessHeader[18] = command;

	// Port, 2-byte big-endian
	vlessHeader[19] = destPort >> 8;
	vlessHeader[20] = destPort & 0xFF;

	// Address Type
	vlessHeader[21] = destType;

	// Address
	switch (destType) {
		case VlessAddrType.IPv4: {
			const octetsIPv4 = destAddr.split('.');
			for (let i = 0; i < 4; i++) {
				vlessHeader[22 + i] = parseInt(octetsIPv4[i]);
			}
			break;
		}
		case VlessAddrType.DomainName:
			addressEncoded = /** @type {Uint8Array} */ (addressEncoded);
			vlessHeader[22] = addressEncoded.length;
			vlessHeader.set(addressEncoded, 23);
			break;
		case VlessAddrType.IPv6: {
			const groupsIPv6 = destAddr.replace(/\[|\]/g, '').split(':');
			for (let i = 0; i < 8; i++) {
				const hexGroup = parseInt(groupsIPv6[i], 16);
				vlessHeader[i * 2 + 22] = hexGroup >> 8;
				vlessHeader[i * 2 + 23] = hexGroup & 0xFF;
			}
			break;
		}
		default:
			throw new Error(`Unknown address type: ${destType}`);
	}

	return vlessHeader;
}
/**
 * Checks the validity of a Vless configuration based on the given address and streamSettings.
 *
 * @param {string} address - The domain name, HTTP request hostname, and SNI of the remote host.
 * @param {import("./workers").StreamSettings} streamSettings - The stream settings object.
 */
function checkVlessConfig(address, streamSettings) {
	// Check if the network method is 'ws' (Websocket)
	if (streamSettings.network !== 'ws') {
		throw new Error(`Unsupported outbound stream method: ${streamSettings.network}, has to be ws (Websocket)`);
	}

	// Check if the security layer is either 'none' or 'tls'
	if (streamSettings.security !== 'tls' && streamSettings.security !== 'none') {
		throw new Error(`Unsupported security layer: ${streamSettings.network}, has to be none or tls.`);
	}

	// Check the Host field in the HTTP header against the server address
	if (streamSettings.wsSettings && streamSettings.wsSettings.headers && streamSettings.wsSettings.headers.Host !== address) {
		throw new Error(`The Host field in the HTTP header is different from the server address, this is unsupported due to Cloudflare API restrictions`);
	}

	// Check the SNI (Server Name Indication) against the server address
	if (streamSettings.tlsSettings && streamSettings.tlsSettings.serverName !== address) {
		throw new Error(`The SNI is different from the server address, this is unsupported due to Cloudflare API restrictions`);
	}
}

/**
 * Parses a Vless URL into its components.
 *
 * @param {string} url - The Vless URL.
 * @returns {Object} - The parsed components of the Vless URL.
 */
function parseVlessString(url) {
	const regex = /^(.+):\/\/(.+?)@(.+?):(\d+)(\?[^#]*)?(#.*)?$/;
	const match = url.match(regex);

	if (!match) {
		throw new Error('Invalid URL format');
	}

	const [, protocol, uuid, remoteHost, remotePort, query, descriptiveText] = match;

	const json = {
		protocol,
		uuid,
		remoteHost,
		remotePort: parseInt(remotePort),
		descriptiveText: descriptiveText ? descriptiveText.substring(1) : '',
		queryParams: {}
	};

	if (query) {
		const queryFields = query.substring(1).split('&');
		queryFields.forEach(field => {
			const [key, value] = field.split('=');
			json.queryParams[key] = value;
		});
	}

	return json;
}

/**
 * Generates a VLESS configuration for the given hostName.
 *
 * @param {string} hostName - The hostname of the server.
 * @returns {string} - The generated VLESS configuration.
 */
export function getVLESSConfig(hostName) {
	const vlessMain = `vless://${globalConfig.userID}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${hostName}`;
	return `
################################################################
v2ray
---------------------------------------------------------------
${vlessMain}
---------------------------------------------------------------
################################################################
clash-meta
---------------------------------------------------------------
- type: vless
  name: ${hostName}
  server: ${hostName}
  port: 443
  uuid: ${globalConfig.userID}
  network: ws
  tls: true
  udp: false
  sni: ${hostName}
  client-fingerprint: chrome
  ws-opts:
	path: "/?ed=2048"
	headers:
	  host: ${hostName}
---------------------------------------------------------------
################################################################
`;
}
