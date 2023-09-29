// <!--GAMFC-->version base on commit 43fad05dcdae3b723c53c226f8181fc5bd47223e, time is 2023-06-22 15:20:02 UTC<!--GAMFC-END-->.
// @ts-ignore
import { connect } from 'cloudflare:sockets';
// import { connectdb } from '@planetscale/database';

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = 'd342d11e-d424-4583-b36e-524ab1f0afa4';

const proxyIPs = ['152.67.201.73', '150.230.194.34'];

let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];

let dohURL = 'https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg='; // https://cloudflare-dns.com/dns-query or https://dns.google/dns-query

// v2board api environment variables (optional) deprecated, please use planetscale.com instead
// v2board api environment variables (optional)
// now deprecated, please use planetscale.com instead
let nodeId = ''; // 1

let apiToken = ''; //abcdefghijklmnopqrstuvwxyz123456

let apiHost = ''; // api.v2board.com

if (!isValidUUID(userID)) {
	throw new Error('uuid is invalid');
@@ -26,14 +33,13 @@ export default {
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		uuid_validator(request);
		try {
			userID = env.UUID || userID;
			proxyIP = env.PROXYIP || proxyIP;
			dohURL = env.DNS_RESOLVER_URL || dohURL;
			// nodeId = env.NODE_ID || nodeId;
			// apiToken = env.API_TOKEN || apiToken;
			// apiHost = env.API_HOST || apiHost;
			nodeId = env.NODE_ID || nodeId;
			apiToken = env.API_TOKEN || apiToken;
			apiHost = env.API_HOST || apiHost;
			let userID_Path = userID;
			if (userID.includes(',')) {
				userID_Path = userID.split(',')[0];
@@ -49,6 +55,47 @@ export default {
								"Content-Type": "application/json;charset=utf-8",
							},
						});
					case '/connect': // for test connect to cf socket
						const [hostname, port] = ['cloudflare.com', '80'];
						console.log(`Connecting to ${hostname}:${port}...`);

						try {
							const socket = await connect({
								hostname: hostname,
								port: parseInt(port, 10),
							});

							const writer = socket.writable.getWriter();

							try {
								await writer.write(new TextEncoder().encode('GET / HTTP/1.1\r\nHost: ' + hostname + '\r\n\r\n'));
							} catch (writeError) {
								writer.releaseLock();
								await socket.close();
								return new Response(writeError.message, { status: 500 });
							}

							writer.releaseLock();

							const reader = socket.readable.getReader();
							let value;

							try {
								const result = await reader.read();
								value = result.value;
							} catch (readError) {
								await reader.releaseLock();
								await socket.close();
								return new Response(readError.message, { status: 500 });
							}

							await reader.releaseLock();
							await socket.close();

							return new Response(new TextDecoder().decode(value), { status: 200 });
						} catch (connectError) {
							return new Response(connectError.message, { status: 500 });
						}
					case `/${userID_Path}`: {
						const vlessConfig = getVLESSConfig(userID, request.headers.get('Host'));
						return new Response(`${vlessConfig}`, {
@@ -79,29 +126,27 @@ export default {
					default:
						// return new Response('Not found', { status: 404 });
						// For any other path, reverse proxy to 'www.fmprc.gov.cn' and return the original response, caching it in the process
						const hostnames = ['www.fmprc.gov.cn', 'www.xuexi.cn', 'www.gov.cn', 'mail.gov.cn', 'www.mofcom.gov.cn', 'www.gfbzb.gov.cn', 'www.miit.gov.cn', 'www.12377.cn'];
						const hostnames = ['www.bing.com'];
						url.hostname = hostnames[Math.floor(Math.random() * hostnames.length)];
						url.protocol = 'https:';

						const newHeaders = new Headers(request.headers);
						newHeaders.set('cf-connecting-ip', newHeaders.get('x-forwarded-for') || newHeaders.get('cf-connecting-ip'));
						newHeaders.set('x-forwarded-for', newHeaders.get('cf-connecting-ip'));
						newHeaders.set('x-real-ip', newHeaders.get('cf-connecting-ip'));
						newHeaders.set('referer', 'https://www.google.com/q=edtunnel');

						request = new Request(url, {
							method: request.method,
							headers: newHeaders,
							body: request.body,
							redirect: request.redirect,
						});

						const cache = caches.default;
						let response = await cache.match(request);

						if (!response) {
							// if not in cache, get response from origin
							// send client ip to origin server to get right ip
							try {
								response = await fetch(request, { redirect: 'manual' });
								response = await fetch(request, { redirect: "manual" });
							} catch (err) {
								url.protocol = 'http:';
								url.hostname = hostnames[Math.floor(Math.random() * hostnames.length)];
@@ -111,9 +156,8 @@ export default {
									body: request.body,
									redirect: request.redirect,
								});
								response = await fetch(request, { redirect: 'manual' });
								response = await fetch(request, { redirect: "manual" });
							}

							const cloneResponse = response.clone();
							ctx.waitUntil(cache.put(request, cloneResponse));
						}
@@ -129,30 +173,22 @@ export default {
	},
};

export async function uuid_validator(request) {
	const hostname = request.headers.get('Host');
	const currentDate = new Date();

	const subdomain = hostname.split('.')[0];
	const year = currentDate.getFullYear();
	const month = String(currentDate.getMonth() + 1).padStart(2, '0');
	const day = String(currentDate.getDate()).padStart(2, '0');

	const formattedDate = `${year}-${month}-${day}`;

	// const daliy_sub = formattedDate + subdomain
	const hashHex = await hashHex_f(subdomain);
	// subdomain string contains timestamps utc and uuid string TODO.
	console.log(hashHex, subdomain, formattedDate);
}

export async function hashHex_f(string) {
	const encoder = new TextEncoder();
	const data = encoder.encode(string);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
	return hashHex;
/**
 * Creates a PlanetScale connection object and returns it.
 * @param {{DATABASE_HOST: string, DATABASE_USERNAME: string, DATABASE_PASSWORD: string}} env The environment variables containing the database connection information.
 * @returns {Promise<object>} A Promise that resolves to the PlanetScale connection object.
 */
function getPlanetScaleConnection(env) {
	const config = {
		host: env.DATABASE_HOST,
		username: env.DATABASE_USERNAME,
		password: env.DATABASE_PASSWORD,
		fetch: (url, init) => {
			delete (init)["cache"];
			return fetch(url, init);
		}
	}
	return connectdb(config)
}

/**
@@ -167,9 +203,8 @@ async function vlessOverWSHandler(request) {

	let address = '';
	let portWithRandomLog = '';
	let currentDate = new Date();
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${currentDate} ${address}:${portWithRandomLog}] ${info}`, event || '');
		console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

@@ -252,6 +287,81 @@ async function vlessOverWSHandler(request) {
	});
}

let apiResponseCache = null;
let cacheTimeout = null;

/**
 * Fetches the API response from the server and caches it for future use.
 * @returns {Promise<object|null>} A Promise that resolves to the API response object or null if there was an error.
 */
async function fetchApiResponse() {
	const requestOptions = {
		method: 'GET',
		redirect: 'follow'
	};

	try {
		const response = await fetch(`https://${apiHost}/api/v1/server/UniProxy/user?node_id=${nodeId}&node_type=v2ray&token=${apiToken}`, requestOptions);

		if (!response.ok) {
			console.error('Error: Network response was not ok');
			return null;
		}
		const apiResponse = await response.json();
		apiResponseCache = apiResponse;

		// Refresh the cache every 5 minutes (300000 milliseconds)
		if (cacheTimeout) {
			clearTimeout(cacheTimeout);
		}
		cacheTimeout = setTimeout(() => fetchApiResponse(), 300000);

		return apiResponse;
	} catch (error) {
		console.error('Error:', error);
		return null;
	}
}

/**
 * Returns the cached API response if it exists, otherwise fetches the API response from the server and caches it for future use.
 * @returns {Promise<object|null>} A Promise that resolves to the cached API response object or the fetched API response object, or null if there was an error.
 */
async function getApiResponse() {
	if (!apiResponseCache) {
		return await fetchApiResponse();
	}
	return apiResponseCache;
}

/**
 * Checks if a given UUID is present in the API response.
 * @param {string} targetUuid The UUID to search for.
 * @returns {Promise<boolean>} A Promise that resolves to true if the UUID is present in the API response, false otherwise.
 */
async function checkUuidInApiResponse(targetUuid) {
	// Check if any of the environment variables are empty
	if (!nodeId || !apiToken || !apiHost) {
		return false;
	}

	try {
		const apiResponse = await getApiResponse();
		if (!apiResponse) {
			return false;
		}
		const isUuidInResponse = apiResponse.users.some(user => user.uuid === targetUuid);
		return isUuidInResponse;
	} catch (error) {
		console.error('Error:', error);
		return false;
	}
}

// Usage example:
//   const targetUuid = "65590e04-a94c-4c59-a1f2-571bce925aad";
//   checkUuidInApiResponse(targetUuid).then(result => console.log(result));

/**
 * Handles outbound TCP connections.
 *
@@ -380,16 +490,14 @@ function processVlessHeader(vlessBuffer, userID) {
			message: 'invalid data',
		};
	}

	const version = new Uint8Array(vlessBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
	const slicedBufferString = stringify(slicedBuffer);
	// check if userID is valid uuid or uuids split by , and contains userID in it otherwise return error message to console
	const uuids = userID.includes(',') ? userID.split(",") : [userID];
	// uuid_validator(hostName, slicedBufferString);

	console.log(slicedBufferString, uuids);

	// isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim());
	isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim()) || uuids.length === 1 && slicedBufferString === uuids[0].trim();
@@ -532,7 +640,7 @@ async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, re
						webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
						vlessHeader = null;
					} else {
						// console.log(`remoteSocketToWS send chunk ${chunk.byteLength}`);
						console.log(`remoteSocketToWS send chunk ${chunk.byteLength}`);
						// seems no need rate limit this, CF seems fix this??..
						// if (remoteChunkCount > 20000) {
						// 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
@@ -867,4 +975,3 @@ function createVLESSSub(userID_Path, hostName) {
	// Join output with newlines
	return output.join('\n');
}
