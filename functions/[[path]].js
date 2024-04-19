import { globalConfig, redirectConsoleLog, setConfigFromEnv, vlessOverWSHandler, cn_hostnames } from './utils.js';
import { createVLESSSub, getVLESSConfig } from './html.js';

/**
 * Entry point function for processing requests.
 *
 * @param {any} context - The context object containing request and environment information.
 * @returns {Promise<Response>} - A promise that resolves to a response object.
 */
export async function onRequest(context) {
    const {
        request, // Original request object including client's request information
        env,     // Worker environment variables
    } = context;

    if (env.LOGPOST) {
        redirectConsoleLog(env.LOGPOST, crypto.randomUUID());
    }

    try {
        setConfigFromEnv(request, env);
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
                        const vlessConfig = getVLESSConfig(globalConfig.userID, request.headers.get('Host'), env.PROXYIP || "cdn.xn--b6gac.eu.org");
                        return new Response(`${vlessConfig}`, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/html;charset=utf-8",
                            }
                        });
                    }
                    // Return an error response with a forbidden status code
                    return new Response('Access Forbidden', { status: 403 });
                case `/sub/${globalConfig.userID}`:
                    const sub_pages = createVLESSSub(globalConfig.userID, request.headers.get('Host'), env.PROXYIP || "cdn.xn--b6gac.eu.org")
                    return new Response(btoa(sub_pages), {
                        status: 200,
                        headers: {
                            "Content-Type": "text/plain; charset=utf-8",
                        }
                    });
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
};
