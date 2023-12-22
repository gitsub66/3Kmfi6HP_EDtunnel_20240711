import { globalConfig, redirectConsoleLog, setConfigFromEnv, getVLESSConfig, vlessOverWSHandler, fetchWithCache } from './utils.js';

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
        setConfigFromEnv(env);
        const upgradeHeader = request.headers.get('Upgrade');

        // Check if the request is not a WebSocket upgrade request
        if (!upgradeHeader || upgradeHeader !== 'websocket') {
            const url = new URL(request.url);

            // Handle different URL paths
            switch (url.pathname) {
                case '/cf':
                    // Return a response with the Cloudflare information in JSON format
                    return new Response(JSON.stringify(request.cf), { status: 200 });
                case `/${globalConfig.userID}`:
                    {
                        // Get VLESS config based on the Host header and return it as a response
                        const vlessConfig = getVLESSConfig(request.headers.get('Host'));
                        return new Response(`${vlessConfig}`, {
                            status: 200,
                            headers: {
                                "Content-Type": "text/plain;charset=utf-8",
                            }
                        });
                    }
                default:
                    return await fetchWithCache(request);
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
