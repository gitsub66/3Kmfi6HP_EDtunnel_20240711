/**
 * Defines a Cloudflare Worker compatible TCP connection.
 */
export interface CloudflareTCPConnection {
    readable: ReadableStream<Uint8Array>,  // Represents a readable stream for receiving data
    writable: WritableStream<Uint8Array>, // Represents a writable stream for sending data
    closed: Promise<void>, // Represents a promise that is resolved when the connection is closed
}

export interface NodeJSUDPRemoteInfo {
    address: string, // The remote IP address
    family: 'IPv4' | 'IPv6', // The IP address family (IPv4 or IPv6)
    port: number, // The remote port number
    size: number, // The size of the received data
}

/**
 * Defines a NodeJS compatible UDP API.
 */
export interface NodeJSUDP {
    send: (
        datagram: any,
        offset: number,
        length: number,
        port: number,
        address: string,
        sendDoneCallback: (err: Error | null, bytes: number) => void
    ) => void, // Sends a UDP datagram to the specified address and port
    close: () => void, // Closes the UDP socket
    onmessage: (handler: (msg: Uint8Array, rinfo: NodeJSUDPRemoteInfo) => void) => void, // Adds a handler for receiving UDP messages
    onerror: (handler: (err: Error) => void) => void, // Adds a handler for UDP socket errors
}

/**
 * The base type of all outbound definitions.
 */
export interface Outbound {
    protocol: string, // The protocol used by the outbound connection
    settings?: {}, // Additional settings for the outbound connection
}

/**
 * Represents a local outbound.
 */
export interface FreedomOutbound extends Outbound {
    protocol: 'freedom',
    settings: undefined // No additional settings required for freedom outbound
}

export type PortMap = { [key: number]: number }; // Represents a mapping of source and destination ports

/**
 * Represents a forwarding outbound.
 * First, the destination port of the request will be mapped according to portMap.
 * If none matches, the destination port remains unchanged.
 * Then, the request stream will be redirected to the given address.
 */
export interface ForwardOutbound extends Outbound {
    protocol: 'forward',
    address: string, // The address to which the request stream is redirected
    portMap?: PortMap // The mapping of source and destination ports
}

export interface Socks5Server {
    address: string, // The address of the SOCKS5 server
    port: number, // The port number of the SOCKS5 server
    users?: {
        user: string,
        pass: string,
    }[] // Optional user credentials for SOCKS5 authentication
}

/**
 * Represents a socks5 outbound.
 */
export interface Socks5Outbound extends Outbound {
    protocol: 'socks',
    settings: {
        servers: Socks5Server[] // The list of SOCKS5 servers
    }
}

export interface VlessServer {
    address: string, // The address of the Vless server
    port: number, // The port number of the Vless server
    users: {
        id: string,
    }[] // The list of user IDs for Vless authentication
}

/**
 * Represents a Vless WebSocket outbound.
 */
export interface VlessWsOutbound {
    protocol: 'vless',
    settings: {
        vnext: VlessServer[] // The list of Vless servers
    },
    streamSettings: StreamSettings // The stream settings for Vless WebSocket
}

export interface StreamSettings {
    network: 'ws', // The network protocol (WebSocket in this case)
    security: 'none' | 'tls', // The security level for the WebSocket connection
    wsSettings?: {
        path?: string, // The path of the WebSocket endpoint
        headers?: {
            Host: string
        }
    },
    tlsSettings?: {
        serverName: string, // The server name for TLS handshake
        allowInsecure: boolean, // Whether to allow insecure TLS connections
    }
}

export interface OutboundContext {
    enforceUDP: boolean, // Whether to enforce UDP protocol for the outbound connection
    forwardDNS: boolean, // Whether to forward DNS queries
    log: LogFunction, // The logging function
    firstChunk: Uint8Array, // The first chunk of data received
}

export type OutboundHanderReturns = Promise<{
    readableStream: ReadableStream<Uint8Array>, // Represents a readable stream for receiving data
    writableStream: WritableStream<Uint8Array>, // Represents a writable stream for sending data
}>;

export type OutboundHandler = (
    vlessRequest: ProcessedVlessHeader, // The processed Vless header
    context: OutboundContext
) => OutboundHanderReturns; // Represents the handler function for outbound connections

export interface OutboundInstance {
    protocol: string, // The protocol used by the outbound instance
    handler: OutboundHandler, // The handler function for outbound connections
}

export interface ForwardInstanceArgs {
    proxyServer: string, // The address of the proxy server
    portMap?: PortMap // The mapping of source and destination ports
}

export interface Socks5InstanceArgs {
    address: string, // The address of the SOCKS5 server
    port: number, // The port number of the SOCKS5 server
    user?: string, // Optional user credentials for SOCKS5 authentication
    pass?: string,
}

export interface VlessInstanceArgs {
    address: string, // The address of the Vless server
    port: number, // The port number of the Vless server
    uuid: string, // The UUID used for Vless authentication
    streamSettings: StreamSettings // The stream settings for Vless WebSocket
}

export interface ProcessedVlessHeader {
    addressRemote: string, // The remote address
    addressType: number, // The type of the remote address
    portRemote: number, // The remote port
    rawDataIndex: number, // The index of raw data
    vlessVersion: Uint8Array, // The Vless version
    isUDP: boolean, // Whether the connection uses UDP protocol
}

export type LogFunction = (...args: any[]) => void; // Represents a logging function

// API starts ------------------------------------------------------------------------------------

export interface PlatformAPI {
    /** 
     * A wrapper for the TCP API, should return a Cloudflare Worker compatible socket.
     * The result is wrapped in a Promise, as in some platforms, the socket creation is async.
     * See: https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/
     */
    connect: (host: string, port: number) => Promise<CloudflareTCPConnection>, // Connects to a host and port using TCP

    /** 
     * A wrapper for the Websocket API.
     */
    newWebSocket: (url: string) => WebSocket, // Creates a new WebSocket connection

    /** 
     * A wrapper for the UDP API, should return a NodeJS compatible UDP socket.
     * The result is wrapped in a Promise, as in some platforms, the socket creation is async.
     */
    associate: null | ((isIPv6: boolean) => Promise<NodeJSUDP>), // Creates a UDP socket

    /**
     * An optional processor to process the incoming WebSocket request and its response.
     * The response processor may need to be created multiple times before truly utilization.
     * @type { }
     */
    processor: null | ((logger: LogFunction) => {
        request: TransformStream<Uint8Array, Uint8Array>, // Represents a transform stream for processing WebSocket requests
        response: () => TransformStream<Uint8Array, Uint8Array>, // Represents a transform stream for processing WebSocket responses
    }),
}

export interface GlobalConfig {
    /** The UUID used in Vless authentication. */
    userID: string, // The UUID used for Vless authentication

    /** Time to wait before an outbound Websocket connection is considered timeout, in ms. */
    openWSOutboundTimeout: number, // The timeout duration for WebSocket connections

    /**
     * Since Cloudflare Worker does not support UDP outbound, we may try DNS over TCP.
     * Set to an empty string to disable UDP to TCP forwarding for DNS queries.
     */
    dnsTCPServer: string, // The DNS over TCP server address

    /** The order controls where to send the traffic after the previous one fails. */
    outbounds: Outbound[], // The list of outbound connections
}

declare const globalConfig: GlobalConfig;
declare const platformAPI: PlatformAPI;

/** 
 * Setup the config (uuid & outbounds) from environmental variables.
 * This is the simplest case and should be preferred where possible.
 */
declare function setConfigFromEnv(env: {
    UUID?: string, // The UUID for Vless authentication

    /** e.g. 114.51.4.0 */
    PROXYIP?: string, // The address of the proxy server

    /** e.g. {443:8443} */
    PORTMAP?: string, // The mapping of source and destination ports

    /** e.g. vless://uuid@domain.name:port?type=ws&security=tls */
    VLESS?: string, // The Vless server configuration

    /** e.g. user:pass@host:port or host:port */
    SOCKS5?: string, // The SOCKS5 server configuration
}): void;

declare function getVLESSConfig(hostName?: string): string;

/** 
 * If you use this file as an ES module, you call this function whenever your Websocket server accepts a new connection. 
 * @param webSocket The established websocket connection, must be an accepted.
 * @param earlyDataHeader for ws 0rtt, an optional field "sec-websocket-protocol" in the request header 
 * may contain some base64 encoded data.
 * @returns status code
 */
declare function vlessOverWSHandler(webSocket: WebSocket, earlyDataHeader: string): number;

declare function redirectConsoleLog(logServer: string, instanceId: string): void;
