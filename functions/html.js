export function createVLESSSub(uuid, hostName, proxyIP) {
    const portArray_https = [443, 8443, 2053, 2096, 2087, 2083];
    const userIDArray = uuid.split(',');

    const output = [];

    for (const userID of userIDArray) {
        for (const port of portArray_https) {
            const commonUrlPart_https = `:${port}?encryption=none&security=tls&sni=${hostName}&fp=random&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#EDtunnel-${hostName}-HTTPS-${port}`;
            const vlessMainHttps = `vless://${userID}@${hostName}${commonUrlPart_https}`;
            const vlessSecHttps = `vless://${userID}@${proxyIP}${commonUrlPart_https}-${proxyIP}`;
            output.push(vlessMainHttps);
            output.push(vlessSecHttps);
        }
    }

    return output.join('\n');
}

/**
 *
 * @param {string} userID - single or comma separated userIDs
 * @param {string | null} hostName
 * @returns {string}
 */
export function getVLESSConfig(userID, hostName, proxyIP) {
    const commonUrlPart = `:443?encryption=none&security=tls&sni=${hostName}&fp=randomized&type=ws&host=${hostName}&path=%2F%3Fed%3D2048#${hostName}`;
    const separator = "---------------------------------------------------------------";
    const hashSeparator = "################################################################";

    // Split the userIDs into an array
    // Prepare output array
    let output = [];
    let header = [];
    const clash_link = `https://subconverter.do.xn--b6gac.eu.org/sub?target=clash&url=https://${hostName}/sub/${userID}?format=clash&insert=false&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
    header.push(`\n<p align="center"><img src="https://cloudflare-ipfs.com/ipfs/bafybeigd6i5aavwpr6wvnwuyayklq3omonggta4x2q7kpmgafj357nkcky" alt="图片描述" style="margin-bottom: -50px;">`);
    header.push(`\n<b style=" font-size: 15px;" >Welcome! This function generates configuration for VLESS protocol. If you found this useful, please check our GitHub project for more:</b>\n`);
    header.push(`<b style=" font-size: 15px;" >欢迎！这是生成 VLESS 协议的配置。如果您发现这个项目很好用，请查看我们的 GitHub 项目给我一个star：</b>\n`);
    header.push(`\n<a href="https://github.com/3Kmfi6HP/EDtunnel" target="_blank">EDtunnel - https://github.com/3Kmfi6HP/EDtunnel</a>\n`);
    header.push(`\n<iframe src="https://ghbtns.com/github-btn.html?user=USERNAME&repo=REPOSITORY&type=star&count=true&size=large" frameborder="0" scrolling="0" width="170" height="30" title="GitHub"></iframe>\n\n`.replace(/USERNAME/g, "3Kmfi6HP").replace(/REPOSITORY/g, "EDtunnel"));
    header.push(`<a href="//${hostName}/sub/${userID}" target="_blank">VLESS 节点订阅连接</a>\n<a href="clash://install-config?url=${encodeURIComponent(clash_link)}" target="_blank">Clash 节点订阅连接</a>\n<a href="${clash_link}" target="_blank">Clash 节点订阅连接2</a></p>\n`);
    header.push(``);

    // Generate output string for each userID
    const vlessMain = `vless://${userID}@${hostName}${commonUrlPart}`;
    const vlessSec = `vless://${userID}@${proxyIP}${commonUrlPart}`;
    output.push(`UUID: ${userID}`);
    output.push(`${hashSeparator}\nv2ray default ip\n${separator}\n${vlessMain}\n${separator}`);
    output.push(`${hashSeparator}\nv2ray with best ip\n${separator}\n${vlessSec}\n${separator}`);
    output.push(`${hashSeparator}\n# Clash Proxy Provider 配置格式(configuration format)\nproxy-groups:\n  - name: UseProvider\n	type: select\n	use:\n	  - provider1\n	proxies:\n	  - Proxy\n	  - DIRECT\nproxy-providers:\n  provider1:\n	type: http\n	url: https://${hostName}/sub/${userID}\n	interval: 3600\n	path: ./provider1.yaml\n	health-check:\n	  enable: true\n	  interval: 600\n	  # lazy: true\n	  url: http://www.gstatic.com/generate_204\n\n${hashSeparator}`);

    // HTML Head with CSS
    const htmlHead = `
    <head>
        <title>EDtunnel: VLESS configuration</title>
        <meta name="description" content="This is a tool for generating VLESS protocol configurations. Give us a star on GitHub https://github.com/3Kmfi6HP/EDtunnel if you found it useful!">
		<meta name="keywords" content="EDtunnel, cloudflare pages, cloudflare worker, severless">
        <meta name="viewport" content="width=device-width, initial-scale=1">
		<meta property="og:site_name" content="EDtunnel: VLESS configuration" />
        <meta property="og:type" content="website" />
        <meta property="og:title" content="EDtunnel - VLESS configuration and subscribe output" />
        <meta property="og:description" content="Use cloudflare pages and worker severless to implement vless protocol" />
        <meta property="og:url" content="https://${hostName}/" />
        <meta property="og:image" content="https://api.qrserver.com/v1/create-qr-code/?size=500x500&data=${encodeURIComponent(`vless://${userID}@${hostName}${commonUrlPart}`)}" />
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content="EDtunnel - VLESS configuration and subscribe output" />
        <meta name="twitter:description" content="Use cloudflare pages and worker severless to implement vless protocol" />
        <meta name="twitter:url" content="https://${hostName}/" />
        <meta name="twitter:image" content="https://cloudflare-ipfs.com/ipfs/bafybeigd6i5aavwpr6wvnwuyayklq3omonggta4x2q7kpmgafj357nkcky" />
        <meta property="og:image:width" content="1500" />
        <meta property="og:image:height" content="1500" />

        <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f0f0;
            color: #333;
            padding: 10px;
        }

        a {
            color: #1a0dab;
            text-decoration: none;
        }
		img {
			max-width: 100%;
			height: auto;
		}
		
        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            background-color: #fff;
            border: 1px solid #ddd;
            padding: 15px;
            margin: 10px 0;
        }
		/* Dark mode */
        @media (prefers-color-scheme: dark) {
            body {
                background-color: #333;
                color: #f0f0f0;
            }

            a {
                color: #9db4ff;
            }

            pre {
                background-color: #282a36;
                border-color: #6272a4;
            }
        }
        </style>
    </head>
    `;

    // Join output with newlines, wrap inside <html> and <body>
    return `
    <html>
    ${htmlHead}
    <body>
    <pre style="
    background-color: transparent;
    border: none;
">${header.join('')}</pre><pre>${output.join('\n')}</pre>
    </body>
</html>`;
}