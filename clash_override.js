const proxyName = "♿代理模式";

const commonHealthCheck = {
  url: "http://www.gstatic.com/generate_204",
  interval: 300,
};

const templateAutoSelect = {
  ...commonHealthCheck,
  type: "url-test",
  tolerance: 50,
  hidden: true,
};

const templateLoadBalance = {
  ...commonHealthCheck,
  type: "load-balance",
  "max-failed-times": 3,
  strategy: "round-robin",
  lazy: true,
  hidden: true,
};

// 地区正则配置
const regionRegexList = [
  { name: "HK", regex: /香港|HK|Hong|🇭🇰/ },
  { name: "TW", regex: /台湾|TW|Taiwan|🇹🇼/ },
  { name: "SG", regex: /新加坡|狮城|SG|Singapore|🇸🇬/ },
  { name: "JP", regex: /日本|JP|Japan|🇯🇵/ },
  { name: "US", regex: /美国|美|US|United States|America|🇺🇸/ },
  { name: "KR", regex: /韩国|韩|KR|KOREA|Korea|🇰🇷/ },
  { name: "CA", regex: /加拿大|CA|CANADA|Canada|🇨🇦/ },
  { name: "RU", regex: /俄罗斯|俄|RU|Russia|RUSSIA|🇷🇺/ },
  { name: "UK", regex: /英国|英|UK|Britain|United Kingdom|🇬🇧/ },
];

const ruleProviderUrls = {
  cncidr: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
  direct: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
  gfw: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt",
  lancidr: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt",
  private: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt",
  proxy: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",
  reject: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt",
  telegramcidr: "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt",
  "tld-not-cn": "https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tld-not-cn.txt",
};

const dnsServers = {
  cn: [
    "https://dns.alidns.com/dns-query",
    "https://doh.pub/dns-query"
  ],
  trust: [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query"
  ],
  default: [
    "223.5.5.5",
    "119.29.29.29",
    "223.6.6.6"
  ],
};

function main(params) {
  if (!params || typeof params !== 'object') {
    console.error('[Error] Invalid params object');
    return params;
  }

  if (!params.proxies || !Array.isArray(params.proxies) || params.proxies.length === 0) {
    console.warn('[Warning] No proxies found, skipping configuration override');
    return params;
  }

  try {
    overwriteRules(params);
    overwriteProxyGroups(params);
    overwriteDns(params);
  } catch (error) {
    console.error('[Error] Configuration override failed:', error.message);
  }

  return params;
}

function overwriteRules(params) {
  // 自定义域名规则（可根据需要添加）
  const customDomain = [
    // "DOMAIN,example.com,DIRECT",
    // "DOMAIN-SUFFIX,example.org,DIRECT",
  ];

  const ruleLayers = {
    block: [
      "RULE-SET,reject,REJECT",
      "GEOSITE,category-ads-all,REJECT",
    ],
    custom: customDomain,
    direct: [
      "GEOSITE,private,DIRECT",
      "GEOIP,private,DIRECT,no-resolve",
      "GEOIP,LAN,DIRECT,no-resolve",
      "GEOSITE,geolocation-cn,DIRECT",
      "GEOSITE,cn,DIRECT",
      "GEOIP,CN,DIRECT,no-resolve",
      "RULE-SET,direct,DIRECT",
      "RULE-SET,private,DIRECT",
      "RULE-SET,lancidr,DIRECT,no-resolve",
      "RULE-SET,cncidr,DIRECT,no-resolve",
    ],
    proxy: [
      "RULE-SET,proxy," + proxyName,
      "RULE-SET,tld-not-cn," + proxyName,
      "GEOSITE,geolocation-!cn," + proxyName,
      "GEOSITE,youtube," + proxyName,
      "GEOSITE,twitter," + proxyName,
      "GEOSITE,google," + proxyName,
      "GEOSITE,pixiv," + proxyName,
      "GEOSITE,telegram," + proxyName,
      "GEOSITE,biliintl," + proxyName,
      "RULE-SET,telegramcidr," + proxyName,
      "GEOSITE,category-scholar-!cn," + proxyName,
      "GEOSITE,gfw," + proxyName,
      "RULE-SET,gfw," + proxyName,
    ],
    fallback: [
      "MATCH,🐟漏网之鱼",
    ],
  };

  const rules = Object.values(ruleLayers).flat();

  const ruleProviders = Object.fromEntries(
    Object.entries(ruleProviderUrls).map(([key, url]) => {
      const behavior = key.includes('cidr') ? 'ipcidr' :
                      key === 'tld-not-cn' ? 'classical' : 'domain';
      return [key, {
        type: "http",
        behavior: behavior,
        format: "yaml",
        url: url,
        path: `./ruleset/${key}.yaml`,
        interval: 86400
      }];
    })
  );

  params["rule-providers"] = ruleProviders;
  params["rules"] = rules;
}

function overwriteProxyGroups(params) {
  const allProxies = params.proxies.map((e) => e.name);

  const { regionGroups, unmatchedProxies } = groupProxiesByRegion(params.proxies, regionRegexList);

  const autoProxyGroups = [];
  Object.entries(regionGroups).forEach(([region, proxies]) => {
    if (proxies.length > 1) {
      autoProxyGroups.push({
        name: region + '-AUTO',
        ...templateAutoSelect,
        proxies: proxies,
      });
    } else if (proxies.length === 1) {
      console.log(`[Info] Region ${region} has only one proxy, skipping group creation`);
    }
  });

  if (unmatchedProxies.length > 0) {
    if (unmatchedProxies.length > 1) {
      autoProxyGroups.push({
        name: "Other-AUTO",
        ...templateAutoSelect,
        proxies: unmatchedProxies,
      });
    }
  }

  const autoBalance = autoProxyGroups.map((item) => {
    const region = item.name.split('-')[0];
    return {
      name: region + '-Balance',
      ...templateLoadBalance,
      proxies: [...item.proxies],
    };
  });
  const topLevelGroups = [
    {
      name: proxyName,
      type: "select",
      url: "http://www.gstatic.com/generate_204",
      proxies: [
        "🔁负载均衡(轮询)",
        "🔀负载均衡(散列)",
        "🤖自动选择",
        "🎯手动选择",
        "DIRECT",
      ],
    },
    {
      name: "🎯手动选择",
      type: "select",
      proxies: allProxies,
    },
    {
      name: "🤖自动选择",
      type: "select",
      proxies: ["ALL-自动选择"],
    },
    {
      name: "🔁负载均衡(轮询)",
      type: "select",
      proxies: ["ALL-轮询"],
    },
    {
      name: "🔀负载均衡(散列)",
      type: "load-balance",
      url: "http://www.gstatic.com/generate_204",
      interval: 300,
      "max-failed-times": 3,
      strategy: "consistent-hashing",
      lazy: true,
      proxies: allProxies,
    },
    {
      name: "ALL-轮询",
      type: "load-balance",
      url: "http://www.gstatic.com/generate_204",
      interval: 300,
      "max-failed-times": 3,
      strategy: "round-robin",
      lazy: true,
      proxies: allProxies,
      hidden: true,
    },
    {
      name: "ALL-自动选择",
      type: "url-test",
      url: "http://www.gstatic.com/generate_204",
      interval: 300,
      tolerance: 50,
      proxies: allProxies,
      hidden: true,
    },
    {
      name: "🐟漏网之鱼",
      type: "select",
      proxies: ["DIRECT", proxyName],
      hidden: false,
    },
  ];
  if (autoProxyGroups.length > 0) {
    topLevelGroups[2].proxies.unshift(...autoProxyGroups.map((item) => item.name));
  }
  if (autoBalance.length > 0) {
    topLevelGroups[3].proxies.unshift(...autoBalance.map((item) => item.name));
  }
  const groups = [
    ...topLevelGroups,
    ...autoProxyGroups,
    ...autoBalance,
  ];

  params["proxy-groups"] = groups;
}
function groupProxiesByRegion(proxies, regexList) {
  const regionGroups = Object.fromEntries(regexList.map(r => [r.name, []]));
  const unmatchedProxies = [];

  proxies.forEach(proxy => {
    const proxyName = proxy.name;
    const matched = regexList.find(r => r.regex.test(proxyName));

    if (matched) {
      regionGroups[matched.name].push(proxyName);
    } else {
      unmatchedProxies.push(proxyName);
    }
  });

  return { regionGroups, unmatchedProxies };
}
function overwriteDns(params) {
  // DNS 隐私保护过滤器（扩展版）
  const fakeIpFilter = [
    "+.lan", "+.local", "localhost",
    "+.msftconnecttest.com", "+.msftncsi.com", "www.msftconnecttest.com",

    // STUN 服务（P2P、游戏、WebRTC）
    "*.stun.*", "+.stun.*",
    "localhost.ptlogin2.qq.com", "localhost.sec.qq.com", "localhost.work.weixin.qq.com",
  ];

  const trustedFallbackDomains = [
    "+.google.com", "+.googleapis.com", "+.googlevideo.com", "+.google.dev",
    "+.youtube.com", "+.ytimg.com",
    "+.facebook.com", "+.fbcdn.net", "+.instagram.com", "+.whatsapp.com",
    "+.twitter.com", "+.twimg.com", "+.x.com",
    "+.github.com", "+.githubusercontent.com", "+.githubapp.com",
    "+.cloudflare.com", "+.cloudflare.net", "+.cloudflare-dns.com",
    "+.openai.com", "+.anthropic.com", "+.claude.ai",
    "+.microsoft.com", "+.microsoftapp.net", "+.azure.com", "+.bing.com",
    "+.telegram.org", "+.t.me",
    "+.netflix.com", "+.nflxvideo.net",
    "+.spotify.com", "+.scdn.co",
    "+.docker.com", "+.docker.io",
  ];

  const dnsOptions = {
    "enable": true,
    "ipv6": false,
    "listen": "0.0.0.0:1053",
    "prefer-h3": true,
    "default-nameserver": dnsServers.default,
    "nameserver": dnsServers.trust,
    "use-hosts": false,
    "use-system-hosts": true,
    "respect-rules": true,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "fake-ip-filter": fakeIpFilter,
    "nameserver-policy": {
      "geosite:cn,private,geolocation-cn": dnsServers.cn,
      "geosite:geolocation-!cn,gfw,google,youtube,twitter,facebook,github,telegram": dnsServers.trust,
      ...Object.fromEntries(trustedFallbackDomains.map(domain => [domain, dnsServers.trust])),
    },
    "proxy-server-nameserver": dnsServers.cn,
    "fallback": dnsServers.trust,
    "fallback-filter": {
      "geoip": true,
      "geoip-code": "CN",
      "geosite": ["gfw"],
      "ipcidr": ["240.0.0.0/4", "0.0.0.0/32"],
      "domain": trustedFallbackDomains
    },
  };

  const otherOptions = {
    "unified-delay": true,
    "tcp-concurrent": true,
    "geodata-mode": true,
    profile: {
      "store-selected": true,
      "store-fake-ip": true,
    },
    sniffer: {
      "enable": true,
      "sniff": {
        "TLS": {
          "ports": [443, 8443],
        },
        "HTTP": {
          "ports": [80, "8080-8880"],
          "override-destination": true,
        },
      },
    },
  };

  params.dns = { ...params.dns, ...dnsOptions };
  Object.keys(otherOptions).forEach((key) => {
    params[key] = otherOptions[key];
  });
}
