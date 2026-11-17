/* Same-origin WHOIS UI. Talks only to this deployment's /v1/whois and /multi. */
(function () {
  "use strict";

  var MAX_BATCH = 10;
  var RECENT_KEY = "whois-ui-recent";
  var LANG_KEY = "whois-ui-lang";

  var I18N = {
    zh: {
      title: "wi.fs.kg — 域名 WHOIS 查询",
      desc: "输入域名，一次看清注册状态、注册商、到期日、名称服务器和联系人。RDAP 优先，WHOIS 兜底。免注册、无广告、无追踪脚本。",
      "nav.lookup": "查询",
      "nav.record": "档案",
      "nav.ns": "服务器",
      "nav.batch": "批量",
      "nav.api": "接口",
      "nav.docs": "文档",
      "nav.contact": "联系",
      "nav.dns": "DNS",
      "lang.aria": "切换到英文",
      "lang.btn": "EN",
      eyebrow: "WHOIS LOOKUP · 免注册 · 无广告",
      "h1.l1": "查一个域名，",
      "h1.a": "归属、",
      "h1.b": "状态、",
      "h1.c": "到期日",
      "h1.l3": "一次搞定。",
      "tag.main": "WHOIS Lookup",
      "tag.sub": "注册、注册商与到期，一次看清。",
      lede: "输入域名即可。优先查询 RDAP，这个后缀没有 RDAP 时再退回 WHOIS，两边都收成同一套字段。没有广告，没有追踪脚本，也不需要注册。命令行直接请求",
      "label.q": "域名",
      ph: "example.com",
      "btn.clear": "清空",
      "btn.search": "查询",
      "btn.searching": "查询中…",
      "chips.label": "试试",
      recent: "最近",
      "recent.clear": "清除",
      "status.idle": "输入域名，或点下面任一示例。",
      "status.loading": "正在向注册局查询…",
      "status.done": "已展开 {domain}",
      "bar.wait": "等待查询",
      "snap.title": "域名速览",
      "snap.badge.wait": "等待查询",
      "snap.badge.loading": "读取中",
      "snap.copy": "复制速览",
      "snap.fine": "字段来自本站 /v1/whois 的归一化结果。联系人常被注册局隐去，隐去时会标明，不用空值冒充「查无此人」。",
      "snap.sub.wait": "查询后这里摊开注册状态",
      "snap.f.status": "注册状态",
      "snap.f.registrar": "注册商",
      "snap.f.created": "创建日期",
      "snap.f.expires": "到期日期",
      "snap.f.source": "数据来源",
      "snap.f.tld": "顶级域",
      "record.title": "注册档案",
      "record.copy": "复制",
      "record.json": "JSON",
      "record.empty.title": "还没有查询目标",
      "record.empty": "输入一个域名，或点上方任意一个示例。",
      "record.domain": "域名",
      "record.unicode": "Unicode",
      "record.id": "注册局 ID",
      "record.tld": "顶级域",
      "record.registered": "注册状态",
      "record.registrar": "注册商",
      "record.iana": "IANA ID",
      "record.url": "注册商网址",
      "record.whois": "WHOIS 服务器",
      "record.reseller": "经销商",
      "record.abuseEmail": "滥用邮箱",
      "record.abusePhone": "滥用电话",
      "record.created": "创建",
      "record.updated": "更新",
      "record.expires": "到期",
      "record.statuses": "状态码",
      "record.statuses.hint": "EPP 状态，右侧是原文",
      "record.noStatus": "上游没有返回状态码",
      "ns.title": "名称服务器",
      "ns.empty": "查询后这里列出委派的名称服务器。",
      "ns.none": "这份结果里没有名称服务器。",
      "dnssec.wait": "查询后显示 DNSSEC",
      "dnssec.on": "DNSSEC 已签名",
      "dnssec.off": "DNSSEC 未签名",
      "dnssec.detail.on": "注册局返回了签名信息。",
      "dnssec.detail.off": "没有看到 DS 记录，或上游标明未签名。",
      "dnssec.ns": "名称服务器",
      "dnssec.ds": "DS 记录",
      "contacts.title": "联系人",
      "contacts.empty": "查询后按角色列出联系人。被隐去的会单独标明。",
      "contacts.redacted": "已隐去",
      "contacts.none": "没有公开字段",
      "role.registrant": "注册人",
      "role.admin": "管理联系人",
      "role.tech": "技术联系人",
      "role.billing": "账单联系人",
      "c.name": "姓名",
      "c.org": "组织",
      "c.email": "邮箱",
      "c.phone": "电话",
      "c.addr": "地址",
      "batch.title": "批量查询",
      "batch.help": "一次粘贴多个域名（换行、逗号或空格分隔均可），最多 10 个。这是服务端 /multi 的默认上限，公开部署上还有按 IP 的速率限制。",
      "batch.ph": "example.com\ngithub.com\nwikipedia.org",
      "batch.run": "解析并查询",
      "batch.running": "查询中…",
      "batch.csv": "导出 CSV",
      "batch.clear": "清空",
      "batch.empty": "结果表会在第一次批量查询后出现。",
      "batch.trim": "超过 10 个，只查了前 10 个。",
      "batch.need": "先贴几个域名。",
      "th.domain": "域名",
      "th.status": "状态",
      "th.registrar": "注册商",
      "th.expires": "到期",
      "th.source": "来源",
      "api.title": "终端接口",
      "api.badge": "无需密钥",
      "api.lede": "页面和接口在同一部署上。浏览器打开根路径看到这个界面；curl 打下面的路径拿到 JSON。不需要 API key，响应带 CORS。",
      "api.n1": "单条查询走 <code class=\"path\">/v1/whois/{domain}</code>，裸路径 <code class=\"path\">/{domain}</code> 也行。加上 <code class=\"path\">?raw=true</code> 返回上游 RDAP JSON 或 WHOIS 原文。",
      "api.n2": "批量用 <code class=\"path\">/multi?domains=a.com,b.com</code>。默认最多 10 个，可用环境变量 <code class=\"path\">MAX_DOMAINS</code> 调整。",
      "api.n3": "完整字段说明在 <code class=\"path\">/docs</code>。OpenAPI 规范在 <code class=\"path\">/openapi.yaml</code>。",
      "about.title": "数据与限制",
      "about.n1": "先问 RDAP。只有这个后缀没有 RDAP 服务器时，才退回端口 43 的 WHOIS。",
      "about.n2": "两种来源收成同一套字段：是否注册、注册商、日期、状态码、名称服务器、DNSSEC、联系人。",
      "about.n3": "速率看部署方式。放在 Vercel 上时，匿名访问默认大约每分钟 30 次。",
      "about.n4": "这是注册信息，不是「这个站安不安全」的结论。页面不加载广告或统计脚本。",
      "faq.title": "常见问题",
      "faq.q1": "怎么查一个域名的注册信息？",
      "faq.a1": "在上方输入域名，例如 example.com，或点一个示例。也接受带 https:// 的地址，服务端会先剥掉协议和路径。页面请求本站的 /v1/whois/{domain}，把注册状态、注册商、日期、名称服务器和联系人摊开。",
      "faq.q2": "为什么联系人经常是空的？",
      "faq.a2": "多数注册局按隐私规则隐去个人联系信息，通用顶级域尤其常见。隐去时这一格会写「已隐去」。那是注册局的选择，不是查询失败。",
      "faq.q3": "可以在命令行里查吗？",
      "faq.a3": "可以，不需要密钥。请求 <code class=\"path\">/v1/whois/example.com</code> 得到归一化 JSON；加上 <code class=\"path\">?raw=true</code> 则是上游原文。多个域名用 <code class=\"path\">/multi?domains=a.com,b.com</code>。完整地址在上面的终端示例里。浏览器访问根路径仍然是这个页面。",
      "faq.q4": "会记录我查过什么吗？",
      "faq.a4": "页面没有第三方统计。「最近」列表只存在你这台浏览器的本地存储里，可以在上面一键清除。服务端可以开内存缓存，用来少打注册局，缓存的是查询结果，不是一份用户档案。",
      "foot.blurb": "域名注册信息",
      "foot.privacy": "无广告 · 无追踪",
      "due.title": "到期倒计时",
      "due.badge.wait": "等待查询",
      "due.badge.active": "生效中",
      "due.badge.expired": "已过期",
      "due.badge.none": "无到期日",
      "due.empty": "查询后这里按「注册 → 到期」的比例画出已过去的时长，并给出现在距离到期还有多久。",
      "due.remaining": "剩余时间",
      "due.elapsed": "已过去",
      "due.expired": "已过期",
      "due.from": "注册",
      "due.to": "到期",
      "due.days": "天",
      "due.noExpiry": "这条记录没有到期日（例如永久注册），没有倒计时可画。",
      "due.notRegistered": "这个域名未注册，没有到期日。",
      "due.suspended": "解析已暂停",
      "due.active": "解析正常",
      "source.title": "查询来源",
      "source.badge.wait": "等待查询",
      "source.empty": "查询后这里显示实际命中的注册局端点，以及这一跳花了多久、走的什么协议。",
      "source.endpoint": "命中端点",
      "source.elapsed": "耗时",
      "source.proto": "协议",
      "source.whois": "WHOIS 服务",
      "source.fetched": "抓取时间",
      "source.bytes": "原文大小",
      "source.protoRdap": "RDAP · HTTPS",
      "source.protoWhois": "WHOIS · 43",
      "source.noEndpoint": "这个后缀没有可用的注册局端点",
      "source.noEndpointBody": "注册局没有为它开机器可读接口，RDAP 和 WHOIS 都问不到。这不是「未注册」，是不支持查询。",
      "source.notFound": "注册局返回 404，没有这条记录",
      "source.notFoundBody": "可能代表未注册，也可能是注册局保留域名，或刚被删除还在赎回期。要确认可注册性，得去注册商的实时下单接口。",
      "source.platform": "这个名字在平台的命名空间里",
      "source.platformBody": "注册局只登记到父域那层，这条记录只在平台内部，要去平台后台查。",
      "source.platformLookup": "去平台查询",
      "source.platformNoLookup": "这个平台没有公开的查询接口",
      "tl.title": "事件时间线",
      "tl.empty": "查询后按时间正序列出注册、变更、转移、到期这些节点，并标出距离现在多久。",
      "tl.count": "{n} 个节点",
      "ev.registration": "注册",
      "ev.lastChanged": "最后变更",
      "ev.expiration": "到期",
      "ev.transfer": "转移",
      "ev.reregistration": "重新注册",
      "ev.dbUpdate": "注册局数据库更新",
      "ev.lastUpdate": "最后更新",
      "ev.unknown": "事件",
      "mean.title": "状态码含义",
      "mean.fine": "client* 是注册商侧的动作，server* 是注册局侧的动作；带 prohibited 的多为保护性锁，带 hold 的才是解析被停。",
      "mean.wait": "查询后这里逐条解释注册局返回的状态码。",
      "mean.empty": "上游没有返回状态码，这里也就没有可解释的。",
      "price.title": "参考价格",
      "price.help": "这个后缀在注册商处的注册、续费、转入报价，三个环节各自取当前最便宜的一家，所以很可能分属三家注册商 —— 这不是一个能照价一次买完的方案。",
      "price.wait": "查询域名后，这里显示这个后缀的注册、续费、转入最便宜报价。",
      "price.order.register": "注册",
      "price.order.renew": "续费",
      "price.order.transfer": "转入",
      "price.noQuote": "无报价",
      "price.noQuoteHint": "这家比价站没收录这个环节",
      "price.std": "标准",
      "price.coupon": "券",
      "price.limit": "限 {n} 次",
      "price.newUser": "仅限新用户",
      "price.at": "采于",
      "price.uncovered": "未收录",
      "price.fail": "价格数据没有取到（这不影响上面的注册局记录）。",
      "price.empty": "这家比价站还没有收录 .{tld} 的报价 —— 它收了上百家注册商、几千个后缀，但确实不是全部。",
      "price.fine": "价格来自哪煮米收录的注册商公开挂牌价；人民币由上游按参考汇率折算，券后价与标准价都按上游记录。最终以注册商结算页为准。",
      "price.loading": "查比价中…",
      "price.copy": "点击复制券码",
      "raw.title": "上游原文",
      "raw.help": "注册局回来的原文（RDAP JSON 或 WHOIS 文本），字段一个不改 —— 上面所有结论都能对着它核。",
      "raw.copy": "复制原文",
      "raw.download": "下载",
      "raw.empty": "查询后这里放注册局回来的原文。",
      "raw.loading": "取原文中…",
      "raw.kindRdap": "RDAP JSON",
      "raw.kindWhois": "WHOIS 文本",
      "raw.bytes": "{n} 字节",
      "rel.past": "{n} {u}前",
      "rel.future": "{n} {u}后",
      "rel.min": "分钟",
      "rel.hour": "小时",
      "rel.day": "天",
      "rel.month": "个月",
      "rel.year": "年",
      "err.PLATFORM_NAMESPACE": "这个名字在 {platform} 的平台命名空间里，注册局不登记这条记录，请去平台后台查",
      "reg.yes": "已注册",
      "reg.no": "未注册",
      "source.rdap": "RDAP",
      "source.whois": "WHOIS",
      cached: "来自缓存",
      copied: "已复制",
      copyfail: "复制失败",
      "json.need": "还没有可以展开的结果",
      "json.hide": "收起",
      "err.EMPTY": "先输入一个域名",
      "err.INVALID_DOMAIN": "没能认出这是一个可注册的域名",
      "err.UNSUPPORTED_TLD": "这个后缀没有 RDAP，WHOIS 也没能查到",
      "err.RATE_LIMITED": "查询太频繁，稍后再试",
      "err.UPSTREAM_ERROR": "注册局暂时没有返回有效数据",
      "err.UPSTREAM_TIMEOUT": "注册局超时了",
      "err.INTERNAL_ERROR": "服务暂时出错",
      "err.UNAUTHORIZED": "这个部署开启了访问密钥",
      "err.NETWORK": "网络请求失败，请重试",
      "err.generic": "查询失败",
      "curl.c1": "归一化 JSON",
      "curl.c2": "上游原文",
      "curl.c3": "一次查多个",
      "sum.registered": "注册状态",
      "sum.registrar": "注册商",
      "sum.created": "创建",
      "sum.updated": "更新",
      "sum.expires": "到期",
      "sum.ns": "名称服务器",
      "sum.source": "来源",
      "sum.statuses": "状态码"
    },
    en: {
      title: "wi.fs.kg — Domain WHOIS lookup",
      desc: "Look up registration status, registrar, dates, nameservers, and contacts for a domain. RDAP first, WHOIS fallback. No account, no ads, no tracking.",
      "nav.lookup": "Lookup",
      "nav.record": "Record",
      "nav.ns": "Servers",
      "nav.batch": "Batch",
      "nav.api": "API",
      "nav.docs": "Docs",
      "nav.contact": "Contact",
      "nav.dns": "DNS",
      "lang.aria": "切换到中文",
      "lang.btn": "中文",
      eyebrow: "WHOIS LOOKUP · NO SIGNUP · NO ADS",
      "h1.l1": "Look up a domain.",
      "h1.a": "owner,",
      "h1.b": "status,",
      "h1.c": "expiry",
      "h1.l3": "in one view.",
      "tag.main": "WHOIS Lookup",
      "tag.sub": "Registrar, status, and expiry, opened up together.",
      lede: "Type a domain. RDAP is queried first; WHOIS on port 43 is the fallback when a suffix has no RDAP server. Both come back as the same fields. No ads, no tracking scripts, no account. From the shell, request",
      "label.q": "Domain",
      ph: "example.com",
      "btn.clear": "Clear",
      "btn.search": "Look up",
      "btn.searching": "Looking…",
      "chips.label": "Try",
      recent: "Recent",
      "recent.clear": "Clear",
      "status.idle": "Enter a domain, or pick an example.",
      "status.loading": "Asking the registry…",
      "status.done": "Opened {domain}",
      "bar.wait": "Waiting",
      "snap.title": "Domain brief",
      "snap.badge.wait": "Waiting",
      "snap.badge.loading": "Reading",
      "snap.copy": "Copy brief",
      "snap.fine": "Fields come from this site's normalized /v1/whois response. Contacts are often redacted by the registry; redaction is labeled, not shown as a failed lookup.",
      "snap.sub.wait": "Registration status lands here",
      "snap.f.status": "Status",
      "snap.f.registrar": "Registrar",
      "snap.f.created": "Created",
      "snap.f.expires": "Expires",
      "snap.f.source": "Source",
      "snap.f.tld": "TLD",
      "record.title": "Registration",
      "record.copy": "Copy",
      "record.json": "JSON",
      "record.empty.title": "Nothing looked up yet",
      "record.empty": "Enter a domain, or pick an example above.",
      "record.domain": "Domain",
      "record.unicode": "Unicode",
      "record.id": "Registry ID",
      "record.tld": "TLD",
      "record.registered": "Status",
      "record.registrar": "Registrar",
      "record.iana": "IANA ID",
      "record.url": "Registrar URL",
      "record.whois": "WHOIS server",
      "record.reseller": "Reseller",
      "record.abuseEmail": "Abuse email",
      "record.abusePhone": "Abuse phone",
      "record.created": "Created",
      "record.updated": "Updated",
      "record.expires": "Expires",
      "record.statuses": "Status codes",
      "record.statuses.hint": "EPP status, raw code on the right",
      "record.noStatus": "The upstream response had no status codes",
      "ns.title": "Nameservers",
      "ns.empty": "Delegated nameservers show up here after a lookup.",
      "ns.none": "This result did not include nameservers.",
      "dnssec.wait": "DNSSEC after a lookup",
      "dnssec.on": "DNSSEC signed",
      "dnssec.off": "DNSSEC not signed",
      "dnssec.detail.on": "The registry reported a signed delegation.",
      "dnssec.detail.off": "No DS records, or the upstream marked the zone unsigned.",
      "dnssec.ns": "Nameservers",
      "dnssec.ds": "DS records",
      "contacts.title": "Contacts",
      "contacts.empty": "Contacts are listed by role after a lookup. Redacted roles are labeled.",
      "contacts.redacted": "Redacted",
      "contacts.none": "No public fields",
      "role.registrant": "Registrant",
      "role.admin": "Admin",
      "role.tech": "Tech",
      "role.billing": "Billing",
      "c.name": "Name",
      "c.org": "Organization",
      "c.email": "Email",
      "c.phone": "Phone",
      "c.addr": "Address",
      "batch.title": "Batch lookup",
      "batch.help": "Paste domains separated by newlines, commas, or spaces. Up to 10, which is the server's default MAX_DOMAINS. Public deploys also rate-limit by IP.",
      "batch.ph": "example.com\ngithub.com\nwikipedia.org",
      "batch.run": "Resolve",
      "batch.running": "Looking…",
      "batch.csv": "Export CSV",
      "batch.clear": "Clear",
      "batch.empty": "The table fills in after the first batch lookup.",
      "batch.trim": "More than 10 domains; only the first 10 were queried.",
      "batch.need": "Paste a few domains first.",
      "th.domain": "Domain",
      "th.status": "Status",
      "th.registrar": "Registrar",
      "th.expires": "Expires",
      "th.source": "Source",
      "api.title": "Terminal API",
      "api.badge": "No key",
      "api.lede": "The page and the API are the same deployment. A browser at the root gets this UI; curl against the paths below gets JSON. No API key. CORS is open.",
      "api.n1": "One domain: <code class=\"path\">/v1/whois/{domain}</code>. The bare <code class=\"path\">/{domain}</code> path works too. <code class=\"path\">?raw=true</code> returns the upstream RDAP JSON or WHOIS text.",
      "api.n2": "Batch: <code class=\"path\">/multi?domains=a.com,b.com</code>. The default cap is 10, changeable with <code class=\"path\">MAX_DOMAINS</code>.",
      "api.n3": "Field reference lives at <code class=\"path\">/docs</code>. The OpenAPI document is <code class=\"path\">/openapi.yaml</code>.",
      "about.title": "Data & limits",
      "about.n1": "RDAP first. Port-43 WHOIS is only used when the suffix has no RDAP server.",
      "about.n2": "Both sources are normalized: registration, registrar, dates, status codes, nameservers, DNSSEC, contacts.",
      "about.n3": "Rate limits depend on the deploy. On Vercel, anonymous traffic defaults to about 30 requests a minute.",
      "about.n4": "This is registration data, not a verdict on whether a site is safe. The page loads no ads and no analytics.",
      "faq.title": "FAQ",
      "faq.q1": "How do I look up a domain?",
      "faq.a1": "Type a domain such as example.com, or pick an example. URLs are fine — the server strips the scheme and path. The page calls this site's /v1/whois/{domain} and lays out status, registrar, dates, nameservers, and contacts.",
      "faq.q2": "Why are contacts often empty?",
      "faq.a2": "Most registries redact personal contact data, especially on generic TLDs. A redacted role is labeled. That is the registry's choice, not a failed lookup.",
      "faq.q3": "Can I use this from the shell?",
      "faq.a3": "Yes, with no key. <code class=\"path\">/v1/whois/example.com</code> returns normalized JSON; <code class=\"path\">?raw=true</code> returns the upstream payload. Several domains: <code class=\"path\">/multi?domains=a.com,b.com</code>. The terminal block above shows the absolute URL for this host. A browser at the root still gets this page.",
      "faq.q4": "Do you store what I look up?",
      "faq.a4": "There is no third-party analytics. The recent list lives only in this browser and can be cleared above. The server may keep an in-memory cache of lookup results so it hits registries less often. That cache is not a user profile.",
      "foot.blurb": "Domain registration",
      "foot.privacy": "No ads · no tracking",
      "due.title": "Expiry countdown",
      "due.badge.wait": "Waiting",
      "due.badge.active": "Active",
      "due.badge.expired": "Expired",
      "due.badge.none": "No expiry",
      "due.empty": "After a lookup, the time from registration to expiry is drawn to scale, with the time left.",
      "due.remaining": "Time remaining",
      "due.elapsed": "elapsed",
      "due.expired": "Expired",
      "due.from": "Registered",
      "due.to": "Expires",
      "due.days": "days",
      "due.noExpiry": "This record has no expiry date (for example a permanent registration), so there is no countdown.",
      "due.notRegistered": "This domain is not registered, so there is no expiry date.",
      "due.suspended": "Resolution suspended",
      "due.active": "Resolving normally",
      "source.title": "Query source",
      "source.badge.wait": "Waiting",
      "source.empty": "After a lookup, the registry endpoint actually hit, how long it took, and the protocol used.",
      "source.endpoint": "Endpoint",
      "source.elapsed": "Elapsed",
      "source.proto": "Protocol",
      "source.whois": "WHOIS service",
      "source.fetched": "Fetched at",
      "source.bytes": "Payload size",
      "source.protoRdap": "RDAP · HTTPS",
      "source.protoWhois": "WHOIS · 43",
      "source.noEndpoint": "No registry endpoint for this suffix",
      "source.noEndpointBody": "The registry publishes no machine-readable interface for it, so neither RDAP nor WHOIS can answer. That is not “unregistered”; it is unsupported.",
      "source.notFound": "Registry returned 404: no record",
      "source.notFoundBody": "It may be unregistered, or a registry-reserved name, or a name in its redemption period. Confirm availability at a registrar's live checkout.",
      "source.platform": "This name lives in a platform namespace",
      "source.platformBody": "The registry only records the parent domain; this record lives inside the platform. Check the platform's own records.",
      "source.platformLookup": "Check at the platform",
      "source.platformNoLookup": "This platform publishes no public lookup",
      "tl.title": "Event timeline",
      "tl.empty": "After a lookup, registration, changes, transfers, and expiry are listed oldest first, each with its distance from now.",
      "tl.count": "{n} events",
      "ev.registration": "Registration",
      "ev.lastChanged": "Last changed",
      "ev.expiration": "Expiration",
      "ev.transfer": "Transfer",
      "ev.reregistration": "Re-registration",
      "ev.dbUpdate": "Registry database update",
      "ev.lastUpdate": "Last update",
      "ev.unknown": "Event",
      "mean.title": "What the status codes mean",
      "mean.fine": "client* is the registrar's side, server* is the registry's side. Most “prohibited” codes are protective locks; “hold” means resolution is suspended.",
      "mean.wait": "After a lookup, each status code from the registry is explained here.",
      "mean.empty": "The upstream returned no status codes, so there is nothing to explain.",
      "price.title": "Reference prices",
      "price.help": "Registration, renewal, and transfer prices for this suffix, each from the cheapest registrar right now — so the three may belong to three different registrars. That is not a single checkout.",
      "price.wait": "Look up a domain and the cheapest register, renew, and transfer prices for its suffix show up here.",
      "price.order.register": "Register",
      "price.order.renew": "Renew",
      "price.order.transfer": "Transfer",
      "price.noQuote": "No quote",
      "price.noQuoteHint": "This comparison site has no price for this step",
      "price.std": "List",
      "price.coupon": "Coupon",
      "price.limit": "{n} uses",
      "price.newUser": "New customers only",
      "price.at": "collected",
      "price.uncovered": "Not covered",
      "price.fail": "Price data did not come back (the registry record above is unaffected).",
      "price.empty": "This comparison site does not list prices for .{tld} yet — it covers over a hundred registrars and thousands of suffixes, but not all of them.",
      "price.fine": "Prices are public registrar lists collected by nazhumi.com; CNY figures use its reference conversion, and coupon and list prices are as recorded upstream. The registrar's checkout page is final.",
      "price.loading": "Checking prices…",
      "price.copy": "Click to copy the coupon code",
      "raw.title": "Upstream payload",
      "raw.help": "The registry's own response (RDAP JSON or WHOIS text), verbatim — every conclusion above can be checked against it.",
      "raw.copy": "Copy raw",
      "raw.download": "Download",
      "raw.empty": "The registry's raw response lands here after a lookup.",
      "raw.loading": "Fetching the raw response…",
      "raw.kindRdap": "RDAP JSON",
      "raw.kindWhois": "WHOIS text",
      "raw.bytes": "{n} bytes",
      "rel.past": "{n} {u} ago",
      "rel.future": "in {n} {u}",
      "rel.min": "minute",
      "rel.hour": "hour",
      "rel.day": "day",
      "rel.month": "month",
      "rel.year": "year",
      "err.PLATFORM_NAMESPACE": "This name sits in {platform}'s platform namespace; the registry does not record it. Check the platform instead",
      "reg.yes": "Registered",
      "reg.no": "Not registered",
      "source.rdap": "RDAP",
      "source.whois": "WHOIS",
      cached: "Cached",
      copied: "Copied",
      copyfail: "Could not copy",
      "json.need": "Nothing to expand yet",
      "json.hide": "Hide",
      "err.EMPTY": "Enter a domain first",
      "err.INVALID_DOMAIN": "That is not a registrable domain",
      "err.UNSUPPORTED_TLD": "No RDAP server for this suffix, and WHOIS did not answer",
      "err.RATE_LIMITED": "Too many lookups. Try again shortly.",
      "err.UPSTREAM_ERROR": "The registry did not return a usable response",
      "err.UPSTREAM_TIMEOUT": "The registry timed out",
      "err.INTERNAL_ERROR": "The service hit an error",
      "err.UNAUTHORIZED": "This deploy requires an API key",
      "err.NETWORK": "The request failed. Try again.",
      "err.generic": "Lookup failed",
      "curl.c1": "Normalized JSON",
      "curl.c2": "Upstream payload",
      "curl.c3": "Several domains",
      "sum.registered": "Status",
      "sum.registrar": "Registrar",
      "sum.created": "Created",
      "sum.updated": "Updated",
      "sum.expires": "Expires",
      "sum.ns": "Nameservers",
      "sum.source": "Source",
      "sum.statuses": "Status codes"
    }
  };

  var STATUS_GLOSS = {
    ok: { zh: "正常", en: "OK" },
    inactive: { zh: "未激活", en: "Inactive" },
    clientTransferProhibited: { zh: "禁止转移", en: "Transfer locked" },
    clientDeleteProhibited: { zh: "禁止删除", en: "Delete locked" },
    clientUpdateProhibited: { zh: "禁止更新", en: "Update locked" },
    clientRenewProhibited: { zh: "禁止续费", en: "Renew locked" },
    clientHold: { zh: "注册商暂停", en: "Client hold" },
    serverTransferProhibited: { zh: "注册局禁止转移", en: "Registry transfer lock" },
    serverDeleteProhibited: { zh: "注册局禁止删除", en: "Registry delete lock" },
    serverUpdateProhibited: { zh: "注册局禁止更新", en: "Registry update lock" },
    serverRenewProhibited: { zh: "注册局禁止续费", en: "Registry renew lock" },
    serverHold: { zh: "注册局暂停", en: "Server hold" },
    pendingDelete: { zh: "等待删除", en: "Pending delete" },
    pendingTransfer: { zh: "等待转移", en: "Pending transfer" },
    pendingUpdate: { zh: "等待更新", en: "Pending update" },
    pendingCreate: { zh: "等待创建", en: "Pending create" },
    pendingRenew: { zh: "等待续费", en: "Pending renew" },
    pendingRestore: { zh: "等待恢复", en: "Pending restore" },
    redemptionPeriod: { zh: "赎回期", en: "Redemption" },
    addPeriod: { zh: "新增宽限期", en: "Add grace" },
    autoRenewPeriod: { zh: "自动续费宽限期", en: "Auto-renew grace" },
    renewPeriod: { zh: "续费宽限期", en: "Renew grace" },
    transferPeriod: { zh: "转移宽限期", en: "Transfer grace" }
  };

  var state = {
    lang: "zh",
    loading: false,
    result: null,
    error: null,
    showJson: false,
    recent: [],
    batch: [],
    batchLoading: false,
    batchError: null,
    batchTrim: false,
    price: null,       // {loading, data, error} for the /api/price card
    priceSeq: 0,
    rawText: "",
    rawKind: "",
    rawLoading: false
  };
  var ctrl = null;
  var toastTimer = 0;

  function $(id) { return document.getElementById(id); }

  function el(tag, attrs, kids) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v == null || v === false) return;
        if (k === "class") node.className = v;
        else if (k === "text") node.textContent = v;
        else node.setAttribute(k, v);
      });
    }
    (kids || []).forEach(function (kid) {
      if (kid == null || kid === false) return;
      node.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    });
    return node;
  }

  function t(key) {
    var pack = I18N[state.lang] || I18N.zh;
    return Object.prototype.hasOwnProperty.call(pack, key) ? pack[key] : key;
  }

  function dash(v) {
    return v == null || v === "" ? "—" : String(v);
  }

  function fmtDate(iso) {
    if (!iso || iso.indexOf("0001-01-01") === 0) return "";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    var formatted = new Intl.DateTimeFormat(state.lang === "en" ? "en-GB" : "zh-CN", {
      year: "numeric",
      month: "short",
      day: "numeric",
      timeZone: "UTC"
    }).format(d);
    return formatted + " UTC";
  }

  function gloss(code) {
    var row = STATUS_GLOSS[code];
    if (!row) return "";
    return state.lang === "en" ? row.en : row.zh;
  }

  function statusTone(code) {
    var k = String(code || "").toLowerCase();
    if (k === "ok" || k === "active") return "ok";
    if (k.indexOf("hold") >= 0 || k.indexOf("pending") >= 0 || k.indexOf("redemption") >= 0) return "warn";
    return "";
  }

  /* Full-sentence explanations for each EPP status, keyed by canonical code.
     The record card keeps the two-word gloss; this table is the long form. */
  var STATUS_MEAN = {
    ok: { zh: "域名正常生效，没有额外限制。", en: "Domain is live with no extra restrictions." },
    active: { zh: "域名正常生效，解析可用。", en: "Domain is live and resolvable." },
    inactive: { zh: "域名未配置可用的域名服务器，解析不通。", en: "No working nameservers configured; it will not resolve." },
    clientTransferProhibited: { zh: "注册商侧禁止转移：别人不能把它未经你同意转出。这是好事，新注册和刚续费的域名普遍带着它。", en: "Registrar-side transfer lock: nobody can move it away without you. This is good — most new and recently renewed names carry it." },
    clientDeleteProhibited: { zh: "注册商侧禁止删除。", en: "Registrar-side delete lock." },
    clientUpdateProhibited: { zh: "注册商侧禁止修改注册信息。", en: "Registrar-side update lock." },
    clientRenewProhibited: { zh: "注册商侧禁止续费（通常由到期流程控制）。", en: "Registrar-side renew lock (usually managed by the expiry flow)." },
    clientHold: { zh: "注册商暂停了解析：域名不解析，一般是欠费或争议处理中。", en: "Registrar suspended resolution — typically non-payment or a dispute." },
    serverTransferProhibited: { zh: "注册局侧禁止转移（ccTLD 常见，锁得更死）。", en: "Registry-side transfer lock (common on ccTLDs)." },
    serverDeleteProhibited: { zh: "注册局侧禁止删除。", en: "Registry-side delete lock." },
    serverUpdateProhibited: { zh: "注册局侧禁止修改。", en: "Registry-side update lock." },
    serverRenewProhibited: { zh: "注册局侧禁止续费。", en: "Registry-side renew lock." },
    serverHold: { zh: "注册局暂停了解析，通常因为合规或争议。", en: "Registry suspended resolution, usually compliance or a dispute." },
    pendingDelete: { zh: "已进入删除流程，到期后会被释放。", en: "In the delete flow; the name will be released." },
    pendingTransfer: { zh: "正在转移中，等待注册局完成。", en: "Transfer in progress, awaiting the registry." },
    pendingUpdate: { zh: "更新流程处理中。", en: "Update in progress." },
    pendingCreate: { zh: "注册流程处理中。", en: "Creation in progress." },
    pendingRenew: { zh: "续费流程处理中。", en: "Renewal in progress." },
    pendingRestore: { zh: "正在从赎回期恢复。", en: "Being restored from redemption." },
    redemptionPeriod: { zh: "赎回期：已过期并被申请删除，原持有人仍可付费赎回。", en: "Redemption: expired and queued for deletion, still recoverable for a fee." },
    addPeriod: { zh: "新注册后的初始期。", en: "Initial period right after registration." },
    autoRenewPeriod: { zh: "自动续费后的 45 天宽限期，仍可退款取消。", en: "45-day grace window after auto-renew, still cancellable." },
    renewPeriod: { zh: "续费后的宽限期。", en: "Grace window after renewal." },
    transferPeriod: { zh: "转移后的宽限期。", en: "Grace window after transfer." },
    locked: { zh: "被注册局或注册商锁定。", en: "Locked by the registry or registrar." },
    reserved: { zh: "被注册局保留，不对外注册。", en: "Reserved by the registry, not registrable." },
    transferProhibited: { zh: "禁止转移。", en: "Transfer prohibited." }
  };

  function statusMean(code) {
    var row = STATUS_MEAN[code];
    if (!row) return "";
    return state.lang === "en" ? row.en : row.zh;
  }

  function statusKey(s) {
    return String(s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  }

  function evLabel(action) {
    var a = String(action || "").toLowerCase();
    if (a === "registration") return t("ev.registration");
    if (a === "expiration") return t("ev.expiration");
    if (a === "last changed") return t("ev.lastChanged");
    if (a === "transfer") return t("ev.transfer");
    if (a === "reregistration") return t("ev.reregistration");
    if (a.indexOf("rdap database") > -1) return t("ev.dbUpdate");
    if (a.indexOf("last update") > -1) return t("ev.lastUpdate");
    return action || t("ev.unknown");
  }

  function fmtRel(iso) {
    if (!iso) return "";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    var diff = d.getTime() - Date.now();
    var abs = Math.abs(diff);
    var n, unit;
    if (abs < 3600e3) { n = Math.max(1, Math.round(abs / 60e3)); unit = t("rel.min"); }
    else if (abs < 86400e3) { n = Math.max(1, Math.round(abs / 3600e3)); unit = t("rel.hour"); }
    else if (abs < 2592e6) { n = Math.max(1, Math.round(abs / 86400e3)); unit = t("rel.day"); }
    else if (abs < 31536e6) { n = Math.max(1, Math.round(abs / 2592e6)); unit = t("rel.month"); }
    else { n = Math.max(1, Math.round(abs / 31536e6)); unit = t("rel.year"); }
    if (state.lang === "en" && n !== 1 && unit !== "day") unit += "s";
    if (state.lang === "en" && n !== 1 && unit === "day") unit = "days";
    var tpl = diff < 0 ? t("rel.past") : t("rel.future");
    return tpl.replace("{n}", String(n)).replace("{u}", unit);
  }

  function fmtDateTime(iso) {
    if (!iso || iso.indexOf("0001-01-01") === 0) return "";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return new Intl.DateTimeFormat(state.lang === "en" ? "en-GB" : "zh-CN", {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit", timeZone: "UTC"
    }).format(d) + " UTC";
  }

  function money(n) {
    if (n == null || !isFinite(n)) return null;
    return Number(n).toFixed(2).replace(/\.00$/, "").replace(/(\.\d)0$/, "$1");
  }

  function safeHttp(url) {
    try {
      var u = new URL(url);
      if (u.protocol === "http:" || u.protocol === "https:") return u.href;
    } catch (e) { /* not a URL */ }
    return "";
  }

  function linkOrText(url) {
    if (!url) return "";
    var href = safeHttp(url);
    if (!href) return url;
    return el("a", { href: href, target: "_blank", rel: "noopener noreferrer", text: url });
  }

  function mailLink(addr) {
    if (!addr) return "";
    if (!/^[^@\s]+@[^@\s]+$/.test(addr)) return addr;
    return el("a", { href: "mailto:" + encodeURIComponent(addr), text: addr });
  }

  function kvRow(label, value) {
    var dd = el("dd");
    if (value == null || value === "") dd.textContent = "—";
    else if (typeof value === "string") {
      dd.textContent = value;
      if (value.length > 22) dd.title = value;
    } else dd.append(value);
    return el("div", { class: "kv-row" }, [el("dt", { text: label }), dd]);
  }

  function regText(yes) { return yes ? t("reg.yes") : t("reg.no"); }

  function sourceText(meta) {
    if (!meta || !meta.source) return "";
    var label = t("source." + meta.source);
    return label === "source." + meta.source ? meta.source : label;
  }

  function errorText(err) {
    if (!err) return t("err.generic");
    if (err.code === "PLATFORM_NAMESPACE" && err.platform && err.platform.name) {
      return t("err.PLATFORM_NAMESPACE").replace("{platform}", err.platform.name);
    }
    if (err.code && I18N[state.lang]["err." + err.code]) return t("err." + err.code);
    return err.message || t("err.generic");
  }

  function readStore(key, fallback) {
    try {
      var raw = localStorage.getItem(key);
      if (!raw) return fallback;
      return JSON.parse(raw);
    } catch (e) {
      return fallback;
    }
  }

  function writeStore(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* private mode */ }
  }

  function toast(msg) {
    var node = $("toast");
    node.textContent = msg;
    node.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { node.classList.remove("show"); }, 1600);
  }

  function copyText(text) {
    function ok() { toast(t("copied")); }
    function fail() { toast(t("copyfail")); }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(ok, function () { fallback(); });
      return;
    }
    fallback();
    function fallback() {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.append(ta);
      ta.select();
      try {
        if (document.execCommand("copy")) ok();
        else fail();
      } catch (e) { fail(); }
      ta.remove();
    }
  }

  function summaryText(r, brief) {
    if (!r) return "";
    var reg = r.registrar || {};
    var dates = r.dates || {};
    var lines = [r.domain || r.query || ""];
    lines.push(t("sum.registered") + ": " + regText(!!r.isRegistered));
    lines.push(t("sum.registrar") + ": " + (reg.name || "—"));
    lines.push(t("sum.created") + ": " + (fmtDate(dates.created) || "—"));
    if (!brief) lines.push(t("sum.updated") + ": " + (fmtDate(dates.updated) || "—"));
    lines.push(t("sum.expires") + ": " + (fmtDate(dates.expires) || "—"));
    var ns = (r.nameservers || []).map(function (n) { return n.name; }).filter(Boolean);
    if (ns.length) lines.push(t("sum.ns") + ": " + ns.join(", "));
    if (!brief && r.status && r.status.length) lines.push(t("sum.statuses") + ": " + r.status.join(", "));
    var src = sourceText(r.meta);
    if (src) lines.push(t("sum.source") + ": " + src);
    return lines.join("\n");
  }

  function applyI18n() {
    document.documentElement.lang = state.lang === "en" ? "en" : "zh-CN";
    document.title = t("title");
    var desc = document.querySelector('meta[name="description"]');
    if (desc) desc.setAttribute("content", t("desc"));
    document.querySelectorAll("[data-i18n]").forEach(function (node) {
      node.textContent = t(node.getAttribute("data-i18n"));
    });
    document.querySelectorAll("[data-i18n-html]").forEach(function (node) {
      node.innerHTML = t(node.getAttribute("data-i18n-html"));
    });
    document.querySelectorAll("[data-i18n-placeholder]").forEach(function (node) {
      node.setAttribute("placeholder", t(node.getAttribute("data-i18n-placeholder")));
    });
    var langBtn = $("langToggle");
    langBtn.setAttribute("aria-label", t("lang.aria"));
    var jsonBtn = $("jsonToggle");
    jsonBtn.textContent = state.showJson ? t("json.hide") : t("record.json");
    jsonBtn.setAttribute("aria-pressed", state.showJson ? "true" : "false");
  }

  function paintStatus() {
    var node = $("status");
    node.classList.remove("is-busy", "is-err");
    if (state.loading) {
      node.classList.add("is-busy");
      node.textContent = t("status.loading");
      return;
    }
    if (state.error) {
      node.classList.add("is-err");
      node.textContent = errorText(state.error);
      return;
    }
    if (state.result) {
      node.textContent = t("status.done").replace("{domain}", state.result.domain || state.result.query || "");
      return;
    }
    node.textContent = t("status.idle");
  }

  function paintBadge() {
    var b = $("snapBadge");
    if (state.loading) {
      b.textContent = t("snap.badge.loading");
      b.className = "badge";
      return;
    }
    if (state.result && state.result.meta && state.result.meta.source) {
      b.textContent = String(state.result.meta.source).toUpperCase();
      b.className = "badge badge-lime";
      return;
    }
    b.textContent = t("snap.badge.wait");
    b.className = "badge badge-grey";
  }

  function paintBar() {
    var q = $("barQuery");
    var dot = $("barDot");
    if (state.loading) dot.className = "dot dot-violet";
    else if (state.result && state.result.domain) dot.className = "dot dot-lime";
    else dot.className = "dot dot-grey";
    q.textContent = state.result && state.result.domain ? state.result.domain : t("bar.wait");
  }

  function paintSnap() {
    var r = state.result;
    var host = $("snapBody");
    var reg = (r && r.registrar) || {};
    var dates = (r && r.dates) || {};
    var name = r && (r.domain || r.query) ? (r.domain || r.query) : "— — —";
    var sub = r ? regText(!!r.isRegistered) : t("snap.sub.wait");
    var plate = el("div", { class: "plate" }, [
      el("div", { class: "plate-id" }, [
        el("div", { class: "plate-name", text: name }),
        el("div", { class: r && !r.isRegistered ? "plate-sub is-warn" : "plate-sub", text: sub })
      ]),
      r ? el("span", { class: "pill pill-sky", text: (r.tld || "").toUpperCase() || "—" }) : null
    ]);
    var kv = el("dl", { class: "kv" }, [
      kvRow(t("snap.f.status"), r ? regText(!!r.isRegistered) : ""),
      kvRow(t("snap.f.registrar"), reg.name || ""),
      kvRow(t("snap.f.created"), fmtDate(dates.created)),
      kvRow(t("snap.f.expires"), fmtDate(dates.expires)),
      kvRow(t("snap.f.source"), r ? sourceText(r.meta) : ""),
      kvRow(t("snap.f.tld"), r && r.tld ? r.tld : "")
    ]);
    host.replaceChildren(plate, kv);
  }

  function addressText(a) {
    if (!a) return "";
    return [a.street, a.city, a.state, a.postalCode, a.country].filter(Boolean).join(", ");
  }

  function paintRecord() {
    var host = $("recordBody");
    var raw = $("rawJson");
    var r = state.result;
    if (!r) {
      host.replaceChildren(el("div", { class: "empty" }, [
        el("strong", { text: t("record.empty.title") }),
        el("p", { text: t("record.empty") })
      ]));
      raw.hidden = true;
      raw.textContent = "";
      return;
    }
    var reg = r.registrar || {};
    var dates = r.dates || {};
    var sub = regText(!!r.isRegistered);
    if (reg.name) sub += " · " + reg.name;
    var top = el("div", { class: "res-top" }, [
      el("div", { class: "res-id" }, [
        el("div", { class: "res-name", text: r.domain || r.query || "—" }),
        el("div", { class: r.isRegistered ? "res-sub" : "res-sub is-warn", text: sub }),
        r.domainUnicode && r.domainUnicode !== r.domain
          ? el("div", { class: "res-path", text: r.domainUnicode })
          : null
      ]),
      el("span", { class: "pill", text: (r.tld || "").toUpperCase() || "—" })
    ]);

    var rows = [
      kvRow(t("record.domain"), r.domain || ""),
      r.domainUnicode && r.domainUnicode !== r.domain ? kvRow(t("record.unicode"), r.domainUnicode) : null,
      r.id ? kvRow(t("record.id"), r.id) : null,
      kvRow(t("record.tld"), r.tld || ""),
      kvRow(t("record.registered"), regText(!!r.isRegistered)),
      kvRow(t("record.registrar"), reg.name || ""),
      reg.ianaId ? kvRow(t("record.iana"), reg.ianaId) : null,
      reg.url ? kvRow(t("record.url"), linkOrText(reg.url)) : null,
      reg.whoisServer ? kvRow(t("record.whois"), reg.whoisServer) : null,
      reg.reseller ? kvRow(t("record.reseller"), reg.reseller) : null,
      reg.abuseEmail ? kvRow(t("record.abuseEmail"), mailLink(reg.abuseEmail)) : null,
      reg.abusePhone ? kvRow(t("record.abusePhone"), reg.abusePhone) : null,
      kvRow(t("record.created"), fmtDate(dates.created)),
      kvRow(t("record.updated"), fmtDate(dates.updated)),
      kvRow(t("record.expires"), fmtDate(dates.expires))
    ];
    var kv = el("dl", { class: "kv kv-2" }, rows);

    var codes = r.status || [];
    var altKids = [
      el("div", { class: "alt-title" }, [
        document.createTextNode(t("record.statuses")),
        el("span", { text: t("record.statuses.hint") })
      ])
    ];
    if (!codes.length) {
      altKids.push(el("p", { class: "fine", text: t("record.noStatus") }));
    } else {
      altKids.push(el("div", { class: "signals" }, codes.map(function (code) {
        var label = gloss(code) || code;
        return el("div", { class: "signal " + statusTone(code) }, [
          el("i"),
          el("span", { text: label }),
          gloss(code) ? el("span", { class: "code", text: code }) : null
        ]);
      })));
    }
    var alt = el("div", { class: "alt" }, altKids);

    var metaBits = [];
    if (r.meta) {
      var src = sourceText(r.meta);
      if (src) metaBits.push(src);
      if (r.meta.server) metaBits.push(r.meta.server);
      if (r.meta.cached) metaBits.push(t("cached"));
      var fetched = fmtDate(r.meta.fetchedAt);
      if (fetched) metaBits.push(fetched);
    }
    var meta = metaBits.length ? el("p", { class: "meta-line", text: metaBits.join(" · ") }) : null;
    host.replaceChildren(top, kv, alt, meta);

    if (state.showJson) {
      raw.hidden = false;
      raw.textContent = JSON.stringify(r, null, 2);
    } else {
      raw.hidden = true;
    }
  }

  function paintNS() {
    var host = $("nsBody");
    var r = state.result;
    if (!r) {
      host.replaceChildren(
        el("div", { class: "score" }, [
          el("div", { class: "score-num is-wait", text: "—" }),
          el("div", { class: "score-side" }, [
            el("div", { class: "score-label", text: t("dnssec.wait") }),
            el("p", { text: t("ns.empty") })
          ])
        ])
      );
      return;
    }
    var dns = r.dnssec || {};
    var signed = !!dns.signed;
    var nss = r.nameservers || [];
    var ds = dns.dsData || [];
    var score = el("div", { class: "score" }, [
      el("div", { class: signed ? "score-num" : "score-num is-off", text: signed ? (state.lang === "en" ? "ON" : "签") : (state.lang === "en" ? "OFF" : "未") }),
      el("div", { class: "score-side" }, [
        el("div", { class: "score-label", text: signed ? t("dnssec.on") : t("dnssec.off") }),
        el("p", { text: signed ? t("dnssec.detail.on") : t("dnssec.detail.off") })
      ])
    ]);
    var facts = el("dl", { class: "kv" }, [
      kvRow(t("dnssec.ns"), String(nss.length)),
      kvRow(t("dnssec.ds"), String(ds.length))
    ]);
    var list;
    if (!nss.length) {
      list = el("p", { class: "fine", text: t("ns.none") });
    } else {
      list = el("div", { class: "ns-list" }, nss.map(function (ns, i) {
        var ips = (ns.ipv4 || []).concat(ns.ipv6 || []);
        return el("div", { class: "ns" }, [
          el("span", { class: "ns-i", text: String(i + 1).padStart(2, "0") }),
          el("div", {}, [
            el("div", { class: "ns-name", text: ns.name || "—" }),
            ips.length ? el("div", { class: "ns-ip", text: ips.join("  ") }) : null
          ])
        ]);
      }));
    }
    var dsBox = null;
    if (ds.length) {
      dsBox = el("div", { class: "ns-list" }, ds.map(function (item) {
        var digest = item.digest || "";
        var short = digest.length > 24 ? digest.slice(0, 24) + "…" : digest;
        return el("div", { class: "ds", title: digest, text: "DS " + (item.keyTag || "") + " · alg " + (item.algorithm || "") + " · " + short });
      }));
    }
    host.replaceChildren(score, facts, list, dsBox);
  }

  function contactCard(role, c) {
    c = c || {};
    var addr = addressText(c.address);
    var fields = [];
    if (c.name) fields.push(kvRow(t("c.name"), c.name));
    if (c.organization) fields.push(kvRow(t("c.org"), c.organization));
    if (c.email) fields.push(kvRow(t("c.email"), mailLink(c.email)));
    if (c.phone) fields.push(kvRow(t("c.phone"), c.phone));
    if (addr) fields.push(kvRow(t("c.addr"), addr));
    var pill = null;
    if (!fields.length && c.redacted) pill = el("span", { class: "pill pill-pink", text: t("contacts.redacted") });
    else if (!fields.length) pill = el("span", { class: "pill pill-wait", text: t("contacts.none") });
    var body = fields.length
      ? el("dl", { class: "kv" }, fields)
      : el("p", { class: "fine", text: c.redacted ? t("contacts.redacted") : t("contacts.none") });
    return el("article", { class: "role" }, [
      el("div", { class: "role-h" }, [
        el("span", { text: t("role." + role) }),
        pill
      ]),
      body
    ]);
  }

  function paintContacts() {
    var host = $("contactsBody");
    var r = state.result;
    if (!r) {
      host.replaceChildren(el("div", { class: "empty" }, [
        el("strong", { text: t("contacts.title") }),
        el("p", { text: t("contacts.empty") })
      ]));
      return;
    }
    var c = r.contacts || {};
    host.replaceChildren(el("div", { class: "roles" }, [
      contactCard("registrant", c.registrant),
      contactCard("admin", c.admin),
      contactCard("tech", c.tech),
      contactCard("billing", c.billing)
    ]));
  }

  function paintSource() {
    var host = $("sourceBody");
    var badge = $("sourceBadge");
    var r = state.result;
    var err = state.error;
    if (err && err.code === "UNSUPPORTED_TLD") {
      badge.textContent = t("source.badge.wait");
      badge.className = "badge badge-grey";
      host.replaceChildren(el("div", { class: "empty" }, [
        el("strong", { text: t("source.noEndpoint") }),
        el("p", { text: t("source.noEndpointBody") })
      ]));
      return;
    }
    if (err && err.code === "PLATFORM_NAMESPACE") {
      badge.textContent = t("source.badge.wait");
      badge.className = "badge badge-grey";
      var p = err.platform || {};
      var kids = [
        el("strong", { text: t("source.platform") }),
        el("p", { text: t("source.platformBody") })
      ];
      if (p.url) {
        kids.push(p.hasLookup
          ? el("a", { href: p.url, target: "_blank", rel: "noopener noreferrer", text: t("source.platformLookup") })
          : el("p", { class: "fine", text: t("source.platformNoLookup") }));
      }
      host.replaceChildren(el("div", { class: "empty" }, kids));
      return;
    }
    if (!r) {
      badge.textContent = t("source.badge.wait");
      badge.className = "badge badge-grey";
      host.replaceChildren(el("div", { class: "empty" }, [
        el("strong", { text: t("source.title") }),
        el("p", { text: t("source.empty") })
      ]));
      return;
    }
    var meta = r.meta || {};
    var src = sourceText(meta);
    badge.textContent = src ? src.toUpperCase() : t("source.badge.wait");
    badge.className = "badge badge-lime";
    var proto = "";
    if (meta.source === "whois") proto = t("source.protoWhois");
    else if (meta.conformance && meta.conformance.length) {
      proto = t("source.protoRdap") + " · " + meta.conformance[0] + (meta.conformance.length > 1 ? " +" + (meta.conformance.length - 1) : "");
    } else proto = t("source.protoRdap");
    var elapsed = meta.durationMs ? String(meta.durationMs) + " ms" : "—";
    if (meta.cached) elapsed += " · " + t("cached");
    var rows = [
      kvRow(t("source.endpoint"), meta.server || ""),
      kvRow(t("source.elapsed"), elapsed),
      kvRow(t("source.proto"), proto),
      kvRow(t("source.whois"), (r.registrar && r.registrar.whoisServer) || (meta.source === "whois" ? meta.server || "" : "")),
      kvRow(t("source.fetched"), fmtDateTime(meta.fetchedAt)),
      kvRow(t("source.bytes"), meta.bytes ? t("raw.bytes").replace("{n}", String(meta.bytes)) : "")
    ];
    host.replaceChildren(el("dl", { class: "kv" }, rows));
  }

  function paintDue() {
    var host = $("dueBody");
    var badge = $("dueBadge");
    var r = state.result;
    if (!r) {
      badge.textContent = t("due.badge.wait");
      badge.className = "badge badge-grey";
      host.replaceChildren(el("div", { class: "empty" }, [
        el("strong", { text: t("due.title") }),
        el("p", { text: t("due.empty") })
      ]));
      return;
    }
    var dates = r.dates || {};
    if (!r.isRegistered) {
      badge.textContent = t("due.badge.none");
      badge.className = "badge badge-grey";
      host.replaceChildren(el("p", { class: "fine", text: t("due.notRegistered") }));
      return;
    }
    if (!dates.expires) {
      badge.textContent = t("due.badge.none");
      badge.className = "badge badge-grey";
      host.replaceChildren(el("p", { class: "fine", text: t("due.noExpiry") }));
      return;
    }
    var now = Date.now();
    var expires = new Date(dates.expires).getTime();
    var created = dates.created ? new Date(dates.created).getTime() : NaN;
    var leftDays = Math.ceil((expires - now) / 86400000);
    var pct = 0;
    if (!isNaN(created) && expires > created) {
      pct = Math.min(100, Math.max(0, ((now - created) / (expires - created)) * 100));
    }
    var suspended = (r.status || []).some(function (s) { return String(s).toLowerCase().indexOf("hold") >= 0; });
    var expired = leftDays < 0;
    badge.textContent = expired ? t("due.badge.expired") : t("due.badge.active");
    badge.className = "badge " + (expired ? "badge-coral" : "badge-lime");
    var fillColor = expired ? "var(--coral)" : leftDays < 30 ? "var(--coral)" : leftDays < 90 ? "var(--amber)" : "var(--violet)";
    var num = el("div", { class: "due-num" }, [
      el("span", { text: expired ? t("due.expired") : String(leftDays) }),
      expired ? null : el("small", { text: " " + t("due.days") })
    ]);
    var bar = el("div", { class: "due-bar" }, [
      el("div", { class: "due-fill", style: "width:" + pct.toFixed(1) + "%;background:" + fillColor })
    ]);
    var range = el("div", { class: "due-range" }, [
      el("span", { text: t("due.from") + " " + (fmtDate(dates.created) || "—") }),
      el("span", { text: t("due.elapsed") + " " + Math.round(pct) + "%" }),
      el("span", { text: t("due.to") + " " + (fmtDate(dates.expires) || "—") })
    ]);
    var flag = el("p", { class: "fine" }, [
      el("span", { class: "pill " + (suspended ? "pill-pink" : "pill-lime"), text: suspended ? t("due.suspended") : t("due.active") })
    ]);
    host.replaceChildren(
      el("div", { class: "due-top" }, [el("div", { text: t("due.remaining") }), num]),
      bar, range, flag
    );
  }

  function timelineEvents(r) {
    var evs = (r && r.events) || [];
    if (evs.length) return evs;
    var dates = (r && r.dates) || {};
    var out = [];
    if (dates.created) out.push({ action: "registration", date: dates.created });
    if (dates.updated) out.push({ action: "last changed", date: dates.updated });
    if (dates.expires) out.push({ action: "expiration", date: dates.expires });
    out.sort(function (a, b) { return new Date(a.date) - new Date(b.date); });
    return out;
  }

  function paintTimeline() {
    var host = $("timelineBody");
    var count = $("tlCount");
    var r = state.result;
    var evs = r ? timelineEvents(r) : [];
    if (!evs.length) {
      count.hidden = true;
      host.replaceChildren(el("div", { class: "empty" }, [
        el("strong", { text: t("tl.title") }),
        el("p", { text: t("tl.empty") })
      ]));
      return;
    }
    count.hidden = false;
    count.textContent = t("tl.count").replace("{n}", String(evs.length));
    var rows = evs.map(function (e) {
      var rel = fmtRel(e.date);
      return el("div", { class: "tl-row" }, [
        el("span", { class: "tl-dot", "aria-hidden": "true" }),
        el("div", { class: "tl-body" }, [
          el("div", { class: "tl-name", text: evLabel(e.action) }),
          el("div", { class: "tl-meta", text: fmtDateTime(e.date) + (rel ? " · " + rel : "") })
        ])
      ]);
    });
    host.replaceChildren(el("div", { class: "tl" }, rows));
  }

  function paintStatusMeanings() {
    var host = $("statusBody");
    var r = state.result;
    var codes = (r && r.status) || [];
    if (!codes.length) {
      host.replaceChildren(el("div", { class: "empty" }, [
        el("strong", { text: t("mean.title") }),
        el("p", { text: r ? t("mean.empty") : t("mean.wait") })
      ]));
      return;
    }
    var rows = codes.map(function (code) {
      var mean = statusMean(code) || gloss(code) || "";
      return el("div", { class: "mean-row " + statusTone(code) }, [
        el("span", { class: "mean-code", text: code }),
        el("span", { class: "mean-text", text: mean || "—" })
      ]);
    });
    host.replaceChildren(el("div", { class: "mean-list" }, rows));
  }

  function priceWhen(s) {
    var m = String(s || "").match(/(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})/);
    return m ? m[2] + "-" + m[3] + " " + m[4] + ":" + m[5] : String(s || "");
  }

  function priceTile(order, it) {
    var label = t("price.order." + order);
    if (!it || it.empty || it.effectiveCny == null) {
      var why = it && it.origValue != null && it.currency
        ? money(it.origValue) + " " + String(it.currency).toUpperCase()
        : t("price.noQuoteHint");
      return el("div", { class: "price-tile is-empty" }, [
        el("span", { class: "price-kind", text: label }),
        el("div", { class: "price-num is-na", text: t("price.noQuote") }),
        el("div", { class: "price-meta", text: why })
      ]);
    }
    var tags = [];
    if (it.promo && it.promo.code) {
      tags.push(el("button", {
        type: "button", class: "price-code", "data-code": it.promo.code,
        title: t("price.copy"), "aria-label": t("price.copy") + " " + it.promo.code
      }, [el("span", { class: "price-code-k", text: t("price.coupon") }), el("b", { text: it.promo.code })]));
    }
    if (it.registrarName) {
      tags.push(it.registrarWeb
        ? el("a", { class: "price-reg", href: it.registrarWeb, target: "_blank", rel: "noopener noreferrer", text: it.registrarName + " ↗" })
        : el("span", { class: "price-reg is-plain", text: it.registrarName }));
    }
    var bits = [];
    if (it.promo && it.promo.priceCny != null) {
      if (it.standardCny != null) bits.push(t("price.std") + " ¥" + money(it.standardCny));
      if (it.promo.limit) bits.push(t("price.limit").replace("{n}", String(it.promo.limit)));
      if (it.promo.newUser) bits.push(t("price.newUser"));
    } else if (it.currency && String(it.currency).toLowerCase() !== "cny" && it.origValue != null) {
      bits.push(money(it.origValue) + " " + String(it.currency).toUpperCase());
    }
    if (it.updatedtime) bits.push(t("price.at") + " " + priceWhen(it.updatedtime));
    return el("div", { class: "price-tile" }, [
      el("span", { class: "price-kind", text: label }),
      el("div", { class: "price-num" }, [
        document.createTextNode("¥" + money(it.effectiveCny)),
        el("span", { class: "price-cur", text: "CNY" })
      ]),
      el("div", { class: "price-tags" }, tags),
      el("div", { class: "price-meta", text: bits.join(" · ") })
    ]);
  }

  function paintPrice() {
    var host = $("priceBody");
    var badge = $("priceBadge");
    var fine = $("priceFine");
    var p = state.price;
    fine.textContent = "";
    if (!p) {
      badge.textContent = "—";
      badge.className = "badge badge-grey";
      host.replaceChildren(el("div", { class: "empty" }, [
        el("p", { text: t("price.wait") })
      ]));
      return;
    }
    if (p.loading) {
      badge.textContent = t("price.loading");
      badge.className = "badge badge-grey";
      host.replaceChildren(el("div", { class: "price-grid" }, ["register", "renew", "transfer"].map(function (o) {
        return el("div", { class: "price-tile is-empty" }, [
          el("span", { class: "price-kind", text: t("price.order." + o) }),
          el("div", { class: "price-num is-na", text: "…" })
        ]);
      })));
      return;
    }
    if (p.error || !p.data) {
      badge.textContent = "—";
      badge.className = "badge badge-grey";
      host.replaceChildren(el("div", { class: "empty" }, [el("p", { text: t("price.fail") })]));
      return;
    }
    var data = p.data;
    var items = data.items || [];
    var quoted = items.filter(function (x) { return x && !x.empty && x.effectiveCny != null; });
    if (!quoted.length) {
      badge.textContent = t("price.uncovered");
      badge.className = "badge badge-grey";
      host.replaceChildren(el("div", { class: "empty" }, [
        el("p", { text: t("price.empty").replace("{tld}", data.tld || "") })
      ]));
      return;
    }
    var byOrder = {};
    items.forEach(function (x) { if (x && x.order) byOrder[x.order] = x; });
    host.replaceChildren(el("div", { class: "price-grid" }, ["register", "renew", "transfer"].map(function (o) {
      return priceTile(o, byOrder[o]);
    })));
    badge.textContent = "nazhumi" + (data.updated ? " · " + priceWhen(data.updated) : "");
    badge.className = "badge badge-lime";
    if (data.updated) badge.title = String(data.updated);
    var link = data.sourceUrl
      ? el("a", { href: data.sourceUrl, target: "_blank", rel: "noopener noreferrer", text: "nazhumi.com" })
      : null;
    fine.replaceChildren(link, link ? document.createTextNode(" · " + t("price.fine")) : document.createTextNode(t("price.fine")));
  }

  function loadPrice(r) {
    if (!r) return;
    var labels = String(r.domain || r.query || "").split(".");
    var cands = [];
    if (labels.length >= 3) cands.push(labels.slice(-2).join("."));
    if (r.tld) cands.push(r.tld);
    cands = cands.filter(function (v, i) { return v && cands.indexOf(v) === i; });
    if (!cands.length) return;
    state.priceSeq++;
    var seq = state.priceSeq;
    state.price = { loading: true };
    paintPrice();
    var i = 0;
    function next() {
      if (seq !== state.priceSeq) return;
      if (i >= cands.length) {
        state.price = { error: true };
        paintPrice();
        return;
      }
      var tld = cands[i++];
      fetchJSON("/api/price?tld=" + encodeURIComponent(tld)).then(function (data) {
        if (seq !== state.priceSeq) return;
        var quoted = (data.items || []).some(function (x) { return x && !x.empty && x.effectiveCny != null; });
        if (quoted || i >= cands.length) {
          state.price = { data: data };
          paintPrice();
        } else next();
      }, function () {
        if (seq !== state.priceSeq) return;
        next();
      });
    }
    next();
  }

  function paintRaw() {
    var host = $("rawBody");
    var pre = $("rawPre");
    var meta = $("rawMeta");
    $("rawCopy").disabled = !state.rawText;
    $("rawDownload").disabled = !state.rawText;
    if (state.rawLoading) {
      host.replaceChildren(el("div", { class: "empty" }, [el("p", { text: t("raw.loading") })]));
      pre.hidden = true;
      pre.textContent = "";
      meta.textContent = "";
      return;
    }
    if (!state.rawText) {
      host.replaceChildren(el("div", { class: "empty" }, [
        el("strong", { text: t("raw.title") }),
        el("p", { text: t("raw.empty") })
      ]));
      pre.hidden = true;
      pre.textContent = "";
      meta.textContent = "";
      return;
    }
    host.replaceChildren();
    pre.hidden = false;
    pre.textContent = state.rawText;
    var kind = state.rawKind === "whois" ? t("raw.kindWhois") : t("raw.kindRdap");
    meta.textContent = kind + " · " + t("raw.bytes").replace("{n}", String(state.rawText.length));
  }

  function loadRaw(r) {
    if (!r) return;
    var q = r.domain || r.query || "";
    if (!q) return;
    state.rawLoading = true;
    state.rawText = "";
    state.rawKind = (r.meta && r.meta.source) || "";
    paintRaw();
    fetch("/v1/whois/" + encodeURIComponent(q) + "?raw=true").then(function (res) {
      if (!res.ok) throw new Error("raw " + res.status);
      return res.text();
    }).then(function (text) {
      state.rawText = text;
      state.rawLoading = false;
      paintRaw();
    }, function () {
      state.rawLoading = false;
      paintRaw();
    });
  }

  function domainTokens(raw) {
    var seen = Object.create(null);
    var out = [];
    String(raw || "").split(/[\s,;]+/).forEach(function (part) {
      var s = part.trim();
      if (!s) return;
      var k = s.toLowerCase();
      if (seen[k]) return;
      seen[k] = true;
      out.push(s);
    });
    return out;
  }

  function paintBatchCount() {
    var n = domainTokens($("batchInput").value).length;
    var node = $("batchCount");
    node.textContent = n + " / " + MAX_BATCH;
    node.classList.toggle("is-over", n > MAX_BATCH);
  }

  function paintBatch() {
    paintBatchCount();
    var run = $("batchRun");
    run.disabled = state.batchLoading;
    run.textContent = state.batchLoading ? t("batch.running") : t("batch.run");
    $("batchCsv").disabled = !state.batch.length;
    var status = $("batchStatus");
    status.classList.remove("is-busy", "is-err");
    if (state.batchLoading) {
      status.classList.add("is-busy");
      status.textContent = t("status.loading");
    } else if (state.batchError) {
      status.classList.add("is-err");
      status.textContent = state.batchError === "EMPTY" ? t("batch.need") : errorText(state.batchError);
    } else if (state.batchTrim) {
      status.textContent = t("batch.trim");
    } else {
      status.textContent = "";
    }

    var body = $("batchRows");
    if (!state.batch.length) {
      body.replaceChildren(el("tr", {}, [
        el("td", { class: "hint", colspan: "5", text: t("batch.empty") })
      ]));
      return;
    }
    var rows = state.batch.map(function (row) {
      if (row && row.error) {
        var q = row.error.query || "—";
        return el("tr", {}, [
          el("td", { class: "m", text: q }),
          el("td", {}, [el("span", { class: "pill pill-err", text: errorText(row.error) })]),
          el("td", { text: "—" }),
          el("td", { class: "m", text: "—" }),
          el("td", { class: "m", text: "—" })
        ]);
      }
      var reg = (row && row.registrar) || {};
      var dates = (row && row.dates) || {};
      var pill = row && row.isRegistered ? "pill pill-lime" : "pill pill-wait";
      return el("tr", {}, [
        el("td", { class: "m", text: (row && (row.domain || row.query)) || "—" }),
        el("td", {}, [el("span", { class: pill, text: row ? regText(!!row.isRegistered) : "—" })]),
        el("td", { text: reg.name || "—" }),
        el("td", { class: "m", text: fmtDate(dates.expires) || "—" }),
        el("td", { class: "m", text: sourceText(row && row.meta) || "—" })
      ]);
    });
    body.replaceChildren();
    rows.forEach(function (row) { body.append(row); });
  }

  function renderCurl() {
    var origin = location.origin;
    var root = $("curlOut");
    var lines = [
      { kind: "c", text: t("curl.c1") },
      { kind: "cmd", text: "curl " + origin + "/v1/whois/example.com" },
      { kind: "blank" },
      { kind: "c", text: t("curl.c2") },
      { kind: "cmd", text: "curl '" + origin + "/v1/whois/example.com?raw=true'" },
      { kind: "blank" },
      { kind: "c", text: t("curl.c3") },
      { kind: "cmd", text: "curl '" + origin + "/multi?domains=example.com,github.com'" }
    ];
    root.replaceChildren();
    lines.forEach(function (line) {
      if (line.kind === "blank") {
        root.append(document.createTextNode("\n"));
        return;
      }
      if (line.kind === "c") {
        root.append(el("span", { class: "t-c", text: "# " + line.text }), document.createTextNode("\n"));
        return;
      }
      root.append(
        el("span", { class: "t-p", text: "$ " }),
        el("span", { text: line.text }),
        document.createTextNode("\n")
      );
    });
  }

  function renderRecent() {
    var row = $("histRow");
    var host = $("hist");
    host.replaceChildren();
    if (!state.recent.length) {
      row.hidden = true;
      return;
    }
    row.hidden = false;
    state.recent.forEach(function (d) {
      host.append(el("button", { type: "button", class: "chip", "data-domain": d, text: d }));
    });
  }

  function remember(domain) {
    if (!domain) return;
    var key = domain.toLowerCase();
    state.recent = [domain].concat(state.recent.filter(function (d) { return d.toLowerCase() !== key; })).slice(0, 8);
    writeStore(RECENT_KEY, state.recent);
    renderRecent();
  }

  function paint() {
    paintStatus();
    paintBadge();
    paintBar();
    paintSnap();
    paintRecord();
    paintNS();
    paintContacts();
    paintSource();
    paintDue();
    paintTimeline();
    paintStatusMeanings();
    paintPrice();
    paintRaw();
    $("searchBtn").disabled = state.loading;
    $("searchBtn").textContent = state.loading ? t("btn.searching") : t("btn.search");
    $("q").setAttribute("aria-busy", state.loading ? "true" : "false");
    $("snapCopy").disabled = !state.result;
    $("recordCopy").disabled = !state.result;
  }

  function fetchJSON(url, signal) {
    return fetch(url, { headers: { Accept: "application/json" }, signal: signal }).then(function (res) {
      return res.text().then(function (text) {
        var data = null;
        if (text) {
          try { data = JSON.parse(text); } catch (e) { data = null; }
        }
        if (!res.ok) {
          var err = data && data.error ? data.error : {};
          var wrapped = new Error(err.message || "");
          wrapped.code = err.code || "";
          wrapped.detail = err.detail || "";
          wrapped.platform = err.platform || null;
          throw wrapped;
        }
        if (!data) {
          var bad = new Error("");
          bad.code = "NETWORK";
          throw bad;
        }
        return data;
      });
    }, function (err) {
      if (err && err.name === "AbortError") throw err;
      var net = new Error("");
      net.code = "NETWORK";
      throw net;
    });
  }

  function lookup(raw) {
    var q = String(raw || "").trim();
    $("q").value = q;
    if (!q) {
      if (ctrl) { ctrl.abort(); ctrl = null; }
      state.error = { code: "EMPTY" };
      state.loading = false;
      paint();
      return;
    }
    var prev = ctrl;
    ctrl = new AbortController();
    if (prev) prev.abort();
    var mine = ctrl;
    state.loading = true;
    state.error = null;
    paint();
    fetchJSON("/v1/whois/" + encodeURIComponent(q), mine.signal).then(function (data) {
      if (mine.signal.aborted) return;
      state.result = data;
      state.error = null;
      state.showJson = false;
      $("jsonToggle").textContent = t("record.json");
      $("jsonToggle").setAttribute("aria-pressed", "false");
      state.price = null;
      state.rawText = "";
      state.rawLoading = false;
      remember(data.domain || q);
      loadPrice(data);
      loadRaw(data);
    }, function (err) {
      if (err && err.name === "AbortError") return;
      if (mine.signal.aborted) return;
      state.error = err;
      state.result = null;
      state.price = null;
      state.rawText = "";
      state.rawLoading = false;
    }).then(function () {
      if (ctrl !== mine) return;
      state.loading = false;
      ctrl = null;
      paint();
      if (state.result && !state.error && window.matchMedia("(max-width: 980px)").matches) {
        var snap = $("snap");
        if (snap && snap.scrollIntoView) snap.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }
    });
  }

  function runBatch() {
    var tokens = domainTokens($("batchInput").value);
    if (!tokens.length) {
      state.batchError = "EMPTY";
      state.batchTrim = false;
      paintBatch();
      return;
    }
    var list = tokens.slice(0, MAX_BATCH);
    state.batchTrim = tokens.length > MAX_BATCH;
    state.batchLoading = true;
    state.batchError = null;
    paintBatch();
    var url = "/multi?domains=" + list.map(encodeURIComponent).join(",");
    fetchJSON(url).then(function (data) {
      state.batch = data.results || [];
    }, function (err) {
      state.batchError = err;
      state.batch = [];
    }).then(function () {
      state.batchLoading = false;
      paintBatch();
    });
  }

  function csvCell(v) {
    var s = v == null ? "" : String(v);
    if (/[",\n]/.test(s)) return '"' + s.split('"').join('""') + '"';
    return s;
  }

  function exportCSV() {
    if (!state.batch.length) return;
    var lines = [["domain", "registered", "registrar", "created", "expires", "source", "error"].join(",")];
    state.batch.forEach(function (row) {
      if (row && row.error) {
        lines.push([
          csvCell(row.error.query), "", "", "", "", "", csvCell(row.error.code || row.error.message)
        ].join(","));
        return;
      }
      var reg = (row && row.registrar) || {};
      var dates = (row && row.dates) || {};
      lines.push([
        csvCell(row && row.domain),
        row && row.isRegistered ? "yes" : "no",
        csvCell(reg.name),
        csvCell(dates.created),
        csvCell(dates.expires),
        csvCell(row && row.meta && row.meta.source),
        ""
      ].join(","));
    });
    var blob = new Blob(["\uFEFF" + lines.join("\n")], { type: "text/csv;charset=utf-8" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "whois.csv";
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }

  function setLang(next) {
    state.lang = next === "en" ? "en" : "zh";
    writeStore(LANG_KEY, state.lang);
    applyI18n();
    renderCurl();
    renderRecent();
    paint();
    paintBatch();
  }

  function bind() {
    $("lookupForm").addEventListener("submit", function (e) {
      e.preventDefault();
      lookup($("q").value);
    });
    $("clearBtn").addEventListener("click", function () {
      $("q").value = "";
      $("q").focus();
    });
    document.body.addEventListener("click", function (e) {
      var chip = e.target.closest("[data-domain]");
      if (!chip) return;
      lookup(chip.getAttribute("data-domain"));
    });
    $("langToggle").addEventListener("click", function () {
      setLang(state.lang === "en" ? "zh" : "en");
    });
    $("barMe").addEventListener("click", function () {
      var target = state.result ? $("record") : $("lookup");
      if (target && target.scrollIntoView) target.scrollIntoView({ behavior: "smooth", block: "start" });
    });
    $("snapCopy").addEventListener("click", function () {
      if (state.result) copyText(summaryText(state.result, true));
    });
    $("recordCopy").addEventListener("click", function () {
      if (state.result) copyText(summaryText(state.result, false));
    });
    $("jsonToggle").addEventListener("click", function () {
      if (!state.result) { toast(t("json.need")); return; }
      state.showJson = !state.showJson;
      $("jsonToggle").textContent = state.showJson ? t("json.hide") : t("record.json");
      $("jsonToggle").setAttribute("aria-pressed", state.showJson ? "true" : "false");
      paintRecord();
    });
    $("clearRecent").addEventListener("click", function () {
      state.recent = [];
      writeStore(RECENT_KEY, []);
      renderRecent();
    });
    $("batchInput").addEventListener("input", paintBatchCount);
    $("batchRun").addEventListener("click", runBatch);
    $("batchClear").addEventListener("click", function () {
      $("batchInput").value = "";
      state.batch = [];
      state.batchError = null;
      state.batchTrim = false;
      paintBatch();
    });
    $("batchCsv").addEventListener("click", exportCSV);
    $("rawCopy").addEventListener("click", function () {
      if (state.rawText) copyText(state.rawText);
    });
    $("rawDownload").addEventListener("click", function () {
      if (!state.rawText) return;
      var r = state.result || {};
      var ext = state.rawKind === "whois" ? ".whois.txt" : ".rdap.json";
      var blob = new Blob([state.rawText], { type: state.rawKind === "whois" ? "text/plain;charset=utf-8" : "application/json;charset=utf-8" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = (r.domain || r.query || "whois") + ext;
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    });
    document.body.addEventListener("click", function (e) {
      var codeBtn = e.target.closest("[data-code]");
      if (codeBtn) {
        copyText(codeBtn.getAttribute("data-code"));
      }
    });
  }

  var storedLang = readStore(LANG_KEY, null);
  if (storedLang === "en" || storedLang === "zh") state.lang = storedLang;
  var storedRecent = readStore(RECENT_KEY, []);
  if (Array.isArray(storedRecent)) {
    state.recent = storedRecent.filter(function (d) { return typeof d === "string" && d; }).slice(0, 8);
  }

  applyI18n();
  renderCurl();
  renderRecent();
  paint();
  paintBatch();
  bind();

  var initial = "";
  try { initial = new URLSearchParams(location.search).get("q") || ""; } catch (e) { initial = ""; }
  if (initial.trim()) lookup(initial.trim());
})();
