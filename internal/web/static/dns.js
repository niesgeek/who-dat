/* DNS laboratory UI. Talks only to this deployment's /api/dns/lab and /api/whoami. */
(function () {
  "use strict";

  var LANG_KEY = "whois-ui-lang";
  var TYPES = ["ALL", "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV", "PTR"];
  var I18N = {
    zh: {
      title: "wi.fs.kg — DNS 查询",
      "nav.whois": "WHOIS",
      "nav.contact": "联系",
      "nav.docs": "文档",
      "lang.btn": "EN",
      "lang.aria": "切换到英文",
      eyebrow: "DNS · 记录 · 传播 · 权威",
      "h1.l1": "问一个名字，",
      "h1.a": "记录、",
      "h1.b": "传播、",
      "h1.c": "序列号",
      lede: "从这台服务器向公共递归解析器和该域的权威服务器发查询。下划线名字可以，比如 _dmarc。响应不入库，Cache-Control 是 no-store。",
      "label.q": "域名或 IP",
      "btn.clear": "清空",
      "btn.search": "查询",
      "btn.searching": "查询中…",
      "chips.label": "试试",
      "status.idle": "输入 example.com，或点一个类型。",
      "me.title": "这条连接",
      "me.badge": "连接",
      "me.note": "只读这次 HTTP 连接和主机已经附上的头。没有第三方地理查询。",
      "me.ip": "地址",
      "me.ver": "版本",
      "me.place": "地区",
      "me.proto": "协议",
      "me.tls": "TLS",
      "me.pop": "节点",
      "me.none": "这台主机没有附上地区信息。",
      "me.fail": "没有读到连接信息。查询本身不受影响。",
      "me.copy": "复制这条连接",
      "jump.lookup": "查询",
      "jump.trace": "链路",
      "jump.records": "记录",
      "jump.prop": "传播",
      "jump.ns": "服务器",
      "jump.dev": "终端",
      "jump.faq": "常见问题",
      "path.title": "解析链路",
      "path.wait": "等待查询",
      "path.foot": "从左往右是一次解析要经过的五段。你的查询交给递归解析器，解析器从根问到 TLD，再问到权威服务器。亮起的一段旁边写着这一跳的事实：解析器是否一致、权威有没有 AA 和序列号、上级有没有 DS。没亮的那一段，先看那里。",
      "path.you": "你的查询",
      "path.resolver": "递归解析器",
      "path.auth": "权威 NS",
      "path.tld": "TLD",
      "path.root": "根服务器",
      "path.you.wait": "待查询",
      "path.you.miss": "未读到",
      "path.idle": "输入名字后逐段点亮",
      "path.res.count": "{n} 个解析器已回话",
      "path.res.none": "没有可比对的答案",
      "path.res.exact": "{e} / {n} 完全一致",
      "path.res.fail": "{n} 个无响应",
      "path.auth.wait": "未知",
      "path.auth.none": "没拿到名称服务器",
      "path.auth.down": "权威没有答上 SOA",
      "path.auth.no": "没拿到区里的答案",
      "path.auth.aa": "AA=1 · serial {s}",
      "path.tld.wait": "未知",
      "path.tld.ds": "已发布 DS（{n} 条）",
      "path.tld.off": "未启用 DNSSEC",
      "path.tld.key": "无 DS 委托，区里有 DNSKEY",
      "path.tld.skip": "这次没检查",
      "path.root.name": ".（13 组任播）",
      "path.root.detail": "根区已签名，锚点在解析器里",
      "rec.title": "记录",
      "rec.copy": "复制",
      "rec.zone": "导出 zone",
      "rec.empty": "还没有记录",
      "rec.empty2": "查询之后，这里按类型、名字、值和 TTL 列出。",
      "rec.none": "这个类型没有记录。",
      "prop.title": "传播",
      "prop.again": "再问一次",
      "prop.note": "递归解析器用 RD=1。权威服务器用 RD=0。耗时从这台服务器量起，含握手。多地址或分线路时，有交集算部分一致，不算故障。",
      "prop.empty": "等待查询",
      "sec.empty": "查询后看记录在不在",
      "ns.title": "权威与 SOA",
      "ns.empty": "查询后比较每台权威的序列号",
      "del.title": "委托是否一致",
      "del.note": "父区委托是递归解析器看到的 NS。子区自报是从一台置了 AA 的权威上用 RD=0 问到的 NS。",
      "how.title": "怎么一起看",
      "how.mail.q": "邮件",
      "how.mail.a": "看 MX，再看 TXT 里的 SPF，以及 _dmarc 这个名字上的 TXT。",
      "how.acme.q": "证书校验",
      "how.acme.a": "看 _acme-challenge 上的 TXT。名字里的下划线是合法的。",
      "how.hijack.q": "怀疑应答被换过",
      "how.hijack.a": "看 DS、DNSKEY、RRSIG 是否都在，以及验证型解析器有没有置 AD。记录都在不等于签名有效。",
      "how.ns.q": "正在换名称服务器",
      "how.ns.a": "看每台权威的 SOA 序列号是否一致，再看父区委托和子区自报的 NS 是不是同一组。",
      "priv.title": "数据与隐私",
      "priv.src.k": "记录从哪来",
      "priv.src.v": "这台服务器问公共递归器，再问权威服务器",
      "priv.db.k": "会不会入库",
      "priv.db.v": "不建查询库。响应带 Cache-Control: no-store",
      "priv.acct.k": "要不要注册",
      "priv.acct.v": "不用。页面没有广告，也没有第三方追踪脚本",
      "priv.name.k": "域名发出去了吗",
      "priv.name.v": "会，作为 DNS 问题本身。不另做一份档案",
      "api.title": "终端里直接用",
      "api.copy": "复制命令",
      "api.lede": "curl 和 wget 拿到 dig 风格的文本。浏览器，或者带 Accept: application/json，拿到 JSON。format=text 和 format=json 可以强制。server 只能是公网地址。",
      "api.params": "参数：name（必填）、type、server（公网地址，缺省 8.8.8.8）、dnssec=0/1、rd=0/1、timeout=毫秒。应答被截断时自动改走 TCP。",
      "api.c1": "# 查记录（默认解析器）",
      "api.c2": "# 向权威要区里的数据（rd=0，带上 DNSSEC）",
      "api.c3": "# 向一台递归器要它缓存里的答案（必须 rd=1）",
      "api.c4": "# JSON（浏览器拿到的就是这个）",
      "faq.title": "常见问题",
      "faq.q1": "怎么查一个名字？",
      "faq.a1": "输入 example.com，或 _dmarc.example.com 这种带下划线的名字。类型可选 A、AAAA、CNAME、MX、TXT、NS、SOA、CAA、SRV、PTR。ALL 会把常见类型列在一张表里，链路和传播按有答案的那个类型展开。",
      "faq.q2": "刚改的记录还是旧的，是这里坏了吗？",
      "faq.a2": "先看传播表里权威那一行。它已经是新值，就是递归器还拿着缓存，等 TTL。它还是旧值，区数据本身还没换。问递归器用 rd=1，问权威用 rd=0。问反了会得到 SERVFAIL，那不是故障。",
      "faq.q3": "序列号为什么要一致？",
      "faq.a3": "同一套权威靠序列号判断是不是同一版数据。一台落后，不同解析器就可能拿到不同答案。如果 SOA 的主服务器不是同一台，两套序列号各自计数，那是迁移中的两套权威，不一定是同步坏了。",
      "faq.q4": "链上的记录都在，就等于签名有效吗？",
      "faq.a4": "不等于。这里看 DS、DNSKEY、RRSIG 在不在，以及验证型解析器有没有置 AD。不做密码学校验。要判断签名本身，用本机的 dig +dnssec 或带校验的解析器。",
      "faq.q5": "耗时为什么和我本机的 dig 不一样？",
      "faq.a5": "数字从这台服务器量到解析器，经常含一次 TCP 握手。拿来横向比较谁先拿到新答案，不代表你家网络的延迟。",
      "faq.q6": "能从 IP 反查名字吗？",
      "faq.a6": "能。输入 1.1.1.1 或 2001:db8::1，会转成 in-addr.arpa 或 ip6.arpa 并查 PTR。手写反查名也可以。",
      "foot.blurb": "WHOIS 与 DNS",
      "col.type": "类型",
      "col.name": "名字",
      "col.value": "值",
      "col.ttl": "TTL",
      "col.server": "服务器",
      "col.answer": "应答",
      "col.rtt": "耗时",
      "col.state": "对照",
      "soa.mname": "主服务器",
      "soa.rname": "邮箱",
      "soa.serial": "序列号",
      "soa.refresh": "刷新",
      "soa.retry": "重试",
      "soa.expire": "过期",
      "soa.minimum": "否定缓存",
      "del.parent": "父区委托",
      "del.child": "子区自报",
      "del.glue": "区内 NS 没有解析到地址",
      "err.generic": "查询失败",
      "state.reference": "权威",
      "state.baseline": "参照",
      "state.match": "一致",
      "state.partial": "部分一致",
      "state.spread": "分散",
      "state.empty": "空答案",
      "state.no-baseline": "无基准",
      "state.fail": "失败",
      "state.down": "无响应",
      "level.complete": "DS、DNSKEY、RRSIG 都在",
      "level.incomplete": "有 DS 和 DNSKEY，这次没看到 RRSIG",
      "level.self-signed": "区里有 DNSKEY，上级没有 DS",
      "level.broken": "上级有 DS，区里没有 DNSKEY",
      "level.unsigned": "没有启用 DNSSEC",
      "level.unknown": "这次没问全，不能下结论",
      "level.no-apex": "没有确定区顶，未检查",
      "serial.synced": "能答话的权威序列号一致",
      "serial.lag": "有权威的序列号落后",
      "serial.multi": "不止一套 SOA 主服务器，序列号各自独立",
      "serial.unreachable": "权威都没有答上 SOA",
      "serial.none": "没有拿到名称服务器",
      "deleg.match": "父区委托和子区自报的 NS 一致",
      "deleg.mismatch": "父区委托和子区自报的 NS 不一致",
      "deleg.child-unavailable": "没能从权威取到子区自报的 NS",
      "ad.on": "有验证型解析器置了 AD=1。那是它自己的结论，本站没有验签。",
      "ad.off": "这次看到的解析器没有置 AD。",
      "ad.na": "没有拿到 AD 位。"
    },
    en: {
      title: "wi.fs.kg — DNS lookup",
      "nav.whois": "WHOIS",
      "nav.contact": "Contact",
      "nav.docs": "Docs",
      "lang.btn": "中文",
      "lang.aria": "切换到中文",
      eyebrow: "DNS · RECORDS · PROPAGATION · AUTHORITY",
      "h1.l1": "Ask one name.",
      "h1.a": "Records,",
      "h1.b": "spread,",
      "h1.c": "serials.",
      lede: "This server asks public resolvers and the domain's authoritative servers. Underscore names such as _dmarc are fine. Answers are not stored. Cache-Control is no-store.",
      "label.q": "Name or IP",
      "btn.clear": "Clear",
      "btn.search": "Look up",
      "btn.searching": "Looking…",
      "chips.label": "Try",
      "status.idle": "Type example.com, or pick a type.",
      "me.title": "This connection",
      "me.badge": "Link",
      "me.note": "Read from this HTTP connection and headers the host already set. No third-party location lookup.",
      "me.ip": "Address",
      "me.ver": "Version",
      "me.place": "Place",
      "me.proto": "Protocol",
      "me.tls": "TLS",
      "me.pop": "Site",
      "me.none": "This host did not attach a place.",
      "me.fail": "No connection details. The lookup still works.",
      "me.copy": "Copy this connection",
      "jump.lookup": "Lookup",
      "jump.trace": "Path",
      "jump.records": "Records",
      "jump.prop": "Spread",
      "jump.ns": "Servers",
      "jump.dev": "Terminal",
      "jump.faq": "FAQ",
      "path.title": "Resolution path",
      "path.wait": "Waiting",
      "path.foot": "Left to right is the path a lookup takes. Your question goes to a recursive resolver, which asks the root, then the TLD, then the authoritative server. A lit step shows the fact from that hop: whether resolvers agree, whether authority set AA and a serial, and whether the parent published a DS. The step that stays dim is the one to read first.",
      "path.you": "Your query",
      "path.resolver": "Recursive resolver",
      "path.auth": "Authoritative NS",
      "path.tld": "TLD",
      "path.root": "Root servers",
      "path.you.wait": "Waiting",
      "path.you.miss": "No address",
      "path.idle": "Each step lights after a lookup",
      "path.res.count": "{n} resolvers replied",
      "path.res.none": "Nothing to compare",
      "path.res.exact": "{e} / {n} agree exactly",
      "path.res.fail": "{n} did not reply",
      "path.auth.wait": "Unknown",
      "path.auth.none": "No nameservers",
      "path.auth.down": "Authoritative SOA did not answer",
      "path.auth.no": "No answer from the zone",
      "path.auth.aa": "AA=1 · serial {s}",
      "path.tld.wait": "Unknown",
      "path.tld.ds": "DS published ({n})",
      "path.tld.off": "DNSSEC is not enabled",
      "path.tld.key": "No DS, but the zone has a DNSKEY",
      "path.tld.skip": "Not checked this time",
      "path.root.name": ". (13 anycast groups)",
      "path.root.detail": "The root is signed. Resolvers ship the trust anchor",
      "rec.copy": "Copy",
      "rec.zone": "Export zone",
      "rec.title": "Records",
      "rec.empty": "No records yet",
      "rec.empty2": "After a lookup, type, name, value, and TTL land here.",
      "rec.none": "No records of this type.",
      "prop.title": "Propagation",
      "prop.again": "Ask again",
      "prop.note": "Resolvers are asked with RD=1. Authoritative servers are asked with RD=0. Time is measured from this server and includes the handshake. Overlapping answers on multi-address names count as partial, not as a failure.",
      "prop.empty": "Waiting",
      "sec.empty": "Presence shows up after a lookup",
      "ns.title": "Authority and SOA",
      "ns.empty": "Serials are compared after a lookup",
      "del.title": "Delegation",
      "del.note": "Parent NS names are what a resolver sees. Child NS names come from an authoritative server that set AA, asked with RD=0.",
      "how.title": "Read them together",
      "how.mail.q": "Mail",
      "how.mail.a": "Read MX, the SPF text in TXT, and TXT at the _dmarc name.",
      "how.acme.q": "Certificate checks",
      "how.acme.a": "Read TXT at _acme-challenge. The underscore is a normal label.",
      "how.hijack.q": "Answer looks swapped",
      "how.hijack.a": "See whether DS, DNSKEY, and RRSIG are all present, and whether a validating resolver set AD. Presence is not a signature check.",
      "how.ns.q": "Moving nameservers",
      "how.ns.a": "Compare SOA serials on each authoritative server, then compare parent-delegation NS names with the child zone's own NS names.",
      "priv.title": "Data and privacy",
      "priv.src.k": "Where records come from",
      "priv.src.v": "This server asks public resolvers, then authoritative servers",
      "priv.db.k": "Stored?",
      "priv.db.v": "No query database. Responses send Cache-Control: no-store",
      "priv.acct.k": "Account?",
      "priv.acct.v": "No. No ads and no third-party tracking scripts",
      "priv.name.k": "Does the name leave?",
      "priv.name.v": "Yes, as the DNS question itself. Nothing else is filed",
      "api.title": "From the terminal",
      "api.copy": "Copy command",
      "api.lede": "curl and wget get dig-style text. Browsers, or Accept: application/json, get JSON. format=text and format=json force one. server must be a public address.",
      "api.params": "Parameters: name (required), type, server (public address, default 8.8.8.8), dnssec=0/1, rd=0/1, timeout in milliseconds. A truncated answer is retried over TCP.",
      "api.c1": "# records (default resolver)",
      "api.c2": "# ask authority for the zone (rd=0, with DNSSEC)",
      "api.c3": "# ask one resolver for its cache (rd=1 required)",
      "api.c4": "# JSON (what a browser receives)",
      "faq.title": "Questions",
      "faq.q1": "How do I look up a name?",
      "faq.a1": "Type example.com, or an underscore name such as _dmarc.example.com. Types are A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, SRV, and PTR. ALL lists the common types; the path and the matrix follow the first type that has an answer.",
      "faq.q2": "I just changed a record and still see the old one. Is this page wrong?",
      "faq.a2": "Read the authoritative row in the matrix. If that row is already new, a resolver is still serving cache until the TTL. If that row is still old, the zone itself has not changed. Resolvers are asked with rd=1. Authority is asked with rd=0. Reversing those gets SERVFAIL, which is not a failure of the zone.",
      "faq.q3": "Why should the serials match?",
      "faq.a3": "Servers for one zone use the serial to tell whether they have the same edition. One behind means resolvers can disagree. If the SOA primary names differ, each set counts its own serial. That is two authorities during a move, not automatically a broken transfer.",
      "faq.q4": "If the records are all present, is the signature valid?",
      "faq.a4": "No. This check looks for DS, DNSKEY, and RRSIG, and for whether a validating resolver set AD. It does not check the cryptography. For the signature itself, use dig +dnssec or a validating resolver on your machine.",
      "faq.q5": "Why is the time different from dig on my machine?",
      "faq.a5": "The number is measured from this server to the resolver and often includes a TCP handshake. Use it to compare who already has the new answer, not as your network's latency.",
      "faq.q6": "Can I look up an IP?",
      "faq.a6": "Yes. 1.1.1.1 or 2001:db8::1 is turned into in-addr.arpa or ip6.arpa and queried as PTR. A handwritten reverse name works too.",
      "foot.blurb": "WHOIS and DNS",
      "col.type": "Type",
      "col.name": "Name",
      "col.value": "Value",
      "col.ttl": "TTL",
      "col.server": "Server",
      "col.answer": "Answer",
      "col.rtt": "Time",
      "col.state": "Match",
      "soa.mname": "Primary",
      "soa.rname": "Mailbox",
      "soa.serial": "Serial",
      "soa.refresh": "Refresh",
      "soa.retry": "Retry",
      "soa.expire": "Expire",
      "soa.minimum": "Negative TTL",
      "del.parent": "Parent delegation",
      "del.child": "Child NS",
      "del.glue": "In-zone NS with no address",
      "err.generic": "Lookup failed",
      "state.reference": "Authority",
      "state.baseline": "Baseline",
      "state.match": "Match",
      "state.partial": "Partial",
      "state.spread": "Spread",
      "state.empty": "Empty",
      "state.no-baseline": "No baseline",
      "state.fail": "Failed",
      "state.down": "No reply",
      "level.complete": "DS, DNSKEY, and RRSIG are present",
      "level.incomplete": "DS and DNSKEY are present; no RRSIG in this pass",
      "level.self-signed": "DNSKEY is in the zone; the parent has no DS",
      "level.broken": "The parent has a DS; the zone has no DNSKEY",
      "level.unsigned": "DNSSEC is not enabled",
      "level.unknown": "The check did not finish",
      "level.no-apex": "No zone apex, so DNSSEC was not checked",
      "serial.synced": "Authoritative serials that answered are the same",
      "serial.lag": "At least one authoritative serial is behind",
      "serial.multi": "More than one SOA primary; serials are independent",
      "serial.unreachable": "No authoritative server returned SOA",
      "serial.none": "No nameservers were found",
      "deleg.match": "Parent delegation and child NS names match",
      "deleg.mismatch": "Parent delegation and child NS names differ",
      "deleg.child-unavailable": "The child NS set could not be read from an authoritative server",
      "ad.on": "A validating resolver set AD=1. That is the resolver's claim. This site did not check the signature.",
      "ad.off": "Resolvers in this pass did not set AD.",
      "ad.na": "No AD bit was available."
    }
  };

  var state = { lang: "zh", type: "ALL", busy: false, last: "", report: null, me: null };

  function $(id) { return document.getElementById(id); }
  function t(key) {
    var pack = I18N[state.lang] || I18N.zh;
    return pack[key] || I18N.zh[key] || key;
  }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }
  function trimDot(s) { return String(s || "").replace(/\.$/, ""); }

  function applyI18n() {
    document.documentElement.lang = state.lang === "en" ? "en" : "zh-CN";
    document.title = t("title");
    document.querySelectorAll("[data-i18n]").forEach(function (node) {
      node.textContent = t(node.getAttribute("data-i18n"));
    });
    var toggle = $("langToggle");
    if (toggle) toggle.setAttribute("aria-label", t("lang.aria"));
    buildChips();
    if (state.report) render(state.report);
    else {
      renderPathIdle();
      renderTerm(null);
    }
    if (state.me) renderMe(state.me);
  }

  function buildChips() {
    var box = $("typeChips");
    if (!box) return;
    box.innerHTML = TYPES.map(function (typ) {
      return '<button type="button" class="chip" data-t="' + typ + '" aria-pressed="' + (typ === state.type ? "true" : "false") + '">' + typ + "</button>";
    }).join("");
  }

  function setStatus(msg, kind) {
    var el = $("status");
    if (!el) return;
    el.className = "status" + (kind ? " is-" + kind : "");
    el.textContent = msg;
  }

  function badge(id, text, kind) {
    var el = $(id);
    if (!el) return;
    el.textContent = text;
    el.className = "badge " + (kind || "badge-grey");
  }

  function loadMe() {
    fetch("/api/whoami", { headers: { Accept: "application/json" } })
      .then(function (r) { return r.json(); })
      .then(function (me) { state.me = me; renderMe(me); })
      .catch(function () {
        $("meKv").innerHTML = "<p class=\"fine\">" + esc(t("me.fail")) + "</p>";
      });
  }

  function renderMe(me) {
    me = me || {};
    var place = [me.country, me.region, me.city].filter(Boolean).join(" · ");
    var rows = [
      [t("me.ip"), me.ip || "—"],
      [t("me.ver"), me.version || "—"],
      [t("me.place"), place || t("me.none")],
      [t("me.proto"), [me.protocol, me.forwardedProto].filter(Boolean).join(" / ") || "—"],
      [t("me.tls"), me.tls || "—"],
      [t("me.pop"), me.pop || "—"]
    ];
    $("meKv").innerHTML = rows.map(function (row) {
      return "<div class=\"kv-row\"><dt>" + esc(row[0]) + "</dt><dd>" + esc(row[1]) + "</dd></div>";
    }).join("");
    badge("meBadge", me.platformHints ? (me.country || t("me.badge")) : t("me.badge"), me.ip ? "badge-lime" : "badge-grey");
  }

  function currentName() {
    return ($("q").value || "").trim();
  }

  function run(name) {
    if (state.busy) return;
    name = (name || "").trim();
    if (!name) {
      setStatus(t("status.idle"), "err");
      return;
    }
    state.busy = true;
    state.last = name;
    $("q").value = name;
    $("searchBtn").disabled = true;
    $("searchBtn").textContent = t("btn.searching");
    $("propAgain").disabled = true;
    setStatus(name + " · " + state.type, "busy");
    var url = "/api/dns/lab?name=" + encodeURIComponent(name) + "&type=" + encodeURIComponent(state.type);
    try { history.replaceState(null, "", "/dns?d=" + encodeURIComponent(name) + "&t=" + encodeURIComponent(state.type)); } catch (e) {}
    fetch(url, { headers: { Accept: "application/json" } })
      .then(function (r) {
        return r.json().then(function (body) { return { ok: r.ok, body: body }; });
      })
      .then(function (res) {
        if (!res.ok || !res.body || res.body.ok === false) {
          var msg = res.body && res.body.error && res.body.error.message ? res.body.error.message : t("err.generic");
          setStatus(msg, "err");
          return;
        }
        render(res.body);
        setStatus(res.body.display + " · " + res.body.primary + " · " + res.body.elapsed_ms + "ms", "");
      })
      .catch(function () { setStatus(t("err.generic"), "err"); })
      .then(function () {
        state.busy = false;
        $("searchBtn").disabled = false;
        $("searchBtn").textContent = t("btn.search");
        $("propAgain").disabled = !state.last;
      });
  }

  function softDots(s) {
    return esc(s).replace(/\./g, ".\u200b");
  }

  function fill(s, map) {
    return String(s).replace(/\{(\w+)\}/g, function (_, k) {
      return map[k] == null ? "" : String(map[k]);
    });
  }

  function render(rep) {
    state.report = rep;
    renderPath(rep);
    renderRecords(rep);
    renderProp(rep);
    renderSec(rep);
    renderNS(rep);
    renderDel(rep);
    renderTerm(rep);
    var hasRows = rep && rep.records && rep.records.length;
    $("copyRec").disabled = !hasRows;
    $("expZone").disabled = !hasRows;
  }

  function renderPathIdle() {
    var keys = [
      ["you", "path.you"],
      ["resolver", "path.resolver"],
      ["authority", "path.auth"],
      ["tld", "path.tld"],
      ["root", "path.root"]
    ];
    var html = "";
    keys.forEach(function (pair, i) {
      html += '<div class="chain-node is-unknown"><div class="chain-k"><span class="chain-dot"></span>' + esc(t(pair[1])) + '</div><div class="chain-name">' + esc(t("path.you.wait")) + '</div><div class="chain-detail">' + esc(t("path.idle")) + "</div></div>";
      if (i < keys.length - 1) html += '<span class="chain-arrow" aria-hidden="true">→</span>';
    });
    $("chainFlow").innerHTML = html;
    badge("pathBadge", t("path.wait"), "badge-grey");
  }

  function renderPath(rep) {
    var nodes = (rep.path && rep.path.nodes) || [];
    if (!nodes.length) {
      renderPathIdle();
      return;
    }
    var html = "";
    nodes.forEach(function (node, i) {
      var view = pathView(node);
      html += '<div class="chain-node is-' + esc(node.state || "unknown") + '"><div class="chain-k"><span class="chain-dot"></span>' + esc(view.label) + '</div><div class="chain-name">' + softDots(view.name) + '</div><div class="chain-detail">' + esc(view.detail) + "</div></div>";
      if (i < nodes.length - 1) html += '<span class="chain-arrow" aria-hidden="true">→</span>';
    });
    $("chainFlow").innerHTML = html;
    var level = (rep.path && rep.path.badge) || "";
    badge("pathBadge", t("level." + level) || level || t("path.wait"), level === "complete" ? "badge-lime" : "badge-grey");
  }

  function pathView(node) {
    var key = node.key;
    if (key === "you") {
      return { label: t("path.you"), name: node.name || t("path.you.miss"), detail: node.detail || "" };
    }
    if (key === "resolver") {
      var detail = node.total ? fill(t("path.res.exact"), { e: node.exact || 0, n: node.total }) : t("path.res.none");
      if (node.failed) detail += " · " + fill(t("path.res.fail"), { n: node.failed });
      return {
        label: t("path.resolver"),
        name: node.total ? fill(t("path.res.count"), { n: node.total }) : t("path.res.none"),
        detail: detail
      };
    }
    if (key === "authority") {
      var adetail = t("path.auth.none");
      if (node.code === "aa") adetail = fill(t("path.auth.aa"), { s: node.serial });
      else if (node.code === "unreachable") adetail = t("path.auth.down") + (node.detail ? " · " + node.detail : "");
      else if (node.code === "no-answer") adetail = t("path.auth.no");
      return { label: t("path.auth"), name: node.name || t("path.auth.wait"), detail: adetail };
    }
    if (key === "tld") {
      var td = t("path.tld.skip");
      if (node.code === "ds") td = fill(t("path.tld.ds"), { n: node.ds || 0 });
      else if (node.code === "unsigned") td = t("path.tld.off");
      else if (node.code === "dnskey-only") td = t("path.tld.key");
      return { label: t("path.tld"), name: node.name || t("path.tld.wait"), detail: td };
    }
    return { label: t("path.root"), name: t("path.root.name"), detail: t("path.root.detail") };
  }

  function renderTerm(rep) {
    var text = cmdText(rep);
    var box = $("cmdBlock");
    if (box) box.textContent = text;
    state.cmd = text;
  }

  function cmdText(rep) {
    var origin = location.origin;
    var name = (rep && (rep.name || rep.display)) || "example.com";
    var type = (rep && rep.primary) || "A";
    if (type === "ALL") type = "A";
    var auth = "8.8.8.8";
    var servers = (rep && rep.nameservers && rep.nameservers.servers) || [];
    for (var i = 0; i < servers.length; i++) {
      if (servers[i].ip || servers[i].host) {
        auth = servers[i].ip || servers[i].host;
        break;
      }
    }
    var q = function (extra) {
      return origin + "/api/dns?name=" + encodeURIComponent(name) + extra;
    };
    return [
      t("api.c1"),
      "curl '" + q("&type=" + encodeURIComponent(type)) + "'",
      "",
      t("api.c2"),
      "curl '" + q("&type=SOA&server=" + encodeURIComponent(auth) + "&rd=0&dnssec=1") + "'",
      "",
      t("api.c3"),
      "curl '" + q("&type=" + encodeURIComponent(type) + "&server=1.1.1.1&rd=1") + "'",
      "",
      t("api.c4"),
      "curl -H 'Accept: application/json' '" + q("&type=" + encodeURIComponent(type)) + "'"
    ].join("\n");
  }

  function copyText(text) {
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).catch(function () { legacyCopy(text); });
      return;
    }
    legacyCopy(text);
  }

  function legacyCopy(text) {
    var area = document.createElement("textarea");
    area.value = text;
    document.body.appendChild(area);
    area.select();
    try { document.execCommand("copy"); } catch (e) {}
    document.body.removeChild(area);
  }

  function zoneText(rep) {
    var rows = (rep && rep.records) || [];
    var name = (rep && rep.name) || "zone";
    var stamp = new Date().toISOString().slice(0, 16).replace("T", " ");
    var head = "; " + name + " — wi.fs.kg (" + stamp + " UTC)\n; Snapshot of this lookup. Check it before pasting into a zone file.\n\n";
    var body = rows.map(function (r) {
      var v = String(r.data == null ? "" : r.data);
      if (r.type === "TXT") v = '"' + v.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
      return [trimDot(r.name), r.ttl, "IN", r.type, v].join("\t");
    }).join("\n");
    return head + body + "\n";
  }

  function download(filename, text) {
    var blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
  }

  function renderRecords(rep) {
    var rows = rep.records || [];
    badge("recBadge", String(rows.length), rows.length ? "badge-lime" : "badge-grey");
    if (!rows.length) {
      $("recBody").innerHTML = "<div class=\"empty\"><strong>" + esc(t("rec.none")) + "</strong></div>";
      return;
    }
    var html = "<table class=\"tbl\"><thead><tr><th>" + esc(t("col.type")) + "</th><th>" + esc(t("col.name")) + "</th><th>" + esc(t("col.value")) + "</th><th>" + esc(t("col.ttl")) + "</th></tr></thead><tbody>";
    rows.forEach(function (rr) {
      html += "<tr><td class=\"m\">" + esc(rr.type) + "</td><td class=\"m\">" + esc(trimDot(rr.name)) + "</td><td>" + esc(rr.data) + "</td><td class=\"m\">" + esc(rr.ttl) + "</td></tr>";
    });
    $("recBody").innerHTML = html + "</tbody></table>";
  }

  function renderProp(rep) {
    var prop = rep.propagation || { rows: [] };
    var rows = prop.rows || [];
    if (!rows.length) {
      $("propBody").innerHTML = "<div class=\"empty\"><strong>" + esc(t("prop.empty")) + "</strong></div>";
      return;
    }
    var html = "<table class=\"tbl\"><thead><tr><th>" + esc(t("col.server")) + "</th><th>" + esc(t("col.answer")) + "</th><th>" + esc(t("col.rtt")) + "</th><th>" + esc(t("col.state")) + "</th></tr></thead><tbody>";
    rows.forEach(function (row) {
      var label = t("state." + row.state) || row.state;
      html += "<tr><td class=\"m\">" + esc(row.name || row.server) + "<div class=\"fine\">" + esc(row.server || "") + (row.rcode ? " · " + esc(row.rcode) : "") + "</div></td><td>" + esc(row.answer || row.error || "—") + "</td><td class=\"m\">" + (row.elapsed_ms ? esc(row.elapsed_ms) + "ms" : "—") + "</td><td><span class=\"dns-tag dns-" + esc(row.state) + "\">" + esc(label) + "</span></td></tr>";
    });
    $("propBody").innerHTML = html + "</tbody></table>";
  }

  function renderSec(rep) {
    var sec = rep.dnssec || {};
    var level = sec.level || "unknown";
    badge("secBadge", level, level === "complete" ? "badge-lime" : "badge-grey");
    var links = [
      ["." , t("level.complete") ? "root" : "root", "assumed", state.lang === "en" ? "Resolvers ship a root trust anchor. This check does not fetch it." : "解析器自带根信任锚。这里不重新获取。"],
      [sec.apex ? sec.apex.split(".").slice(-1)[0] + "." : "TLD", "tld", sec.tldQueryOk ? (sec.tldDs > 0 ? "present" : "absent") : "unknown", sec.tldQueryOk ? ("DS " + sec.tldDs) : (state.lang === "en" ? "Query did not finish" : "查询没完成")],
      [(sec.apex || "zone") + " DNSKEY", "zone", sec.dnskeyQueryOk ? (sec.dnskey > 0 ? "present" : "absent") : "unknown", "DNSKEY " + (sec.dnskey || 0) + " · KSK " + (sec.ksk || 0) + " · DS " + (sec.apexDs || 0)],
      ["RRSIG", "rrsig", sec.rrsig ? "present" : "absent", sec.rrsig ? "RRSIG" : "—"]
    ];
    var html = "<p class=\"dns-level\">" + esc(t("level." + level) || level) + "</p><ul class=\"dns-links\">";
    links.forEach(function (link) {
      html += "<li class=\"dns-" + esc(link[2]) + "\"><b>" + esc(link[0]) + "</b><span>" + esc(link[3]) + "</span></li>";
    });
    var ad = t("ad.na");
    if (sec.ad === true) ad = t("ad.on");
    else if (sec.ad === false) ad = t("ad.off");
    html += "</ul><p class=\"fine\">" + esc(ad) + "</p>";
    $("secBody").innerHTML = html;
  }

  function renderNS(rep) {
    var ns = rep.nameservers || {};
    var serials = ns.serials || {};
    badge("nsBadge", serials.code || "—", serials.code === "synced" ? "badge-lime" : "badge-grey");
    var servers = ns.servers || [];
    if (!servers.length && !ns.soa) {
      $("nsBody").innerHTML = "<div class=\"empty\"><strong>" + esc(t("serial." + (serials.code || "none"))) + "</strong></div>";
      return;
    }
    var html = "<p class=\"dns-level\">" + esc(t("serial." + (serials.code || "none")) || serials.code) + "</p>";
    if (ns.soa) {
      var soa = ns.soa;
      var fields = [
        [t("soa.mname"), soa.mname],
        [t("soa.rname"), soa.rname],
        [t("soa.serial"), soa.serial],
        [t("soa.refresh"), soa.refresh],
        [t("soa.retry"), soa.retry],
        [t("soa.expire"), soa.expire],
        [t("soa.minimum"), soa.minimum]
      ];
      html += "<dl class=\"kv\">" + fields.map(function (row) {
        return "<div class=\"kv-row\"><dt>" + esc(row[0]) + "</dt><dd>" + esc(row[1]) + "</dd></div>";
      }).join("") + "</dl>";
    }
    html += "<div class=\"dns-ns\">";
    servers.forEach(function (n) {
      var serial = n.serial == null ? "—" : String(n.serial);
      html += "<div class=\"dns-ns-item\"><b>" + esc(n.host) + "</b><span class=\"fine\">" + esc(n.ip || "—") + (n.aa ? " · AA" : "") + "</span><span>serial " + esc(serial) + (n.elapsed_ms ? " · " + esc(n.elapsed_ms) + "ms" : "") + "</span>" + (n.error ? "<span class=\"fine\">" + esc(n.error) + "</span>" : "") + "</div>";
    });
    $("nsBody").innerHTML = html + "</div>";
  }

  function renderDel(rep) {
    var d = (rep.nameservers && rep.nameservers.delegation) || {};
    var code = d.code || "child-unavailable";
    var html = "<p class=\"dns-level\">" + esc(t("deleg." + code) || code) + "</p>";
    html += "<div class=\"dns-split\"><div><h3>" + esc(t("del.parent")) + "</h3>" + nameList(d.parent) + "</div><div><h3>" + esc(t("del.child")) + "</h3>" + (d.childKnown ? nameList(d.child) : "<p class=\"fine\">—</p>") + "</div></div>";
    if (d.glueMissing && d.glueMissing.length) {
      html += "<p class=\"fine\">" + esc(t("del.glue")) + ": " + esc(d.glueMissing.join(", ")) + "</p>";
    }
    $("delBody").innerHTML = html;
  }

  function nameList(list) {
    if (!list || !list.length) return "<p class=\"fine\">—</p>";
    return "<ul class=\"dns-names\">" + list.map(function (n) { return "<li>" + esc(n) + "</li>"; }).join("") + "</ul>";
  }

  document.addEventListener("click", function (e) {
    var tbtn = e.target.closest ? e.target.closest("[data-t]") : null;
    if (tbtn) {
      state.type = tbtn.getAttribute("data-t");
      buildChips();
      if (state.last) run(state.last);
      return;
    }
    var domain = e.target.closest ? e.target.closest("[data-domain]") : null;
    if (domain) {
      run(domain.getAttribute("data-domain"));
    }
  });

  $("dnsForm").addEventListener("submit", function (e) {
    e.preventDefault();
    run(currentName());
  });
  $("clearBtn").addEventListener("click", function () {
    $("q").value = "";
    state.last = "";
    state.report = null;
    setStatus(t("status.idle"), "");
    $("propAgain").disabled = true;
    $("copyRec").disabled = true;
    $("expZone").disabled = true;
    renderPathIdle();
    renderTerm(null);
  });
  $("copyCmd").addEventListener("click", function () {
    copyText(state.cmd || cmdText(state.report));
  });
  $("copyRec").addEventListener("click", function () {
    var rows = (state.report && state.report.records) || [];
    copyText(rows.map(function (r) { return [r.type, trimDot(r.name), r.ttl, r.data].join("\t"); }).join("\n"));
  });
  $("expZone").addEventListener("click", function () {
    if (!state.report) return;
    var name = state.report.name || "zone";
    download(name.replace(/\.$/, "") + ".zone.txt", zoneText(state.report));
  });
  $("meCopy").addEventListener("click", function () {
    var lines = [];
    document.querySelectorAll("#meKv .kv-row").forEach(function (row) {
      var k = row.querySelector("dt");
      var v = row.querySelector("dd");
      if (k && v) lines.push(k.textContent + ": " + v.textContent);
    });
    copyText(lines.join("\n"));
  });
  $("propAgain").addEventListener("click", function () {
    if (state.last) run(state.last);
  });
  $("langToggle").addEventListener("click", function () {
    state.lang = state.lang === "en" ? "zh" : "en";
    try { localStorage.setItem(LANG_KEY, state.lang); } catch (e) {}
    applyI18n();
  });

  try {
    var stored = localStorage.getItem(LANG_KEY);
    if (stored === "en" || stored === "zh") state.lang = stored;
  } catch (e) {}
  applyI18n();
  loadMe();

  var params = new URLSearchParams(location.search);
  var initial = params.get("d") || params.get("name") || "";
  var initialType = (params.get("t") || params.get("type") || "").toUpperCase();
  if (TYPES.indexOf(initialType) >= 0) state.type = initialType;
  buildChips();
  if (initial) run(initial);
})();
