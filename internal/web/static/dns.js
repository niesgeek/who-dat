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
      "rec.title": "记录",
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
      "api.title": "命令行",
      "api.lede": "curl 的 User-Agent 得到 dig 风格的文本。浏览器和 Accept: application/json 得到 JSON。format=json 或 format=text 可以强制。",
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
      "api.title": "curl",
      "api.lede": "A curl User-Agent gets dig-style text. Browsers and Accept: application/json get JSON. format=json or format=text forces one.",
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

  var state = { lang: "zh", type: "ALL", busy: false, last: "" };

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
      .then(renderMe)
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

  function render(rep) {
    renderRecords(rep);
    renderProp(rep);
    renderSec(rep);
    renderNS(rep);
    renderDel(rep);
    var shown = rep.primary || "A";
    var qname = rep.display || rep.name || "example.com";
    $("curlBox").textContent = "curl \"" + location.origin + "/api/dns?name=" + encodeURIComponent(rep.name || qname) + "&type=" + encodeURIComponent(shown) + "\"";
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
    setStatus(t("status.idle"), "");
    $("propAgain").disabled = true;
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
