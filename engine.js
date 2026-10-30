/* ScamOrNot engine — pattern-based scam analysis.
   One job: given a message, link, or address, explain the risk in plain words.
   No data leaves the browser. Pattern-matching only — never a guarantee. */
(function (global) {
  'use strict';

  var BRAND_DOMAINS = {
    paypal: ['paypal.com'], binance: ['binance.com'], coinbase: ['coinbase.com'],
    apple: ['apple.com', 'icloud.com'], amazon: ['amazon.com', 'amazon.ae', 'amazon.co.uk'],
    microsoft: ['microsoft.com', 'live.com', 'outlook.com'], netflix: ['netflix.com'],
    instagram: ['instagram.com'], facebook: ['facebook.com', 'meta.com'],
    whatsapp: ['whatsapp.com'], telegram: ['telegram.org', 't.me'],
    chase: ['chase.com'], bankofamerica: ['bankofamerica.com'], wellsfargo: ['wellsfargo.com'],
    hsbc: ['hsbc.com'], emiratesnbd: ['emiratesnbd.com'], aramex: ['aramex.com'],
    dhl: ['dhl.com'], fedex: ['fedex.com'], emiratespost: ['emiratespost.ae']
  };
  var SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'rb.gy', 'cutt.ly', 'shorturl.at', 'is.gd', 'ow.ly', 'buff.ly', 'rebrand.ly', 'bl.ink', 'short.io'];
  var RISKY_TLDS = ['.top', '.xyz', '.click', '.zip', '.mov', '.gq', '.tk', '.ml', '.cf', '.work', '.live', '.buzz', '.club', '.site', '.online', '.fun', '.icu', '.rest', '.best', '.today'];

  // Each rule: id, weight, label, why, advice, patterns (regex list)
  var RULES = [
    {
      id: 'seed_theft', weight: 50, label: 'Asks for a seed phrase, private key or password',
      why: 'No legitimate company, exchange or support agent will ever ask for these. Whoever holds them controls the wallet completely.',
      advice: 'Stop. Never type a seed phrase or private key into any website, form or chat. Real support never asks.',
      patterns: [/seed phrase/i, /recovery phrase/i, /private key/i, /12[-\s]?word/i, /24[-\s]?word/i, /enter your (wallet )?(password|pin|otp|2fa)/i, /share your (otp|verification code|one[-\s]?time code)/i, /send (me |us )?your (otp|code|password)/i, /validate your wallet/i, /connect your wallet to (claim|verify|receive)/i]
    },
    {
      id: 'advance_fee', weight: 28, label: 'Upfront fee to unlock money',
      why: 'The classic advance-fee pattern: a prize, refund, withdrawal or parcel is "yours" — after you pay a small fee first. The money behind the fee does not exist.',
      advice: 'Never pay to release money. Real refunds, prizes and withdrawals never require an upfront payment.',
      patterns: [/pay (a |an |the )?(small )?(fee|charge|deposit|amount)[^.]{0,60}(unlock|release|receive|withdraw|claim|process)/i, /(unlock|release|claim|withdraw)[^.]{0,40}(fee|payment|deposit) (of|is|required)/i, /processing fee (is )?(required|needed)/i, /clearance fee/i, /activation fee/i, /verification (fee|deposit) (of|is)/i, /refundable deposit/i, /pay [^ ]+ (first|in advance) (to|and) (receive|get|unlock)/i]
    },
    {
      id: 'giveaway_doubling', weight: 42, label: 'Send crypto to receive more back',
      why: 'Giveaway doubling ("send 0.1, get 0.2 back") is always a scam. Nothing is ever sent back.',
      advice: 'Never send crypto to "verify", "enter" or "double" it. Every such offer keeps what you send.',
      patterns: [/send (0\.\d+|\d+) ?(btc|eth|bnb|usdt|sol)[^.]{0,50}(get|receive|double|back)/i, /double your (crypto|bitcoin|money|investment)/i, /giveaway[^.]{0,40}(send|deposit)/i, /(elon|cz|binance|official)[^.]{0,30}giveaway/i, /airdrop[^.]{0,40}(send|deposit|fee)/i]
    },
    {
      id: 'guaranteed_returns', weight: 22, label: 'Guaranteed or unrealistic returns',
      why: 'Real investments cannot guarantee profit. Promised daily/weekly percentages and "risk-free" returns are the bait in almost every investment scam.',
      advice: 'Treat any guaranteed return as a red flag by itself. Check the firm is licensed by a real regulator before sending anything.',
      patterns: [/double your (crypto|bitcoin|money|investment)/i, /guaranteed (profit|return|income|earnings)/i, /risk[-\s]?free (investment|profit|trading|income)/i, /\d+\s?% (daily|weekly|monthly) (profit|return|interest|roi)/i, /(earn|make) \$\d[\d,]* (a |per )?(day|week|month) (from home|online|with)/i, /100% (profit|return|guaranteed)/i, /10x your (money|investment|deposit)/i, /passive income of \$\d/i]
    },
    {
      id: 'pig_butchering', weight: 30, label: 'Friendly stranger steering you into "trading"',
      why: 'Pig-butchering scams start as a friendly chat, then a "mentor", relative or insider introduces a trading platform. Deposits work, withdrawals never do.',
      advice: 'Never invest through a platform a stranger, online friend or "mentor" introduced. Withdrawal problems there are the trap, not a glitch.',
      patterns: [/my (uncle|aunt|mentor|teacher|friend)[^.]{0,60}(trad(e|ing)|platform|invest)/i, /(trading )?(mentor|teacher|analyst) (taught|showed|introduced) me/i, /i (made|earned) \$\d[\d,]*[^.]{0,40}(trading|investing|crypto)/i, /join (me|us) (on|in) (this|the) (trading )?platform/i, /copy my trades/i, /signal group[^.]{0,30}(vip|premium|join)/i]
    },
    {
      id: 'job_scam', weight: 24, label: 'Job or task scam pattern',
      why: 'Fake jobs monetise you three ways: upfront "training" or kit fees, cheques that bounce after you forward money, or tasks that need a "recharge" to withdraw earnings.',
      advice: 'Real employers never charge you to start, never send cheques to forward, and never make you deposit to withdraw pay.',
      patterns: [/(like|watch|follow|review)[^.]{0,30}(videos?|posts?|products?)[^.]{0,30}(\$\d|per (day|task)|earn)/i, /reshipping/i, /mystery shopper[^.]{0,40}(gift card|purchase)/i, /(training|starter kit|equipment) fee/i, /recharge[^.]{0,30}(withdraw|unlock)/i, /recharge your (task )?(account )?balance/i, /task(s)? (platform|based)[^.]{0,40}(deposit|recharge)/i, /earn \$\d+ (per|a) task/i, /overpayment[^.]{0,30}(refund|send back)/i]
    },
    {
      id: 'prize', weight: 22, label: 'Prize or lottery you never entered',
      why: 'Unsolicited "you have won" messages exist to collect fees and personal data. Legitimate lotteries do not notify winners this way.',
      advice: 'If you did not enter, you did not win. Do not pay fees or send ID documents to claim.',
      patterns: [/you (have |'ve )?won/i, /claim your (prize|reward|winnings)/i, /(lottery|raffle|sweepstakes)[^.]{0,30}(winner|won|selected)/i, /selected (as a |as the )?winner/i, /congratulations[^.]{0,40}(won|winner|prize)/i]
    },
    {
      id: 'delivery_customs', weight: 18, label: 'Parcel held — pay to release',
      why: 'Fake courier messages claim a parcel is stuck and ask for a small card payment on a look-alike page. The small fee is how your card details get stolen.',
      advice: 'Go to the courier\'s real app or website yourself and track the parcel there. Never pay through a link in a message.',
      patterns: [/(package|parcel|shipment)[^.]{0,40}(held|stuck|delayed|on hold)[^.]{0,40}(customs|fee|pay)/i, /pay[^.]{0,30}(redelivery|delivery fee|customs)/i, /your (parcel|package) (is )?(waiting|held|undeliverable)/i, /arrange redelivery/i]
    },
    {
      id: 'payment_redflags', weight: 20, label: 'Payment demanded in gift cards, crypto or wire to a person',
      why: 'Scammers insist on payment methods that cannot be reversed. No government, bank or real company asks for gift cards or crypto to settle a bill or a problem.',
      advice: 'If payment must be gift cards, crypto, or a wire to an individual — it is a scam. Stop and verify through the official number.',
      patterns: [/pay(ment)? (with|in|using|by) (gift ?cards?|bitcoin|btc|crypto|usdt|steam|google play|itunes|apple gift)/i, /buy (gift ?cards?|google play cards?|steam cards?)[^.]{0,40}(pay|settle|clear)/i, /wire (the )?money to/i, /send (the )?(payment|money) to this (wallet|address|account) (first|now|today)/i]
    },
    {
      id: 'impersonation_pressure', weight: 16, label: 'Authority impersonation with a threat',
      why: 'Fake police, tax, bank-fraud and immigration messages create fear so you act before thinking. Real authorities do not demand instant payment or secrecy.',
      advice: 'Hang up / close the message. Call the institution on the number from its official website or the back of your card.',
      patterns: [/(police|irs|tax (office|authority)|immigration|customs officer|fraud department)[^.]{0,60}(arrest|warrant|deport|frozen|seized|suspend)/i, /your account (has been|will be) (frozen|suspended|closed|blocked)[^.]{0,40}(immediately|today|unless)/i, /legal action (will be|has been) (taken|initiated)/i, /arrest warrant/i]
    },
    {
      id: 'urgency', weight: 12, label: 'Heavy urgency and pressure',
      why: 'Countdown pressure is a tool to stop you checking. Legitimate organisations give you time and official channels.',
      advice: 'Slow down. Any message that cannot survive a 10-minute pause and an independent check is not worth obeying.',
      patterns: [/act (now|immediately|fast)/i, /within (the next )?\d+ (hours?|minutes?)[^.]{0,40}(or|suspend|closed|lose|expire)/i, /last chance/i, /expires (today|tonight|in \d+)/i, /immediately or (else|your)/i, /urgent action required/i, /respond (immediately|within \d+)/i, /offer ends (today|tonight|soon)/i]
    },
    {
      id: 'secrecy', weight: 15, label: 'Asked to keep it secret or move apps',
      why: 'Isolation protects the scam: moving to WhatsApp/Telegram and "tell no one" stops family, banks and platforms from warning you.',
      advice: 'A request for secrecy is itself the warning. Tell someone you trust and check together.',
      patterns: [/don'?t tell (anyone|anybody|your)/i, /keep (this|it) (secret|confidential|between us)/i, /(move|switch|continue) (this )?(to|on) (whatsapp|telegram|signal)/i, /delete this (chat|message|conversation)/i, /do not (inform|tell|alert) (your )?(bank|branch|family)/i]
    },
    {
      id: 'free_email_company', weight: 10, label: 'Company or bank writing from a free email address',
      why: 'Banks, exchanges and large companies do not run official business from @gmail.com or @yahoo.com addresses.',
      advice: 'Check the sender domain letter by letter. Contact the company through its official site, not by replying.',
      patterns: [/(bank|exchange|support|official|admin|finance|billing|security)[a-z0-9._-]*@(gmail|yahoo|hotmail|outlook|protonmail)\.com/i]
    },
    {
      id: 'account_verify_bait', weight: 16, label: '"Verify your account" bait',
      why: 'The most common phishing shape: a problem with your account, and a link or form to "verify" — built to harvest your login and codes.',
      advice: 'Never verify through a message link. Open the official app yourself and check there.',
      patterns: [/verify your (account|identity|wallet|payment)[^.]{0,40}(click|link|button|below|now)/i, /validate your (wallet|account)/i, /confirm your (account|identity|details) (now|here|below|immediately)/i, /your account (will be|has been) (limited|restricted|suspended)[^.]{0,50}(verify|confirm)/i, /unusual (activity|sign[-\s]?in)[^.]{0,50}(verify|confirm|secure)/i]
    },
    {
      id: 'romance', weight: 14, label: 'Fast romance leading to money',
      why: 'Romance scams build intense closeness quickly, then an emergency, a customs problem, or an investment "opportunity" needs your money.',
      advice: 'Never send money to someone you have not met in person — for any reason, however real it feels.',
      patterns: [/(my love|darling|dear)[^.]{0,80}(send|transfer|help me with) \$\d/i, /stuck (in|at) (customs|the airport|abroad)[^.]{0,50}(money|send|\$)/i, /i (will|want to) (marry|come to) you[^.]{0,60}(but|need|first)/i, /gift cards?[^.]{0,30}(my (phone|internet)|so we can talk)/i]
    }
  ];

  function excerptAround(text, match) {
    var i = text.toLowerCase().indexOf(match.toLowerCase());
    if (i < 0) return match.slice(0, 90);
    var start = Math.max(0, i - 25), end = Math.min(text.length, i + match.length + 35);
    return (start > 0 ? '…' : '') + text.slice(start, end).replace(/\s+/g, ' ').trim() + (end < text.length ? '…' : '');
  }

  function verdictFor(score) {
    if (score >= 70) return { band: 'scam', label: 'Almost certainly a scam', color: '#e5484d' };
    if (score >= 45) return { band: 'high', label: 'High risk — do not proceed', color: '#f76b15' };
    if (score >= 20) return { band: 'suspicious', label: 'Suspicious — verify independently first', color: '#ffb224' };
    return { band: 'low', label: 'No strong scam signals found', color: '#46a758' };
  }

  function analyzeText(raw) {
    var text = String(raw || '');
    var flags = [], advice = [], score = 0;
    // Protective/educational framing ("never share your seed phrase") is safety advice, not theft.
    var protectiveSeed = /never (share|give|enter|reveal|type) (your |a )?(seed phrase|recovery phrase|private key)/i.test(text) || /(will|would) never ask (you )?for (your )?(seed|private key|password)/i.test(text);
    RULES.forEach(function (rule) {
      if (rule.id === 'seed_theft' && protectiveSeed) return;
      for (var p = 0; p < rule.patterns.length; p++) {
        var m = text.match(rule.patterns[p]);
        if (m) {
          score += rule.weight;
          flags.push({ id: rule.id, weight: rule.weight, label: rule.label, why: rule.why, excerpt: excerptAround(text, m[0]) });
          if (advice.indexOf(rule.advice) < 0) advice.push(rule.advice);
          break; // one hit per rule
        }
      }
    });
    // links inside the message get URL checks too
    var urls = text.match(/https?:\/\/[^\s<>"')]+/gi) || [];
    var urlFindings = [];
    urls.slice(0, 3).forEach(function (u) {
      var r = analyzeUrl(u);
      r.flags.forEach(function (f) { urlFindings.push(f); });
    });
    urlFindings.forEach(function (f) {
      score += Math.round(f.weight * 0.8);
      flags.push(f);
    });
    if (urls.length && !urlFindings.length) {
      flags.push({ id: 'url_present', weight: 0, label: 'Contains a link', why: 'The link itself shows no structural red flags. Still open important accounts through the official app, not message links.', excerpt: urls[0].slice(0, 90) });
    }
    score = Math.min(100, score);
    var safeSigns = [];
    if (!/pay|send|transfer|fee|deposit|card|bank|account number/i.test(text)) safeSigns.push('No payment or money request detected');
    if (!urls.length) safeSigns.push('No links in the message');
    if (!/urgent|immediately|act now|expires|within \d+ hours/i.test(text)) safeSigns.push('No deadline pressure or urgency language');
    if (!/password|otp|code|seed|private key/i.test(text)) safeSigns.push('Does not ask for passwords, codes or keys');
    return buildResult('message', score, flags, advice, safeSigns, urls.length ? { linksChecked: urls.length } : {});
  }

  function analyzeUrl(raw) {
    var input = String(raw || '').trim();
    var flags = [], advice = [], score = 0;
    var url;
    try { url = new URL(/^https?:\/\//i.test(input) ? input : 'http://' + input); }
    catch (e) { return buildResult('link', 0, [{ id: 'bad_url', weight: 0, label: 'Not a readable web address', why: 'This does not parse as a URL, so there is nothing safe to open.', excerpt: input.slice(0, 90) }], ['Do not try to open malformed links from messages.'], [], {}); }
    var host = url.hostname.toLowerCase();
    var full = input.toLowerCase();
    function hit(weight, id, label, why, adv) {
      score += weight; flags.push({ id: id, weight: weight, label: label, why: why, excerpt: host });
      if (adv && advice.indexOf(adv) < 0) advice.push(adv);
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) hit(30, 'ip_host', 'Link uses a raw IP address instead of a name', 'Real companies serve login pages from their named domain. Raw IP addresses are a classic phishing host.', 'Do not log in or pay on an IP-address link.');
    if (host.indexOf('xn--') >= 0) hit(25, 'punycode', 'Look-alike (punycode) domain', 'Punycode domains imitate real brands with swapped characters that look identical at a glance.', 'Type the real address yourself instead of using this link.');
    if (full.indexOf('@') > full.indexOf('://') + 2 && full.split('@')[0].indexOf('.') > 0) hit(20, 'at_sign', 'Hidden destination (@ trick)', 'Everything before the @ is ignored by the browser — the real destination is what follows it.', 'Do not trust the readable name in this link.');
    var labels = host.split('.');
    if (labels.length >= 4) hit(10, 'deep_sub', 'Unusually deep subdomain chain', 'Long subdomain chains are used to bury the real domain behind a trusted-looking name.', 'Read the domain right-to-left: only the last two parts are the real site.');
    RISKY_TLDS.forEach(function (t) { if (host.endsWith(t)) hit(10, 'risky_tld', 'Cheap / frequently abused domain ending (' + t + ')', 'These endings cost almost nothing and are heavily used for throwaway scam sites. Not proof alone — but it adds up.', null); });
    if (SHORTENERS.indexOf(host) >= 0) hit(10, 'shortener', 'Shortened link hides the destination', 'Shorteners are legitimate in general, but in an unsolicited message they hide where you will actually land.', 'Do not open shortened links from strangers or unexpected messages.');
    var brandHit = null;
    Object.keys(BRAND_DOMAINS).forEach(function (brand) {
      if (host.indexOf(brand) >= 0) {
        var ok = BRAND_DOMAINS[brand].some(function (d) { return host === d || host.endsWith('.' + d); });
        if (!ok) brandHit = brand;
      }
    });
    if (brandHit) hit(40, 'brand_fake', 'Brand name in the address — but not the brand\'s real domain', 'The address borrows "' + brandHit + '" to look official while belonging to someone else. This is the single strongest phishing sign.', 'Go to the brand\'s real website or app yourself. Never log in through this link.');
    if (/(login|signin|verify|secure|account|update|confirm|wallet|claim)/i.test(url.pathname + url.search) && !brandHit) {
      var onRealBrand = Object.keys(BRAND_DOMAINS).some(function (b) { return BRAND_DOMAINS[b].some(function (d) { return host === d || host.endsWith('.' + d); }); });
      if (!onRealBrand) hit(15, 'login_path', 'Login / verification page on an unrecognised domain', 'Credential-harvesting pages copy real login screens onto domains the brand does not own.', 'Only enter passwords inside the official app or a domain you typed yourself.');
    }
    if (url.protocol === 'http:' && /(login|signin|verify|pay|account)/i.test(url.pathname + url.search)) hit(15, 'http_login', 'Unencrypted (http) page asking for login or payment', 'Real banks and exchanges never take credentials over plain http.', 'Never enter a password or card on an http page.');
    if (input.length > 120) hit(5, 'long_url', 'Very long, cluttered link', 'Excess length and random-looking strings are used to hide the destination and tracking tokens.', null);
    score = Math.min(100, score);
    var safeSigns = [];
    if (!flags.length) safeSigns.push('Domain structure looks ordinary — no impersonation pattern detected');
    return buildResult('link', score, flags, advice, safeSigns, { host: host });
  }

  function analyzeAddress(raw) {
    var a = String(raw || '').trim();
    var flags = [], advice = [], score = 0;
    var kind = null;
    if (/^0x[0-9a-fA-F]{40}$/.test(a)) kind = 'Ethereum / EVM address';
    else if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(a) || /^bc1[ac-hj-np-z02-9]{11,71}$/i.test(a)) kind = 'Bitcoin address';
    else if (/^T[1-9A-HJ-NP-Za-z]{33}$/.test(a)) kind = 'Tron address';
    else if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a)) kind = 'Solana-style address';
    if (!kind) {
      return buildResult('address', 0, [{ id: 'addr_unknown', weight: 0, label: 'Not a recognised address format', why: 'This does not match a standard crypto address format. Double-check what you were given before using it anywhere.', excerpt: a.slice(0, 90) }], ['Ask the sender to confirm the exact address and chain — a wrong address loses funds permanently.'], [], {});
    }
    flags.push({ id: 'addr_format', weight: 0, label: kind + ' — format is valid', why: 'A valid format only means the address exists in shape. It says nothing about who controls it or whether the deal around it is real. Scam addresses are perfectly valid addresses.', excerpt: a.slice(0, 18) + '…' + a.slice(-8) });
    advice.push('An address can never prove a deal is real. Judge the offer, not the address.');
    advice.push('Send a tiny test amount first on any new counterparty — and never send to "verify" or "unlock" a larger amount.');
    return buildResult('address', score, flags, advice, ['Address format is structurally valid'], { kind: kind });
  }

  function buildResult(type, score, flags, advice, safeSigns, meta) {
    flags.sort(function (x, y) { return y.weight - x.weight; });
    var v = verdictFor(score);
    return { type: type, score: score, band: v.band, verdict: v.label, color: v.color, flags: flags, advice: advice, safeSigns: safeSigns, meta: meta || {}, checkedAt: new Date().toISOString() };
  }

  var api = { analyzeText: analyzeText, analyzeUrl: analyzeUrl, analyzeAddress: analyzeAddress, ruleCount: RULES.length };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  global.ScamEngine = api;
})(typeof window !== 'undefined' ? window : globalThis);
