"use strict";

/* === IMPORTS === */
const { Telegraf, Markup } = require("telegraf");
const axios = require("axios");
const mysql = require("mysql2/promise");
require("dotenv").config();

/* === BOT === */
const bot = new Telegraf(process.env.TG_BOT_TOKEN);

/* === API KEYS === */
const MORALIS = process.env.MORALIS_API_KEY;
const GOPLUS  = process.env.GOPLUS_API_KEY;
const LUNAR   = process.env.LUNARCRUSH_API_KEY;
const XSCAN   = process.env.XSCAN_BEARER;
const PUMPFUN = process.env.PUMPFUN_API_URL;

const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || "";
const BSCSCAN_API_KEY   = process.env.BSCSCAN_API_KEY   || "";
const YT_API_KEY        = process.env.YT_API_KEY        || ""; // opsiyonel

/* === API KEY VALIDATION === */
if (!process.env.TG_BOT_TOKEN) {
  console.error("❌ TG_BOT_TOKEN is required!");
  process.exit(1);
}
if (!XSCAN) console.warn("⚠️  XSCAN_BEARER not found - /xscan command will have limited functionality");
if (!YT_API_KEY) console.warn("⚠️  YT_API_KEY not found - YouTube search disabled");

/* === MarkdownV2 güvenliği === */
function mdSafe(text){
  if(!text) return "";
  return text
    .replace(/([_*\[\]()~`>#+=|{}.!\\])/g, '\\$1')  // temel özel karakterler
    .replace(/-/g, '\\-')        // tire
    .replace(/\$/g, '\\$')       // dolar
    .replace(/%/g, '\\%')        // yüzde
    .replace(/&amp;/g, '&')      // html temizle
    .replace(/'/g, "'")          // tipografik apostrof
    .replace(/—/g, '\\-')        // uzun tire
    .replace(/"/g, '\\"');       // çift tırnak
}

/* === HELPERS === */
const isEvm = a => typeof a==="string" && /^0x[a-fA-F0-9]{40}$/.test(a);
const lc = s => (s||"").toLowerCase();
const normAddr = a => isEvm(a) ? ("0x"+a.slice(2).toLowerCase()) : a;
const normalizeChain = v => {
  v=(v||"").toLowerCase();
  if(v==="bnb") return "bsc";
  if(["eth","bsc","sol"].includes(v)) return v;
  return "eth";
};
const nowStr = ()=> new Date().toLocaleTimeString();

/* === DATABASE === */
const db = mysql.createConnection({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  database: process.env.DB_NAME || 'hyperbot',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || ''
});

db.then(() => {
  console.log('✅ MySQL connected');
}).catch(e => console.error('❌ MySQL error', e.message));

/* === I18N (en/tr/ru/de/zh) === */
const M = {
  en:{welcome:`🚀 **Welcome to Hype Scanner Bot!**\n\n🔍 Multi-chain token security & social scanner\n• Real-time honeypot detection\n• Trust score (0-100)\n• Liquidity & whale analysis\n• Risk & social sentiment\n\n📊 Choose a network to start:`,
    askWallet: n=>`Please send your **${n.toUpperCase()}** wallet address to monitor your trades.`,
    walletSaved: w=>`✅ Wallet saved: \`${w}\``,
    walletRemoved: w=>`✅ Unsubscribed: \`${w}\``,
    nothingRemoved: w=>`ℹ️ No matching subscription found for \`${w}\`.`,
    langSet: l=>`✅ Language changed to **${l.toUpperCase()}**`,
  },
  tr:{welcome:`🚀 **Hype Scanner Bot’a Hoşgeldiniz!**\n\n🔍 Çok-zincirli token güvenlik ve sosyal tarayıcı\n• Anlık honeypot tespiti\n• Güven skoru (0-100)\n• Likidite & balina analizi\n• Risk & sosyal duygu\n\n📊 Başlamak için ağ seçin:`,
    askWallet: n=>`Lütfen **${n.toUpperCase()}** ağındaki cüzdan adresinizi gönderin.`,
    walletSaved: w=>`✅ Cüzdan kaydedildi: \`${w}\``,
    walletRemoved: w=>`✅ Abonelikten çıkarıldı: \`${w}\``,
    nothingRemoved: w=>`ℹ️ Bu cüzdan için aktif abonelik bulunamadı: \`${w}\`.`,
    langSet: l=>`✅ Dil **${l.toUpperCase()}** olarak değiştirildi`,
  },
  ru:{welcome:`🚀 **Добро пожаловать в Hype Scanner Bot!**\n\n🔍 Мультичейн-сканер безопасности и соц. сигналов\n• Honeypot в реальном времени\n• Trust score (0–100)\n• Ликвидность и киты\n• Риск и сентимент\n\n📊 Выберите сеть для старта:`,
    askWallet:n=>`Отправьте адрес кошелька в сети **${n.toUpperCase()}** для мониторинга ваших сделок.`,
    walletSaved:w=>`✅ Кошелёк сохранён: \`${w}\``,
    walletRemoved:w=>`✅ Подписка удалена: \`${w}\``,
    nothingRemoved:w=>`ℹ️ Подписка не найдена для: \`${w}\`.`,
    langSet:l=>`✅ Язык изменён на **${l.toUpperCase()}**`,
  },
  de:{welcome:`🚀 **Willkommen bei Hype Scanner Bot!**\n\n🔍 Multichain-Token-Sicherheits- & Social-Scanner\n• Honeypot-Erkennung in Echtzeit\n• Trust Score (0–100)\n• Liquiditäts- & Wal-Analyse\n• Risiko & Stimmung\n\n📊 Wähle ein Netzwerk:`,
    askWallet:n=>`Sende deine **${n.toUpperCase()}** Wallet-Adresse zur Überwachung deiner Trades.`,
    walletSaved:w=>`✅ Wallet gespeichert: \`${w}\``,
    walletRemoved:w=>`✅ Abo entfernt: \`${w}\``,
    nothingRemoved:w=>`ℹ️ Kein Abo gefunden für: \`${w}\`.`,
    langSet:l=>`✅ Sprache geändert: **${l.toUpperCase()}**`,
  },
  zh:{welcome:`🚀 **欢迎使用 Hype Scanner Bot！**\n\n🔍 多链代币安全与社交扫描\n• 实时蜜罐检测\n• 信任分（0-100）\n• 流动性与鲸鱼分析\n• 风险与情绪\n\n📊 请选择网络开始：`,
    askWallet:n=>`请发送你在 **${n.toUpperCase()}** 网络的钱包地址，用于监控交易。`,
    walletSaved:w=>`✅ 已保存钱包：\`${w}\``,
    walletRemoved:w=>`✅ 已取消订阅：\`${w}\``,
    nothingRemoved:w=>`ℹ️ 未找到该钱包的订阅：\`${w}\`。`,
    langSet:l=>`✅ 语言已切换为 **${l.toUpperCase()}**`,
  },
};

/* === DB HELPERS === */
async function getUser(tg){
  const connection = await db;
  const [rows] = await connection.execute("SELECT * FROM users WHERE telegram_id = ?", [tg.id]);
  if(rows.length) return rows[0];
  const [result] = await connection.execute(
    "INSERT INTO users (telegram_id, username, first_name, lang, risk_profile) VALUES (?, ?, ?, ?, ?)",
    [tg.id, tg.username||null, tg.first_name||null, "en", "medium"]
  );
  const [newUser] = await connection.execute("SELECT * FROM users WHERE id = ?", [result.insertId]);
  return newUser[0];
}
async function setLang(uid,lang){ 
  const connection = await db;
  await connection.execute("UPDATE users SET lang = ? WHERE id = ?", [lang, uid]); 
}
async function setProfile(uid,profile){ 
  const connection = await db;
  await connection.execute("UPDATE users SET risk_profile = ? WHERE id = ?", [profile, uid]); 
}
async function saveWallet(uid,addr,chain){
  const A = normAddr(addr);
  const C = normalizeChain(chain);
  const connection = await db;
  await connection.execute(
    "INSERT IGNORE INTO subscriptions (user_id, wallet, chain) VALUES (?, ?, ?)",
    [uid, A, C]
  );
}
async function removeWallet(uid,addr,chain){
  const A = normAddr(addr);
  const C = normalizeChain(chain);
  const connection = await db;
  const [result] = await connection.execute("DELETE FROM subscriptions WHERE user_id = ? AND wallet = ? AND chain = ?", [uid, A, C]);
  return result.affectedRows;
}
async function saveAnalysis(uid,addr,chain,data,trust){
  const connection = await db;
  await connection.execute(
    "INSERT INTO token_analyses (user_id, token_address, chain, analysis_data, trust_score) VALUES (?, ?, ?, ?, ?)",
    [uid, normAddr(addr), normalizeChain(chain), JSON.stringify(data), trust]
  );
}

/* === EXTERNAL HELPERS === */
async function detectEvmChain(addr){
  if(!isEvm(addr) || !MORALIS) return "eth";
  try{
    const eth = await axios.get(`https://deep-index.moralis.io/api/v2/erc20/${addr}`,{
      headers:{'X-API-Key':MORALIS}, params:{chain:"eth"}
    });
    if(eth.data) return "eth";
  }catch{}
  try{
    const bsc = await axios.get(`https://deep-index.moralis.io/api/v2/erc20/${addr}`,{
      headers:{'X-API-Key':MORALIS}, params:{chain:"bsc"}
    });
    if(bsc.data) return "bsc";
  }catch{}
  return "eth";
}

async function getMoralis(addr,chain){
  if(!MORALIS || !isEvm(addr)) return null;
  try{
    const r=await axios.get(`https://deep-index.moralis.io/api/v2/erc20/${addr}`,{
      headers:{'X-API-Key':MORALIS},
      params:{chain}
    });
    return r.data;
  }catch(e){
    console.error(`Moralis API error for ${addr}:`, e.message);
    return null;
  }
}

async function getGoPlus(addr,chain){
  if(!GOPLUS || !isEvm(addr)) return null;
  try{
    const cid=chain==="eth"?"1":chain==="bsc"?"56":"1";
    const r=await axios.get(`https://api.gopluslabs.io/api/v1/token_security/${cid}`,{
      params:{contract_addresses:normAddr(addr),api_key:GOPLUS}
    });
    return r.data?.result?.[normAddr(addr)]||null;
  }catch(e){
    console.error(`GoPlus API error for ${addr}:`, e.message);
    return null;
  }
}

async function getContractVerification(addr, chain){
  try{
    let base="", key="";
    if(chain==="eth"){ base="https://api.etherscan.io/api"; key=ETHERSCAN_API_KEY; }
    if(chain==="bsc"){ base="https://api.bscscan.com/api"; key=BSCSCAN_API_KEY; }
    if(!base || !key) return {verified:false};
    const res = await axios.get(base,{params:{
      module:"contract", action:"getsourcecode", address:normAddr(addr), apikey:key
    }});
    const row = (Array.isArray(res.data?.result) ? res.data.result[0] : {}) || {};
    const verified = !!(row.SourceCode && row.SourceCode.length);
    return { verified, contractName: row.ContractName || "Unknown" };
  }catch{ return {verified:false}; }
}

async function getDexScreener(addr){
  try{
    const r = await axios.get(`https://api.dexscreener.com/latest/dex/tokens/${addr}`);
    const pair = r.data?.pairs?.[0];
    if(!pair) return null;
    return {
      chain: pair.chainId,
      dex: pair.dexId,
      base: pair.baseToken?.symbol,
      quote: pair.quoteToken?.symbol,
      priceUsd: pair.priceUsd,
      fdv: pair.fdv,
      mcap: pair.marketCap,
      liquidityUsd: pair.liquidity?.usd,
      volume24h: pair.volume?.h24,
      buys: pair.txns?.h24?.buys,
      sells: pair.txns?.h24?.sells,
      url: pair.url
    };
  }catch{ return null; }
}

async function getLunar(symbol){
  if(!LUNAR) return null;
  try{
    const r=await axios.get(`https://lunarcrush.com/api3/coins`,{
      params:{symbol:(symbol||"").toUpperCase(), key:LUNAR}
    });
    return r.data?.data?.[0]||null;
  }catch(e){
    console.error(`LunarCrush API error for ${symbol}:`, e.message);
    return null;
  }
}

async function getPumpfun(mint){
  if(!PUMPFUN) return null;
  try{
    const r=await axios.get(`${PUMPFUN}/token/${mint}`);
    return r.data;
  }catch(e){
    console.error(`Pumpfun API error for ${mint}:`, e.message);
    return null;
  }
}

async function getXscan(symbol){
  if(!symbol || !XSCAN) return null;
  try{
    const r=await axios.get(`https://api.xscan.io/social/${symbol}`,{headers:{Authorization:`Bearer ${XSCAN}`}});
    return r.data;
  }catch(e){
    console.error(`XScan API error for ${symbol}:`, e.message);
    return null;
  }
}

async function searchReddit(term, limit=5){
  try{
    const r = await axios.get("https://www.reddit.com/search.json",{
      params:{q: term, sort:"new", limit}
    });
    const posts = (r.data?.data?.children||[]).map(c=>c.data).map(p=>({
      title: p.title, score:p.score, subreddit: p.subreddit, url: "https://reddit.com"+p.permalink
    }));
    return {count: posts.length, items: posts};
  }catch(e){
    console.error(`Reddit API error for ${term}:`, e.message);
    return null;
  }
}

async function searchYouTube(term, limit=5){
  if(!YT_API_KEY) return null;
  try{
    const r = await axios.get("https://www.googleapis.com/youtube/v3/search",{
      params:{
        part:"snippet", q:term, maxResults:limit, type:"video", key:YT_API_KEY, order:"date"
      }
    });
    const items = (r.data?.items||[]).map(i=>({
      title: i.snippet?.title,
      channel: i.snippet?.channelTitle,
      url: `https://www.youtube.com/watch?v=${i.id?.videoId}`
    }));
    return {count: items.length, items};
  }catch(e){
    console.error(`YouTube API error for ${term}:`, e.message);
    return null;
  }
}

/* === SCAM HEURISTICS === */
function scamHeuristics(go){
  if(!go) return { flags:[], scorePen:0, isScam:false };
  const flags=[];
  let pen=0;

  const bool = k => (go[k]==="1" || go[k]===1 || go[k]===true);

  if(bool("is_honeypot")) { flags.push("Honeypot"); pen+=70; }
  if(parseFloat(go.buy_tax)>10) { flags.push("High Buy Tax"); pen+=20; }
  if(parseFloat(go.sell_tax)>15){ flags.push("High Sell Tax"); pen+=20; }
  if(bool("is_proxy")) { flags.push("Proxy"); pen+=10; }
  if(bool("is_mintable")) { flags.push("Mintable"); pen+=15; }
  if(bool("is_blacklisted")) { flags.push("Blacklist Enabled"); pen+=25; }
  if(bool("can_take_back_ownership")) { flags.push("Owner Can Reclaim"); pen+=15; }
  if(bool("slippage_modifiable")) { flags.push("Slippage Modifiable"); pen+=10; }
  if(bool("is_airdrop_scam")) { flags.push("Airdrop Scam Pattern"); pen+=25; }
  if(bool("selfdestruct")) { flags.push("Selfdestruct Present"); pen+=25; }
  const ownerPerc = parseFloat(go.owner_percent||go.owner_balance_percent||0);
  if(ownerPerc>30){ flags.push(`Owner ${ownerPerc}%`); pen+=25; }

  return { flags, scorePen:pen, isScam: pen>=50 || flags.includes("Honeypot") };
}

/* === TRUST SCORE === */
function calcTrust(go,social){
  let t=100;
  if(go){
    const sh = scamHeuristics(go);
    t -= sh.scorePen;
  }
  if(social?.galaxy_score) t+=Math.floor(social.galaxy_score/20);
  return Math.max(0,Math.min(100,t));
}

/* === REPORT BUILDERS === */
function bubbleMapsLink(addr, chain){
  const A = normAddr(addr);
  if(chain==="eth") return `https://app.bubblemaps.io/eth/token/${A}`;
  if(chain==="bsc") return `https://app.bubblemaps.io/bsc/token/${A}`;
  // SOL şu an desteklenmeyebilir, yine de bilgi amaçlı:
  return null;
}

function buildSocialBlock({symbol, xscan, reddit, youtube, lunar}){
  let t = `📣 **Social Overview**\n`;
  if(lunar){
    t += `• 🌌 GalaxyScore: ${lunar.galaxy_score ?? "?"} | SocialVol24h: ${lunar.social_volume_24h ?? "?"}\n`;
  }
  if(xscan){
    t += `• 𝕏 Mentions(24h): ${xscan.mentions ?? "?"} | Sentiment: ${xscan.sentiment ?? "?"}/5\n`;
  }
  if(reddit){
    t += `• Reddit posts: ${reddit.count} — ${reddit.items.slice(0,3).map(p=>`[${p.subreddit}]`).join(" ")}\n`;
  }
  if(youtube){
    t += `• YouTube recent: ${youtube.count}\n`;
  }
  if(!xscan && !reddit && !youtube && !lunar) t += `• No social data available.\n`;
  return t + "\n";
}

function buildReport({addr,chain,trust,go,social,verify,dex,pump, xscan, reddit, youtube}){
  const scam = scamHeuristics(go);
  let txt = `🔎 **Token Analysis Report**\n\n`;
  txt += `📄 Contract: \`${addr.slice(0,8)}...${addr.slice(-6)}\`\n⛓️ Chain: ${chain.toUpperCase()}\n\n`;
  txt += `📊 **Trust Score:** ${trust}/100 — ${trust>=70?"🟢 SAFE":trust>=40?"🟡 MEDIUM":"🔴 HIGH"}\n`;
  if(scam.isScam) txt += `\n🚨 **SCAM Signals:** ${scam.flags.join(", ")}\n`;
  txt += `\n`;

  if(verify && (chain==="eth"||chain==="bsc")){
    txt += `🔍 **Contract**\n• Verified: ${verify.verified?"✅ Yes":"❌ No"}\n• Name: ${verify.contractName||"Unknown"}\n\n`;
  }

  if(go){
    txt += `🛡 **GoPlus Security**\n`;
    txt += `• 🍯 Honeypot: ${go.is_honeypot==="1"?"❌ Detected":"✅ Safe"}\n`;
    txt += `• 💰 BuyTax: ${go.buy_tax ?? "?"}% | 💸 SellTax: ${go.sell_tax ?? "?"}%\n`;
    txt += `• Proxy: ${go.is_proxy==="1"?"⚠️ Yes":"✅ No"} | Mintable: ${go.is_mintable==="1"?"⚠️ Yes":"✅ No"}\n`;
    if(go.is_blacklisted) txt += `• Blacklist Enabled: ${go.is_blacklisted==="1"?"⚠️ Yes":"No"}\n`;
    if(go.owner_percent)  txt += `• Owner %: ${go.owner_percent}\n`;
    txt += `\n`;
  }

  if(dex){
    txt += `💧 **Dexscreener (Market)**\n`;
    txt += `• Pair: ${dex.base||"?"}/${dex.quote||"?"} on ${dex.dex||"?"}\n`;
    txt += `• Price: ${dex.priceUsd?("$"+Number(dex.priceUsd).toFixed(6)):"?"}\n`;
    txt += `• Liquidity: ${dex.liquidityUsd?("$"+Number(dex.liquidityUsd).toLocaleString()):"?"}\n`;
    txt += `• 24h Vol: ${dex.volume24h?("$"+Number(dex.volume24h).toLocaleString()):"?"}\n`;
    txt += `• FDV: ${dex.fdv?("$"+Number(dex.fdv).toLocaleString()):"?"} | Mcap: ${dex.mcap?("$"+Number(dex.mcap).toLocaleString()):"?"}\n`;
    txt += `• 24h Txns (B/S): ${dex.buys ?? "?"}/${dex.sells ?? "?"}\n`;
    if(dex.url) txt += `• Chart: ${dex.url}\n`;
    txt += `\n`;
  }

  // Social block (Lunar + XSCAN + Reddit + YouTube)
  const socialBlock = buildSocialBlock({symbol: social?.symbol, xscan, reddit, youtube, lunar:social});
  txt += socialBlock;

  if(pump){
    const buyers = pump.buyers ?? pump.metrics?.buyers ?? "?";
    const sellers = pump.sellers ?? pump.metrics?.sellers ?? "?";
    txt += `🟣 **Pump.fun**\n`;
    txt += `• Curve: ${pump.curve ?? "?"}% | MCAP: ${pump.market_cap?("$"+pump.market_cap):"?"}\n`;
    txt += `• Buyers/Sellers (24h): ${buyers}/${sellers}\n`;
    if(pump.twitter) txt += `• X: ${pump.twitter}\n`;
    txt += `\n`;
  }

  const bmap = bubbleMapsLink(addr,chain);
  if(bmap){
    txt += `🫧 **BubbleMaps (Holders Clusters)**\n• ${bmap}\n`;
  }

  return txt.trim();
}

/* === SESSION STATE (komutlar arası bağ) === */
const sessionState = new Map(); // key: telegram_id, val: { lastToken, lastChain, lastSymbol }

/* === COMMANDS === */
// /start
bot.start(async ctx=>{
  try {
    const u=await getUser(ctx.from);
    const lang=u.lang||"en";
    const kb=Markup.inlineKeyboard([
      [Markup.button.callback("🔸 BNB","net:bnb"),Markup.button.callback("⚡ ETH","net:eth")],
      [Markup.button.callback("🟣 SOL","net:sol")]
    ]);
    await ctx.reply(M[lang].welcome,{parse_mode:"Markdown",reply_markup:kb.reply_markup});
  } catch(e) {
    console.error('Start command error:', e.message);
    await ctx.reply("❌ An error occurred. Please try again later.");
  }
});

// ağ seçimi → cüzdan
bot.action(/net:(bnb|eth|sol)/, async ctx=>{
  try {
    const u=await getUser(ctx.from);
    const lang=u.lang||"en";
    const net=ctx.match[1];
    sessionState.set(ctx.from.id,{ ...(sessionState.get(ctx.from.id)||{}), network:net });
    await ctx.answerCbQuery(`${net.toUpperCase()} selected`);
    await ctx.reply(M[lang].askWallet(net),{parse_mode:"Markdown"});
  } catch(e) {
    console.error('Network selection error:', e.message);
    await ctx.answerCbQuery("❌ Error occurred");
  }
});

// wallet kaydı öncelikli handler
bot.on("text", async (ctx,next)=>{
  try {
    const state=sessionState.get(ctx.from.id);
    if(state && state.network){
      const u=await getUser(ctx.from);
      const chain = normalizeChain(state.network);
      const addr  = normAddr(ctx.message.text.trim());
      await saveWallet(u.id, addr, chain);
      sessionState.set(ctx.from.id, {...state, network:null});
      const lang=u.lang||"en";
      return ctx.reply(M[lang].walletSaved(addr),{parse_mode:"Markdown"});
    }
    return next();
  } catch(e) {
    console.error('Text handler error:', e.message);
    await ctx.reply("❌ An error occurred while processing your message.");
  }
});

// /language en|tr|ru|de|zh
bot.command("language", async ctx=>{
  try {
    const code=(ctx.message.text.split(/\s+/)[1]||"").toLowerCase();
    if(!["en","tr","ru","de","zh"].includes(code)) return ctx.reply("Usage: /language en|tr|ru|de|zh");
    const u=await getUser(ctx.from);
    await setLang(u.id,code);
    await ctx.reply(M[code].langSet(code),{parse_mode:"Markdown"});
  } catch(e) {
    console.error('Language command error:', e.message);
    await ctx.reply("❌ An error occurred while changing language.");
  }
});

// /setprofile
bot.command("setprofile",async ctx=>{
  const p=(ctx.message.text.split(/\s+/)[1]||"").toLowerCase();
  if(!["low","medium","high"].includes(p)) return ctx.reply("Usage: /setprofile low|medium|high");
  const u=await getUser(ctx.from);
  await setProfile(u.id,p);
  ctx.reply(`✅ Risk profile set to **${p.toUpperCase()}**`,{parse_mode:"Markdown"});
});

// /subscribe [wallet] [chain]
bot.command("subscribe",async ctx=>{
  const [_,addrRaw,chainRaw='eth']=ctx.message.text.split(/\s+/);
  if(!addrRaw) return ctx.reply("Usage: /subscribe [wallet] [chain]");
  const u=await getUser(ctx.from);
  const addr = normAddr(addrRaw);
  const chain= normalizeChain(chainRaw);
  await saveWallet(u.id, addr, chain);
  ctx.reply(`✅ Subscribed wallet: ${addr} on ${chain.toUpperCase()}`);
});

// /unsubscribe [wallet] [chain]
bot.command("unsubscribe",async ctx=>{
  const [_,addrRaw,chainRaw='eth']=ctx.message.text.split(/\s+/);
  if(!addrRaw) return ctx.reply("Usage: /unsubscribe [wallet] [chain]");
  const u=await getUser(ctx.from);
  const addr = normAddr(addrRaw);
  const chain= normalizeChain(chainRaw);
  const removed = await removeWallet(u.id, addr, chain);
  const lang = u.lang || "en";
  if(removed>0) ctx.reply(M[lang].walletRemoved(addr));
  else ctx.reply(M[lang].nothingRemoved(addr));
});

// /check [address]
bot.command("check", async ctx=>{
  try {
    const addrRaw = (ctx.message.text.split(/\s+/)[1]||"").trim();
    if(!addrRaw) return ctx.reply("Usage: /check [token_address]");
    const u=await getUser(ctx.from);
    const addr = normAddr(addrRaw);

    let chain = "sol";
    if(isEvm(addr)) chain = await detectEvmChain(addr);

    await ctx.reply(`🔎 Scanning on ${chain.toUpperCase()}...`);

    let mor = null, go = null, verify=null, dex=null, lunar=null, trust=50;
    if(chain!=="sol"){
      mor    = await getMoralis(addr,chain);
      go     = await getGoPlus(addr,chain);
      verify = await getContractVerification(addr,chain);
      dex    = await getDexScreener(addr);
      if(mor?.symbol){ lunar = await getLunar(mor.symbol); }
      trust  = calcTrust(go,lunar);
    }else{
      dex   = await getDexScreener(addr);
      trust = 60;
    }

    // Social extras
    const symbolGuess = (mor?.symbol || dex?.base || "").toUpperCase();
    const xscan = symbolGuess ? await getXscan(symbolGuess) : null;
    const reddit = symbolGuess ? await searchReddit(symbolGuess+" token",5) : null;
    const youtube= symbolGuess ? await searchYouTube(symbolGuess+" crypto",5) : null;

    await saveAnalysis(u.id,addr,chain,{mor,go,verify,dex,lunar,xscan,reddit,youtube},trust);

    // session for next commands
    sessionState.set(ctx.from.id,{...sessionState.get(ctx.from.id), lastToken:addr, lastChain:chain, lastSymbol:symbolGuess });

    const rep = buildReport({addr,chain,trust,go,social:lunar,verify,dex,xscan,reddit,youtube});
    await ctx.reply(rep,{parse_mode:"Markdown"});
  } catch(e) {
    console.error('Check command error:', e.message);
    await ctx.reply("❌ An error occurred while analyzing the token. Please try again later.");
  }
});

// /pumpfun [mint]  (parametresiz → lastToken SOL ise onu kullan)
bot.command("pumpfun", async ctx=>{
  let mint=(ctx.message.text.split(/\s+/)[1]||"").trim();
  if(!mint){
    const st = sessionState.get(ctx.from.id);
    if(st?.lastChain==="sol" && st.lastToken) mint = st.lastToken;
  }
  if(!mint) return ctx.reply("Usage: /pumpfun [mint_address]");
  const u=await getUser(ctx.from);
  const pump = await getPumpfun(mint);
  const trust = pump ? (Number(pump.curve||0)<20?40:80) : 55;
  await saveAnalysis(u.id,mint,"sol",{pump},trust);
  sessionState.set(ctx.from.id,{...sessionState.get(ctx.from.id), lastToken:mint, lastChain:"sol"});
  const rep = buildReport({addr:mint,chain:"sol",trust,pump});
  await ctx.reply(rep,{parse_mode:"Markdown"});
});

// /xscan [symbol|address] (parametresiz → lastSymbol/lastToken)
bot.command("xscan", async ctx=>{
  try {
    let raw=(ctx.message.text.split(/\s+/)[1]||"").trim();
    const st = sessionState.get(ctx.from.id);
    if(!raw){
      raw = st?.lastSymbol || st?.lastToken || "";
      if(!raw) return ctx.reply("Usage: /xscan [symbol|address]");
    }

    let symbol = raw;
    if(isEvm(raw) && MORALIS){
      const ch = await detectEvmChain(raw);
      const md = await getMoralis(raw, ch);
      if(md?.symbol) symbol = md.symbol;
    }
    const symbolUp = (symbol||"").toUpperCase();

    // XSCAN + fallbacks
    const x = await getXscan(symbolUp);
    const rd= await searchReddit(symbolUp+" token",5);
    const yt= await searchYouTube(symbolUp+" crypto",5);
    const lc = await getLunar(symbolUp);

    let txt = `🛰️ **Social Scan for ${mdSafe(symbolUp)}**\n\n`;
    if(lc)  txt += `🌌 GalaxyScore: ${mdSafe(String(lc.galaxy_score ?? "?"))} | SocialVol24h: ${mdSafe(String(lc.social_volume_24h ?? "?"))}\n`;
    if(x)   txt += `𝕏 Mentions(24h): ${mdSafe(String(x.mentions ?? "?"))} | Sentiment: ${mdSafe(String(x.sentiment ?? "?"))}/5\n`;
    if(rd)  txt += `Reddit: ${mdSafe(String(rd.count))} posts (latest: ${mdSafe(rd.items.slice(0,2).map(p=>p.subreddit).join(", "))})\n`;
    if(yt)  txt += `YouTube: ${mdSafe(String(yt.count))} recent videos\n`;
    if(!lc && !x && !rd && !yt) txt += `No social data available right now\.\n`;

    // kısa link listesi
    if(rd?.items?.length){
      txt += `\nReddit latest:\n` + rd.items.slice(0,3).map(p=>`• ${mdSafe(p.title)} — ${mdSafe(p.url)}`).join("\n") + "\n";
    }
    if(yt?.items?.length){
      txt += `\nYouTube latest:\n` + yt.items.slice(0,3).map(v=>`• ${mdSafe(v.title)} — ${mdSafe(v.url)}`).join("\n") + "\n";
    }

    sessionState.set(ctx.from.id,{...st, lastSymbol:symbolUp});
    await ctx.reply(txt.trim(),{parse_mode:"Markdown"});
  } catch(e) {
    console.error('XScan command error:', e.message);
    await ctx.reply("❌ An error occurred while fetching social data. Please try again later.");
  }
});

// /trending (placeholder demo)
bot.command("trending",async ctx=>{
  const tokens=[
    {name:"PEPE",chg:"+15%",vol:"120M"},
    {name:"SHIB",chg:"+8%",vol:"90M"},
    {name:"DOGE",chg:"+5%",vol:"200M"},
    {name:"LINK",chg:"+4%",vol:"75M"}
  ];
  let txt=`🔥 **Trending Tokens**\n\n`;
  tokens.forEach((t,i)=>{txt+=`${i+1}. ${t.name} – ${t.chg} | Vol: $${t.vol}\n`;});
  txt+=`\nUpdated: ${nowStr()}`;
  ctx.reply(txt);
});

// /mylist
bot.command("mylist",async ctx=>{
  const u=await getUser(ctx.from);
  const connection = await db;
  const [subs] = await connection.execute("SELECT * FROM subscriptions WHERE user_id = ? ORDER BY created_at DESC", [u.id]);
  const [analyses] = await connection.execute("SELECT * FROM token_analyses WHERE user_id = ? ORDER BY created_at DESC LIMIT 5", [u.id]);
  let txt=`📋 **Your Dashboard**\n\n`;
  if(subs.length){
    txt+=`⭐ **Subscriptions:**\n`;
    subs.forEach((s,i)=>{txt+=`${i+1}. ${s.wallet} (${s.chain.toUpperCase()})\n`;});
  } else txt+=`No subscriptions.\n`;
  if(analyses.length){
    txt+=`\n🔎 **Recent Analyses:**\n`;
    analyses.forEach((a,i)=>{txt+=`${i+1}. ${a.chain.toUpperCase()} ${a.token_address.slice(0,8)}... — ${a.trust_score}/100\n`;});
  } else txt+=`\nNo recent analyses.`;
  ctx.reply(txt);
});

// /portfolio
bot.command("portfolio",async ctx=>{
  const u=await getUser(ctx.from);
  const [_,sub,addrRaw,chainRaw] = ctx.message.text.split(/\s+/);
  if(sub==="add" && addrRaw){
    const addr = normAddr(addrRaw);
    const ch = isEvm(addr) ? await detectEvmChain(addr) : normalizeChain(chainRaw||"eth");
    const connection = await db;
    await connection.execute("INSERT IGNORE INTO watchlists (user_id, token_address, chain) VALUES (?, ?, ?)", [u.id, addr, ch]);
    sessionState.set(ctx.from.id,{...sessionState.get(ctx.from.id), lastToken:addr, lastChain:ch});
    return ctx.reply(`✅ Added ${addr} to portfolio (${ch.toUpperCase()})`);
  }
  const connection = await db;
  const [wl] = await connection.execute("SELECT * FROM watchlists WHERE user_id = ?", [u.id]);
  if(!wl.length) return ctx.reply("Your portfolio is empty. Use /portfolio add [address] [chain?]");
  let txt=`💼 **Your Portfolio:**\n`;
  wl.forEach((w,i)=>{txt+=`${i+1}. ${w.token_address} (${w.chain.toUpperCase()})\n`;});
  ctx.reply(txt);
});

// /setalert (demo)
bot.command("setalert",async ctx=>{
  const [_,addr,metric,threshold]=ctx.message.text.split(/\s+/);
  if(!addr||!metric||!threshold) return ctx.reply("Usage: /setalert [address] [metric] [threshold]");
  ctx.reply(`✅ Alert set for ${addr} – ${metric} > ${threshold}`);
});

// /stats
bot.command("stats",async ctx=>{
  const u=await getUser(ctx.from);
  const connection = await db;
  const [r] = await connection.execute("SELECT COUNT(*) as c, AVG(trust_score) as a, MAX(trust_score) as mx, MIN(trust_score) as mn FROM token_analyses WHERE user_id = ?", [u.id]);
  ctx.reply(`📊 **Your Stats**
Analyses: ${r[0].c}
Avg Score: ${Math.round(r[0].a||0)}
Best: ${r[0].mx||0}
Worst: ${r[0].mn||0}`);
});

// /help
bot.help(async ctx=>{
  try {
    await ctx.reply(`📚 **Commands**
/start – Start & select network
/check [address] – Analyze token (detailed + social)
/pumpfun [mint] – Pump.fun analysis (SOL)
/xscan [symbol|address] – Social scan (X/Reddit/YouTube)
/trending – View trending tokens
/subscribe [wallet] [chain] – Add wallet monitoring
/unsubscribe [wallet] [chain] – Remove wallet
/mylist – Subscriptions & recent analyses
/portfolio add [address] [chain?] – Manage portfolio
/setalert [address] [metric] [threshold] – Set alert
/setprofile [low/medium/high] – Set risk profile
/language en|tr|ru|de|zh – Change language
/stats – User statistics
/help – This help
`,{parse_mode:"Markdown"});
  } catch(e) {
    console.error('Help command error:', e.message);
    await ctx.reply("❌ An error occurred while showing help.");
  }
});

/* === BACKGROUND: Token Transfer Burst Monitor (ETH/BSC) ===
   - Etherscan/BscScan anahtarı varsa çalışır.
   - Abone olunan cüzdanlar için son 10 dakikada tek alıcıya 50+ farklı gönderen token yolladıysa uyarır.
*/
const POLL_MS = 60_000; // her 60sn
const WINDOW_MIN = 10;
async function fetchErc20Transfers(chain, address){
  // returns [{from, to, tokenSymbol, timeStamp}]
  const A = normAddr(address);
  try{
    if(chain==="eth" && ETHERSCAN_API_KEY){
      const r = await axios.get("https://api.etherscan.io/api",{
        params:{module:"account", action:"tokentx", address:A, sort:"desc", apikey:ETHERSCAN_API_KEY}
      });
      return (r.data?.result||[]).map(x=>({from:lc(x.from), to:lc(x.to), tokenSymbol:x.tokenSymbol, timeStamp:Number(x.timeStamp)}));
    }
    if(chain==="bsc" && BSCSCAN_API_KEY){
      const r = await axios.get("https://api.bscscan.com/api",{
        params:{module:"account", action:"tokentx", address:A, sort:"desc", apikey:BSCSCAN_API_KEY}
      });
      return (r.data?.result||[]).map(x=>({from:lc(x.from), to:lc(x.to), tokenSymbol:x.tokenSymbol, timeStamp:Number(x.timeStamp)}));
    }
  }catch{}
  return [];
}

async function monitorBursts(){
  try{
    if(!ETHERSCAN_API_KEY && !BSCSCAN_API_KEY) return; // anahtar yoksa pas
    const connection = await db;
    const [subs] = await connection.execute("SELECT s.user_id, s.wallet, s.chain, u.telegram_id FROM subscriptions s JOIN users u ON u.id=s.user_id");
    const since = Math.floor(Date.now()/1000) - (WINDOW_MIN*60);
    for(const s of subs){
      if(s.chain==="sol") continue; // şimdilik EVM
      const txs = await fetchErc20Transfers(s.chain, s.wallet);
      const recent = txs.filter(t => t.timeStamp >= since);
      // tek bir hedefe 50+ farklı gönderen?
      const grouped = new Map(); // key: to, val: Set(from)
      for(const t of recent){
        const key = t.to;
        if(!grouped.has(key)) grouped.set(key, new Set());
        grouped.get(key).add(t.from);
      }
      for(const [to,setFrom] of grouped){
        if(setFrom.size >= 50){
          await bot.telegram.sendMessage(
            s.telegram_id,
            `🚨 **Burst Transfer Alert**\nChain: ${s.chain.toUpperCase()}\nWatched: \`${s.wallet}\`\nReceiver: \`${to}\`\nDistinct senders (last ${WINDOW_MIN}m): ${setFrom.size}`,
            {parse_mode:"Markdown"}
          );
        }
      }
    }
  }catch(e){
    console.error("burst monitor error:", e.message);
  }
}
setInterval(monitorBursts, POLL_MS);

/* === START BOT === */
(async ()=>{
  try{
    await bot.telegram.setMyCommands([
      { command: 'start', description: '🚀 Welcome & network selection' },
      { command: 'check', description: '🔍 Analyze token (detailed + social)' },
      { command: 'pumpfun', description: '🟣 Pump.fun analysis (SOL)' },
      { command: 'xscan', description: '🛰️ Social scan (symbol/address)' },
      { command: 'trending', description: '🔥 Trending tokens' },
      { command: 'subscribe', description: '🔔 Add wallet monitoring' },
      { command: 'unsubscribe', description: '🔕 Remove wallet monitoring' },
      { command: 'mylist', description: '📋 Subscriptions & analyses' },
      { command: 'portfolio', description: '💼 Portfolio manager' },
      { command: 'setalert', description: '⏰ Set a custom alert' },
      { command: 'setprofile', description: '👤 Set risk profile' },
      { command: 'language', description: '🌐 Change language' },
      { command: 'stats', description: '📊 Your statistics' },
      { command: 'help', description: '❓ Help' },
    ]);
  }catch(e){ console.error("⚠️ setMyCommands:", e.message); }
  await bot.launch();
  console.log("✅ Bot v11 running...");
})();

process.once("SIGINT",()=>bot.stop("SIGINT"));
process.once("SIGTERM",()=>bot.stop("SIGTERM"));

