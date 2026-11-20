// ----------------------------------------------------------------------------
// DumperPro Online - semantik aciklama motoru (Turkce tahmin motoru)
//
// Cikarilan verinin NE IS YAPTIGINI tahmin eder: fonksiyon adi/etiketi,
// string icerikleri, struct alan adlari ve enum uye adlari ~650 anahtar
// kelime sozlugu uzerinden 23 oyun kategorisine skorlanir (Saglik, Silah/
// Hasar, Ekonomi/Para, Konum/Koordinat ...). Skorlama: tam eslesme > onek >
// icerme; birden fazla kategori eslesirse en yuksek skor kazanir, digerleri
// tags alanina yazilir. Tum aciklamalar TAHMINIDIR (confidence 0..1) ve
// kesin dogrulama canli modda yapilmalidir.
//
// Dekor temizligi: MSVC "?updateHealth@Player@@QEAAXH@Z" -> "updateHealth",
// Itanium "_ZN7Player12updateHealthEi" -> "updateHealth", JNI "Java_..." ->
// son segment. Fiil tespiti (get/set/update/tick ...) Turkce cumle sablonu
// uretir; callsOut/xrefsIn yorumlanarak ozete eklenir.
// ----------------------------------------------------------------------------

import type { FunctionEntry, RecoveredEnum, RecoveredStruct } from "./types";

// ---------------------------------------------------------------------------
// genel arayuz
// ---------------------------------------------------------------------------

export interface SemanticInfo {
  category: string; // baskin kategori (TR)
  confidence: number; // 0..1 (eslesme sayisi + pozisyonu)
  summary: string; // kisa Turkce ozet cumlesi
  computes: string; // ne hesaplar/okur (eslesen anahtar kelimeler)
  writes: string; // nereye yazar (kategori bazli tahmin)
  tags: string[]; // ikincil kategoriler + ozel etiketler (platform vb.)
}

// ---------------------------------------------------------------------------
// kategoriler (TR)
// ---------------------------------------------------------------------------

export const SEMANTIC_CATEGORIES = [
  "Karakter/Saglik",
  "Silah/Hasar",
  "Envanter/Esya",
  "Ekonomi/Para",
  "Ilerleme/Seviye",
  "Konum/Koordinat",
  "Hareket/Fizik",
  "Arac/Tasima",
  "Gorsel/Model",
  "Animasyon",
  "Grafik/Render",
  "Kamera",
  "Hava/Cevre",
  "Ses",
  "Arayuz/HUD",
  "Ag/Online",
  "Kayit/Konfig",
  "Girdi/Kontrol",
  "Yapay Zeka",
  "Zaman/Sayac",
  "Gelistirici/Debug",
  "AntiHile/Koruma",
  "Bellek/Bellegi",
  "Genel",
] as const;

const C = {
  SAGLIK: "Karakter/Saglik",
  SILAH: "Silah/Hasar",
  ENVANTER: "Envanter/Esya",
  EKONOMI: "Ekonomi/Para",
  ILERLEME: "Ilerleme/Seviye",
  KONUM: "Konum/Koordinat",
  HAREKET: "Hareket/Fizik",
  ARAC: "Arac/Tasima",
  GORSEL: "Gorsel/Model",
  ANIMASYON: "Animasyon",
  GRAFIK: "Grafik/Render",
  KAMERA: "Kamera",
  HAVA: "Hava/Cevre",
  SES: "Ses",
  ARAYUZ: "Arayuz/HUD",
  AG: "Ag/Online",
  KAYIT: "Kayit/Konfig",
  GIRDI: "Girdi/Kontrol",
  YAPAYZEKA: "Yapay Zeka",
  ZAMAN: "Zaman/Sayac",
  DEBUG: "Gelistirici/Debug",
  ANTIHILE: "AntiHile/Koruma",
  BELLEK: "Bellek/Bellegi",
  GENEL: "Genel",
} as const;

// ---------------------------------------------------------------------------
// anahtar kelime sozlugu (keyword -> kategori); tek sira = beraberlik onceligi
// ---------------------------------------------------------------------------

const DICT_GROUPS: [string, string[]][] = [
  [C.SAGLIK, [
    "health", "can", "hp", "life", "heal", "healing", "stamina", "mana", "armor", "regen",
    "invincible", "invulnerable", "immortal", "godmode", "player", "character", "pawn",
    "avatar", "karakter", "oyuncu", "playerstate", "alive", "dead", "death", "kill",
    "suicide", "revive", "hunger", "thirst", "oxygen", "fatigue", "sanity", "morale",
    "bleed", "poison",
  ]],
  [C.SILAH, [
    "damage", "hasar", "atk", "attack", "dps", "ammo", "mermi", "magazine", "mag", "clip",
    "weapon", "silah", "gun", "rifle", "pistol", "bullet", "fire", "firerate", "reload",
    "shoot", "recoil", "spread", "crit", "critical", "melee", "grenade", "explosive",
    "bomb", "projectile", "muzzle", "caliber", "aim", "hit", "pierce", "range", "cannon",
    "shooter",
  ]],
  [C.ENVANTER, [
    "inventory", "item", "items", "slot", "envanter", "loot", "bag", "backpack", "stash",
    "equip", "gear", "pickup", "drop", "craft", "recipe", "chest", "crate", "container",
    "quantity", "stack", "consumable", "pouch", "holster", "relic", "artifact", "weight",
    "cargo",
  ]],
  [C.EKONOMI, [
    "money", "gold", "coin", "para", "cash", "credit", "credits", "bakiye", "currency",
    "wallet", "price", "shop", "store", "sell", "buy", "purchase", "trade", "payment",
    "transaction", "balance", "bank", "diamond", "gem", "premium", "donate", "salary",
    "revenue", "income", "tax", "iap", "microtransaction", "cashout",
  ]],
  [C.ILERLEME, [
    "level", "xp", "exp", "experience", "seviye", "rank", "ranking", "skill", "prestige",
    "quest", "mission", "achievement", "unlock", "progress", "score", "points",
    "reputation", "badge", "talent", "perk", "upgrade", "tier", "league", "rating", "mmr",
    "elo", "leaderboard", "battlepass", "mastery", "levelup",
  ]],
  [C.KONUM, [
    "position", "pos", "location", "coordinate", "coords", "konum", "origin", "waypoint",
    "marker", "gps", "compass", "map", "worldmap", "zone", "area", "region", "chunk",
    "tile", "sector", "spawnpoint", "teleport", "latitude", "longitude", "altitude",
    "heading", "rotation", "yaw", "pitch", "transform", "world", "distance", "radius",
    "bounds", "quadrant",
  ]],
  [C.HAREKET, [
    "velocity", "speed", "hiz", "move", "movement", "jump", "dash", "gravity", "physic",
    "physics", "momentum", "acceleration", "accel", "friction", "bounce", "ragdoll",
    "collision", "collider", "hitbox", "swim", "climb", "sprint", "walk", "run", "fall",
    "falling", "parachute", "glide", "roll", "dodge", "impulse", "force", "torque",
    "mass", "knockback", "slide", "crouch", "lean",
  ]],
  [C.ARAC, [
    "car", "vehicle", "wheel", "wheels", "engine", "arac", "araba", "plane", "aircraft",
    "helicopter", "heli", "boat", "ship", "tank", "truck", "bike", "motorcycle", "drift",
    "driving", "driver", "passenger", "chassis", "fuel", "nitro", "steer", "steering",
    "brake", "throttle", "flight", "jet", "submarine", "hover", "garage", "parking",
    "traffic",
  ]],
  [C.GORSEL, [
    "skin", "skins", "skinid", "model", "mesh", "texture", "tex", "material", "apparel",
    "outfit", "cosmetic", "cloth", "clothing", "hair", "face", "body", "appearance",
    "costume", "color", "tint", "decal", "prop", "wardrobe", "customization", "dye",
    "palette", "morph",
  ]],
  [C.ANIMASYON, [
    "animation", "anim", "animations", "skeleton", "bone", "bones", "montage", "blend",
    "blendspace", "pose", "rig", "ik", "motion", "animgraph", "emote", "gesture", "dance",
    "playback", "keyframe", "retarget",
  ]],
  [C.GRAFIK, [
    "render", "rendering", "renderer", "shader", "draw", "drawcall", "lighting", "shadow",
    "postprocess", "fps", "frame", "framerate", "graphics", "d3d11", "d3d12", "dx11",
    "dx12", "dxgi", "vulkan", "opengl", "directx", "bloom", "raytracing", "resolution",
    "quality", "vertex", "pixel", "gpu", "rasterizer", "depthstencil", "swapchain",
    "present", "gamma", "brightness", "antialias", "vram",
  ]],
  [C.KAMERA, [
    "camera", "kamera", "cam", "viewtarget", "zoom", "shake", "springarm", "boom", "orbit",
    "cine", "cinematic", "focal", "firstperson", "thirdperson", "pov", "viewport",
    "lookat", "freelook", "frustum", "fisheye", "freecam",
  ]],
  [C.HAVA, [
    "weather", "rain", "sun", "sunny", "snow", "temperature", "wind", "gunbatimi", "hava",
    "climate", "fog", "storm", "thunder", "lightning", "humidity", "forecast", "sunrise",
    "sunset", "dusk", "dawn", "moon", "cloud", "tide",
  ]],
  [C.SES, [
    "audio", "sound", "music", "voice", "sfx", "mixer", "volume", "mute", "soundtrack",
    "ambience", "reverb", "doppler", "audiomix", "playlist", "radio", "bass", "tone",
    "beep", "speaker", "microphone", "footsteps",
  ]],
  [C.ARAYUZ, [
    "ui", "hud", "widget", "menu", "button", "panel", "overlay", "tooltip", "cursor",
    "crosshair", "minimap", "slider", "checkbox", "textbox", "dialog", "toast",
    "notification", "banner", "layout", "screen", "font", "healthbar", "progressbar",
    "icon", "tab",
  ]],
  [C.AG, [
    "network", "ping", "latency", "session", "socket", "replication", "rpc", "online",
    "multiplayer", "server", "client", "host", "join", "lobby", "match", "packet", "tcp",
    "udp", "http", "https", "websocket", "steam", "epic", "eos", "platform", "bandwidth",
    "netmode", "channel", "disconnect", "reconnect", "matchmaking", "login", "auth",
    "token", "downloader", "upload", "endpoint", "payload", "proxy", "relay", "hostname",
    "port", "ip",
  ]],
  [C.KAYIT, [
    "save", "saving", "autosave", "cloudsave", "config", "configuration", "setting",
    "settings", "profil", "profile", "kayit", "preference", "prefs", "persist",
    "persistence", "userdata", "checkpoint", "backup", "restore", "export", "import",
    "registry", "storage", "file", "files",
  ]],
  [C.GIRDI, [
    "input", "inputs", "key", "keys", "keyboard", "mouse", "touch", "gamepad",
    "controller", "joystick", "axis", "bind", "binding", "hotkey", "rumble", "vibration",
    "sensitivity", "deadzone", "keymap", "control", "controls", "hold", "press",
    "release", "tap", "swipe", "drag",
  ]],
  [C.YAPAYZEKA, [
    "ai", "behavior", "bt", "brain", "bot", "npc", "enemy", "enemies", "aggro",
    "pathfind", "pathfinding", "navmesh", "flee", "chase", "patrol", "perception",
    "threat", "difficulty", "companion", "crowd", "aware", "senses", "vision", "decision",
    "utility", "goap", "blackboard",
  ]],
  [C.ZAMAN, [
    "timer", "clock", "day", "night", "season", "date", "time", "timeofday", "cooldown",
    "duration", "interval", "tickrate", "schedule", "countdown", "elapsed", "delta",
    "deltatime", "timestamp", "uptime", "calendar", "year", "month", "hour", "minute",
    "second", "delay", "realtime", "daytime",
  ]],
  [C.DEBUG, [
    "debug", "debugger", "dev", "developer", "console", "cheat", "cheats", "test",
    "testing", "assert", "log", "logging", "logger", "dump", "dbg", "breakpoint",
    "profiling", "verbose", "warning", "error", "exception", "crash",
  ]],
  [C.ANTIHILE, [
    "anticheat", "shield", "protect", "protection", "encrypt", "encryption", "decrypt",
    "obfus", "obfuscate", "integrity", "secure", "security", "guard", "ban", "validate",
    "verify", "signature", "checksum", "license", "drm", "hwid", "sandbox", "permission",
    "tamper", "jailbreak", "guardian", "defender",
  ]],
  [C.BELLEK, [
    "memory", "mem", "alloc", "allocation", "allocator", "heap", "pool", "malloc",
    "garbage", "gc", "refcount", "buffer", "arena", "leak", "vmem", "address", "pointer",
    "deref", "mmap", "paging", "virtualalloc", "readprocess", "writeprocess", "snapshot",
    "cache", "free",
  ]],
];

export const DICT: Record<string, string> = {};
for (const [cat, words] of DICT_GROUPS) {
  for (const w of words) {
    if (DICT[w] === undefined) DICT[w] = cat;
  }
}
export const SEMANTIC_KEYWORD_COUNT = Object.keys(DICT).length;

// ---------------------------------------------------------------------------
// kategori -> konu / yazma hedefi sablonlari
// ---------------------------------------------------------------------------

const SUBJECTS: Record<string, string> = {
  [C.SAGLIK]: "Saglik/can",
  [C.SILAH]: "Silah/hasar",
  [C.ENVANTER]: "Envanter/esya",
  [C.EKONOMI]: "Para/bakiye",
  [C.ILERLEME]: "Seviye/XP",
  [C.KONUM]: "Konum/koordinat",
  [C.HAREKET]: "Hareket/fizik",
  [C.ARAC]: "Arac/tasima",
  [C.GORSEL]: "Gorsel/model",
  [C.ANIMASYON]: "Animasyon",
  [C.GRAFIK]: "Grafik/render",
  [C.KAMERA]: "Kamera",
  [C.HAVA]: "Hava/cevre",
  [C.SES]: "Ses",
  [C.ARAYUZ]: "Arayuz/HUD",
  [C.AG]: "Ag/baglanti",
  [C.KAYIT]: "Kayit/konfig",
  [C.GIRDI]: "Girdi/kontrol",
  [C.YAPAYZEKA]: "Yapay zeka",
  [C.ZAMAN]: "Zaman/sayac",
  [C.DEBUG]: "Hata ayiklama/dev",
  [C.ANTIHILE]: "Anti-hile/koruma",
  [C.BELLEK]: "Bellek yonetimi",
};

const WRITES: Record<string, string> = {
  [C.SAGLIK]: "Health/can alani uzerine yazma olasiligi yuksek",
  [C.SILAH]: "hasar/ammo alanlarina yazar; ates hattini tetikleyebilir",
  [C.ENVANTER]: "envanter dizi/slot alanlarina yazar",
  [C.EKONOMI]: "para/bakiye alanina yazma olasiligi yuksek",
  [C.ILERLEME]: "XP/level/progress alanlarina yazar",
  [C.KONUM]: "pozisyon/transform verisine yazar",
  [C.HAREKET]: "hiz/ivme ve fizik durum degiskenlerine yazar",
  [C.ARAC]: "arac durumu (hiz/hasar) alanlarina yazar",
  [C.GORSEL]: "model/kostum ozellik alanlarina yazar",
  [C.ANIMASYON]: "animasyon durum makinesine yazar",
  [C.GRAFIK]: "render hattina parametre tasir",
  [C.KAMERA]: "kamera hedef/parametre alanlarina yazar",
  [C.HAVA]: "cevre/hava durum degiskenlerine yazar",
  [C.SES]: "ses kanal/volume ayarlarina yazar",
  [C.ARAYUZ]: "HUD/widget durumuna yazar",
  [C.AG]: "ag akisina paket/parametre gonderir",
  [C.KAYIT]: "dosya/kayit akisina yazar",
  [C.GIRDI]: "girdi durum/tus tablosuna yazar",
  [C.YAPAYZEKA]: "YZ davranis durumuna yazar",
  [C.ZAMAN]: "zamanlayici/sayac alanlarina yazar",
  [C.DEBUG]: "log/konsol akisina yazar",
  [C.ANTIHILE]: "dogrulama sonucu/bayrak alanlarina yazar",
  [C.BELLEK]: "bellek bolgesi ayirir/yazar",
};

const PLATFORM_WORDS = ["steam", "epic", "eos", "platform"];

// ---------------------------------------------------------------------------
// fiil sablonlari (Turkce cumle kalibi; {S} = konu)
// ---------------------------------------------------------------------------

const VERB_TEMPLATES: Record<string, string> = {
  get: "{S} degerini okur",
  set: "{S} alanina yeni deger yazar",
  update: "{S} alanini gunceller",
  apply: "{S} degisikligini uygular",
  init: "{S} sistemini ilklendirir",
  tick: "her kare {S} durumunu isler",
  lerp: "{S} degerleri arasinda dogrusal gecis hesaplar",
  damage: "{S} uzerine hasar uygular",
  heal: "{S} degerini iyilestirir",
  spawn: "{S} nesnesi olusturur",
  destroy: "{S} nesnesini yok eder",
  load: "{S} verisini bellege yukler",
  save: "{S} verisini kayit akisina yazar",
  serialize: "{S} yapisini serilestirir",
  process: "{S} verisini isler",
  handle: "{S} olayini yakalayip isler",
  compute: "{S} ile ilgili deger hesaplar",
  check: "{S} kosulunu dogrular",
  toggle: "{S} durumunu degistirir",
  enable: "{S} ozelligini etkinlestirir",
  disable: "{S} ozelligini devre disi birakir",
};

// ---------------------------------------------------------------------------
// isim temizligi + tokenizasyon
// ---------------------------------------------------------------------------

/** Turkce karakterleri ASCII karsiligina indirger. */
function stripAccents(s: string): string {
  let out = "";
  for (const ch of s) {
    switch (ch) {
      case "ı": case "İ": out += "i"; break;
      case "ş": case "Ş": out += "s"; break;
      case "ğ": case "Ğ": out += "g"; break;
      case "ü": case "Ü": out += "u"; break;
      case "ö": case "Ö": out += "o"; break;
      case "ç": case "Ç": out += "c"; break;
      default: out += ch;
    }
  }
  return out.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
}

/**
 * Windows/MSVC + Itanium + JNI dekorasyonunu temizler.
 * "?updateHealth@Player@@QEAAXH@Z" -> "updateHealth"
 */
export function cleanDecoration(raw: string): string {
  const s = (raw ?? "").trim();
  if (!s) return "";
  // ordinal / adres benzeri etiketler anlamsizdir
  if (/^(0x[0-9a-fA-F]+|\d+|Ordinal_?\d+)$/i.test(s)) return "";
  // MSVC: ?updateHealth@Player@@QEAAXH@Z
  if (s.startsWith("?")) {
    const m = s.match(/^\?([A-Za-z_$][A-Za-z0-9_$]*)@/);
    if (m) return m[1]!;
    return s.replace(/[?@].*$/, "");
  }
  // Itanium: _ZN7Player12updateHealthEi -> son uzunluk-on ekli segment
  if (s.startsWith("_Z") || s.startsWith("__Z")) {
    const names = [...s.matchAll(/(?:^|[^A-Za-z0-9_])(\d{1,4})([A-Za-z_$][A-Za-z0-9_$]{2,})/g)].map((m) => m[2]!);
    if (names.length > 0) return names[names.length - 1]!;
    return s.replace(/^_+Z/, "");
  }
  // JNI: Java_com_x_Foo_bar -> son segment
  if (s.startsWith("Java_")) {
    const parts = s.split("_").filter((p) => p.length > 0);
    if (parts.length > 1) return parts[parts.length - 1]!;
  }
  return s.replace(/@@.*$/, "").replace(/@.*$/, "");
}

/** camelCase / snake_case / tireli isimleri sozcuklere boler (kucuk harf). */
function tokenize(name: string): string[] {
  const cleaned = stripAccents(cleanDecoration(name));
  if (!cleaned) return [];
  const split = cleaned
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase();
  return split.split(/[^a-z0-9]+/).filter((t) => t.length > 0);
}

// ---------------------------------------------------------------------------
// skorlama
// ---------------------------------------------------------------------------

interface CatScore {
  score: number; // agirlikli toplam
  matches: number; // eslesme sayisi
  exact: number; // tam eslesme sayisi
  words: string[]; // eslesen anahtar kelimeler
  minIdx: number; // en erken eslesen token indeksi (pozisyon)
}

interface Winner {
  cat: string;
  sc: CatScore;
  order: number;
}

function scoreTokenList(tokens: string[]): Map<string, CatScore> {
  const map = new Map<string, CatScore>();
  const bump = (cat: string, word: string, pts: number, exact: boolean, idx: number): void => {
    const cur = map.get(cat);
    if (cur) {
      cur.score += pts;
      cur.matches += 1;
      if (exact) cur.exact += 1;
      if (!cur.words.includes(word)) cur.words.push(word);
      if (idx < cur.minIdx) cur.minIdx = idx;
    } else {
      map.set(cat, { score: pts, matches: 1, exact: exact ? 1 : 0, words: [word], minIdx: idx });
    }
  };
  const fullLower = tokens.join("");
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;
    // sozlukte birebir var -> tam eslesme
    const direct = DICT[t];
    if (direct !== undefined) {
      bump(direct, t, 3, true, i);
      continue;
    }
    // tek harf (x/y/z) yalnizca TAM AD eslesmesinde sayilir
    if (t.length < 3) continue;
    for (const kw of Object.keys(DICT)) {
      if (kw.length < 4) continue; // kisa anahtarlar yalnizca tam eslesme ile
      const cat = DICT[kw]!;
      if (t.length > kw.length && t.startsWith(kw)) bump(cat, kw, 2, false, i); // onek
      else if (kw.length > t.length && t.length >= 4 && kw.startsWith(t)) bump(cat, kw, 2, false, i);
      else if (t.length >= kw.length + 4 && t.includes(kw)) bump(cat, kw, 1, false, i); // icerme
    }
  }
  // x/y/z tam ad kontrolu ("x", "y", "z" alanlari)
  for (const one of ["x", "y", "z"]) {
    if (fullLower === one) bump(C.KONUM, one, 3, true, 0);
  }
  return map;
}

function mergeScores(dst: Map<string, CatScore>, src: Map<string, CatScore>, weight: number): void {
  for (const [cat, v] of src) {
    const cur = dst.get(cat);
    if (cur) {
      cur.score += v.score * weight;
      cur.matches += v.matches;
      cur.exact += v.exact;
      for (const w of v.words) if (!cur.words.includes(w)) cur.words.push(w);
      if (v.minIdx < cur.minIdx) cur.minIdx = v.minIdx;
    } else {
      dst.set(cat, { score: v.score * weight, matches: v.matches, exact: v.exact, words: [...v.words], minIdx: v.minIdx });
    }
  }
}

function pickWinner(map: Map<string, CatScore>): Winner | null {
  let best: Winner | null = null;
  for (const [cat, sc] of map) {
    const order = SEMANTIC_CATEGORIES.indexOf(cat as (typeof SEMANTIC_CATEGORIES)[number]);
    if (!best) { best = { cat, sc, order: order === -1 ? 99 : order }; continue; }
    const b = best.sc;
    const better =
      sc.score > b.score ||
      (sc.score === b.score && sc.matches > b.matches) ||
      (sc.score === b.score && sc.matches === b.matches && sc.exact > b.exact) ||
      (sc.score === b.score && sc.matches === b.matches && sc.exact === b.exact && order !== -1 && order < best.order);
    if (better) best = { cat, sc, order: order === -1 ? 99 : order };
  }
  return best;
}

function confidenceOf(win: Winner): number {
  let conf = 0.35 + 0.11 * Math.min(win.sc.matches, 6) + 0.12 * Math.min(win.sc.exact, 3);
  if (win.sc.minIdx === 0) conf += 0.05;
  conf = Math.round(Math.min(0.97, Math.max(0.05, conf)) * 100) / 100;
  return conf;
}

function wordsOf(map: Map<string, CatScore>, cap = 8): string[] {
  const out: string[] = [];
  for (const v of map.values()) {
    for (const w of v.words) if (!out.includes(w)) out.push(w);
  }
  return out.slice(0, cap);
}

function tagsOf(map: Map<string, CatScore>, winnerCat: string, extra: string[] = []): string[] {
  const others = [...map.entries()]
    .filter(([c]) => c !== winnerCat)
    .sort((a, b) => b[1].score - a[1].score)
    .map(([c]) => c)
    .slice(0, 5);
  return [...new Set([...others, ...extra])].slice(0, 8);
}

function subjectOf(cat: string): string {
  return SUBJECTS[cat] ?? "veri";
}

function writesOf(cat: string): string {
  return WRITES[cat] ?? "yazma hedefi belirsiz (dusuk guven)";
}

function genelInfo(summaryTail = ""): SemanticInfo {
  const base = "Tahmin icin yeterli anahtar kelime bulunamadi";
  return {
    category: C.GENEL,
    confidence: 0,
    summary: summaryTail ? `${base}; ${summaryTail}` : base,
    computes: "eslesen anahtar kelime yok (girdi adi anlamsiz/normalize edilemedi)",
    writes: "Yazma hedefi belirlenemedi (eslesme yok)",
    tags: [],
  };
}

const NO_MATCH_COMPUTES = "eslesen anahtar kelime yok";
const NO_MATCH_WRITES = "Yazma hedefi belirlenemedi (eslesme yok)";

// ---------------------------------------------------------------------------
// public API
// ---------------------------------------------------------------------------

/** Jenerik yardimci: herhangi bir ad/kelime dizisi icin kategori tahmini. */
export function explainName(name: string): SemanticInfo {
  const cleaned = cleanDecoration(name);
  const tokens = tokenize(cleaned);
  if (tokens.length === 0) return genelInfo(`"${name}" adindan anlamlir token cikarilamadi`);
  const map = scoreTokenList(tokens);
  const win = pickWinner(map);
  if (!win) return genelInfo(`"${name}" icin sozluk eslesmesi yok`);
  const subject = subjectOf(win.cat);
  return {
    category: win.cat,
    confidence: confidenceOf(win),
    summary: `"${name}": ${subject} baglaminda kullaniliyor olabilir`,
    computes: `Eslesen anahtar kelimeler: ${win.sc.words.join(", ")}`,
    writes: writesOf(win.cat),
    tags: tagsOf(map, win.cat),
  };
}

/** Struct alan aciklamasi: ad + tip + struct baglami. */
export function explainField(name: string, type: string, structName?: string): SemanticInfo {
  const cleaned = cleanDecoration(name);
  const tokens = tokenize(cleaned);
  const typeLower = (type ?? "").toLowerCase();
  const isPointer = typeLower.includes("ptr") || typeLower.includes("void*") || typeLower.includes("*");

  if (tokens.length === 0) {
    const info = genelInfo("alan adindan anlamlir token cikarilamadi");
    if (isPointer) {
      info.tags = [C.BELLEK];
      info.computes = `${type} turunde isaretci; bellek erisimi muhtemel`;
    }
    return info;
  }

  const map = scoreTokenList(tokens);
  if (isPointer) mergeScores(map, scoreTokenList(["pointer"]), 1);
  const win = pickWinner(map);
  if (!win) {
    const info = genelInfo("alan adi sozlukte yok");
    if (isPointer) {
      info.tags = [C.BELLEK];
      info.computes = `${type} turunde isaretci; bellek erisimi muhtemel`;
    }
    return info;
  }

  const subject = subjectOf(win.cat);
  const prefix = structName ? `${structName}.` : "";
  const computesParts: string[] = [];
  if (isPointer) computesParts.push(`${type} turunde isaretci; bellek erisimi muhtemel`);
  else computesParts.push(`${type} turunde deger tasir`);
  computesParts.push(`Eslesen anahtar kelimeler: ${win.sc.words.join(", ")}`);

  return {
    category: win.cat,
    confidence: confidenceOf(win),
    summary: `${prefix}${cleaned}: ${subject} alanini isaret ediyor`,
    computes: computesParts.join("; "),
    writes: writesOf(win.cat),
    tags: tagsOf(map, win.cat, isPointer ? [C.BELLEK] : []),
  };
}

/** Fonksiyon aciklamasi: ad + stringler + api cagrilari + cagri grafi. */
export function explainFunction(
  f: FunctionEntry,
  extra?: { strings?: string[]; apiCalls?: string[] },
): SemanticInfo {
  const rawName = f.label ?? "";
  const cleaned = cleanDecoration(rawName);
  const tokens = tokenize(cleaned);

  const nameMap = tokens.length > 0 ? scoreTokenList(tokens) : new Map<string, CatScore>();
  const strMap = new Map<string, CatScore>();
  const apiMap = new Map<string, CatScore>();
  const hintMap = new Map<string, CatScore>();

  const strings = extra?.strings ?? f.strings ?? [];
  const apiCalls = extra?.apiCalls ?? f.apiCalls ?? [];

  for (const s of strings.slice(0, 16)) {
    const st = tokenize(s);
    if (st.length > 0) mergeScores(strMap, scoreTokenList(st.slice(0, 64)), 1);
  }
  for (const a of apiCalls.slice(0, 16)) {
    const at = tokenize(a);
    if (at.length > 0) mergeScores(apiMap, scoreTokenList(at), 2);
  }
  if (f.structHint) {
    const ht = tokenize(f.structHint);
    if (ht.length > 0) mergeScores(hintMap, scoreTokenList(ht), 1);
  }

  const merged = new Map<string, CatScore>();
  mergeScores(merged, nameMap, 2);
  mergeScores(merged, strMap, 1);
  mergeScores(merged, apiMap, 1);
  mergeScores(merged, hintMap, 1);

  const win = pickWinner(merged);
  if (!win) {
    const info = genelInfo("ad + stringler + api cagrilari sozlukte eslesmedi");
    appendGraphNotes(info, f);
    return info;
  }

  // fiil tespiti (yalnizca fonksiyon adindan)
  const verb = tokens.find((t) => VERB_TEMPLATES[t] !== undefined);
  const subject = subjectOf(win.cat);
  let summary = verb
    ? VERB_TEMPLATES[verb]!.replace("{S}", subject)
    : `${subject} ile ilgili islem yaptigi tahmin ediliyor`;

  // cagri grafi yorumlari
  if ((f.callsOut ?? 0) >= 8) summary += `; ${f.callsOut} cikis cagrisi var - merkezi/yardimci fonksiyon gibi gorunuyor`;
  if ((f.xrefsIn ?? 0) >= 8) summary += `; ${f.xrefsIn} farkli fonksiyondan cagiriliyor - sicak/hub noktasi`;
  if ((f.callsOut ?? 0) === 0 && (f.xrefsIn ?? 0) === 0) summary += "; cagri grafinde izole (giris noktasi/kesilebilir yordam olabilir)";

  // platform etiketi (steam/epic/eos/platform)
  const allWords = wordsOf(merged, 24);
  const extras: string[] = [];
  if (win.cat === C.AG && PLATFORM_WORDS.some((p) => allWords.includes(p))) extras.push("platform");

  // computes: kaynak bazli eslesme raporu
  const parts: string[] = [];
  const nameWords = wordsOf(nameMap, 6);
  const strWords = wordsOf(strMap, 6);
  const apiWords = wordsOf(apiMap, 6);
  const hintWords = wordsOf(hintMap, 6);
  if (nameWords.length) parts.push(`ad eslesmesi: ${nameWords.join(", ")}`);
  if (hintWords.length) parts.push(`struct eslesmesi: ${hintWords.join(", ")}`);
  if (strWords.length) parts.push(`string eslesmesi: ${strWords.join(", ")}`);
  if (apiWords.length) parts.push(`API eslesmesi: ${apiWords.join(", ")}`);
  const computes = parts.length > 0 ? parts.join("; ") : NO_MATCH_COMPUTES;

  const info: SemanticInfo = {
    category: win.cat,
    confidence: confidenceOf(win),
    summary,
    computes,
    writes: writesOf(win.cat),
    tags: tagsOf(merged, win.cat, extras),
  };
  return info;
}

function appendGraphNotes(info: SemanticInfo, f: FunctionEntry): void {
  const notes: string[] = [];
  if ((f.callsOut ?? 0) >= 8) notes.push(`${f.callsOut} cikis cagrisi var - merkezi/yardimci fonksiyon gibi gorunuyor`);
  if ((f.xrefsIn ?? 0) >= 8) notes.push(`${f.xrefsIn} farkli fonksiyondan cagiriliyor - sicak/hub noktasi`);
  if (notes.length > 0) info.summary = `${info.summary}; ${notes.join("; ")}`;
}

/** Struct aciklamasi: tum alanlar taranir, baskin kategori secilir. */
export function explainStruct(s: RecoveredStruct): SemanticInfo {
  const merged = new Map<string, CatScore>();
  const fieldWords: string[] = [];
  let matchedFields = 0;

  for (const fld of s.fields.slice(0, 64)) {
    const tokens = tokenize(fld.name);
    if (tokens.length === 0) continue;
    const m = scoreTokenList(tokens);
    if (m.size > 0) matchedFields += 1;
    mergeScores(merged, m, 1);
    for (const w of wordsOf(m, 4)) if (!fieldWords.includes(w)) fieldWords.push(w);
  }
  // struct adinin kendisi de taranir
  const nm = scoreTokenList(tokenize(s.name));
  if (nm.size > 0) matchedFields += 1;
  mergeScores(merged, nm, 1);

  const win = pickWinner(merged);
  if (!win) return genelInfo(`${s.name} yapisinin alan/adlari sozlukte eslesmedi`);

  const subject = subjectOf(win.cat);
  const total = Math.max(1, s.fields.length);
  const vftNote = s.vftableRva !== undefined ? "; vftable mevcut (sanal metot tablosu)" : "";
  return {
    category: win.cat,
    confidence: confidenceOf(win),
    summary: `${s.name} yapisi tarandi (${total} alan, ${matchedFields} eslesme): baskin kategori ${subject}${vftNote}`,
    computes: `eslesen alanlar/anahtar kelimeler: ${fieldWords.slice(0, 8).join(", ") || "yok"}`,
    writes: writesOf(win.cat),
    tags: tagsOf(merged, win.cat),
  };
}

/** Dize aciklamasi: icerikteki anahtar kelimeler. */
export function explainString(value: string): SemanticInfo {
  const text = (value ?? "").trim();
  if (!text) return genelInfo("bos dize");
  const words = text.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 0).slice(0, 64);
  const map = scoreTokenList(words);
  const win = pickWinner(map);
  if (!win) return genelInfo(`"${text.slice(0, 64)}" icinde sozluk eslesmesi yok`);
  const subject = subjectOf(win.cat);
  const shown = text.length > 64 ? `${text.slice(0, 61)}...` : text;
  return {
    category: win.cat,
    confidence: confidenceOf(win),
    summary: `"${shown}" dizesi ${subject} baglamina isaret ediyor`,
    computes: `Eslesen anahtar kelimeler: ${win.sc.words.join(", ")}`,
    writes: writesOf(win.cat),
    tags: tagsOf(map, win.cat, PLATFORM_WORDS.some((p) => win.sc.words.includes(p)) ? ["platform"] : []),
  };
}

/** Enum aciklamasi: ad + uye adlari. */
export function explainEnum(e: RecoveredEnum): SemanticInfo {
  const merged = new Map<string, CatScore>();
  const memberWords: string[] = [];

  const nm = scoreTokenList(tokenize(e.name));
  mergeScores(merged, nm, 1);
  for (const m of e.members.slice(0, 64)) {
    const mt = scoreTokenList(tokenize(m.name));
    mergeScores(merged, mt, 1);
    for (const w of wordsOf(mt, 3)) if (!memberWords.includes(w)) memberWords.push(w);
  }

  const win = pickWinner(merged);
  if (!win) return genelInfo(`${e.name} enum uye/adlari sozlukte eslesmedi`);

  const subject = subjectOf(win.cat);
  const membersShown = e.members.slice(0, 6).map((m) => m.name).join(", ");
  return {
    category: win.cat,
    confidence: confidenceOf(win),
    summary: `${e.name}: ${subject} baglaminda kullanilan sabit degerleri tanimliyor (${e.members.length} uye)`,
    computes: `eslesen anahtar kelimeler: ${[...wordsOf(nm, 4), ...memberWords].slice(0, 8).join(", ") || "yok"}${membersShown ? ` | uyeler: ${membersShown}` : ""}`,
    writes: writesOf(win.cat),
    tags: tagsOf(merged, win.cat),
  };
}
