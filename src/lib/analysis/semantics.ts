// ----------------------------------------------------------------------------
// DumperPro Online - semantik aciklama motoru (Turkce tahmin motoru)
//
// Cikarilan verinin NE IS YAPTIGINI tahmin eder: fonksiyon adi/etiketi,
// string icerikleri, struct alan adlari ve enum uye adlari ~1100 anahtar
// kelime sozlugu uzerinden 23 oyun kategorisine skorlanir (Saglik, Silah/
// Hasar, Ekonomi/Para, Konum/Koordinat ...). Skorlama: tam eslesme > onek >
// icerme; birden fazla kategori eslesirse en yuksek skor kazanir, digerleri
// tags alanina yazilir. Tum aciklamalar TAHMINIDIR (confidence 0..1) ve
// kesin dogrulama canli modda yapilmalidir.
//
// Kategori meta tablosu (CATEGORY_META) her kategori icin Turkce aciklama
// tutar: ne is yapiyor / ne hesapliyor / nereye yaziyor-etkiliyor. SemanticInfo
// uzerindeki categoryId (EN kimlik), description (kisa TR aciklama) ve hints
// (action/computation/target) alanlari bu tablodan doldurulur; eski alanlar
// (category/computes/writes) geriye uyumlu sekilde aynen korunur.
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
  categoryId: string; // makine okur EN kimlik (health, weapon_damage, ...)
  confidence: number; // 0..1 (eslesme sayisi + pozisyonu)
  summary: string; // kisa Turkce ozet cumlesi
  computes: string; // ne hesaplar/okur (eslesen anahtar kelimeler)
  writes: string; // nereye yazar (kategori bazli tahmin)
  description: string; // kategori bazli kisa TR aciklama (ne is/hesap/yazim)
  hints: SemanticHints; // eylem/hesap/hedef ipuclari (yeni alanlar)
  tags: string[]; // ikincil kategoriler + ozel etiketler (platform vb.)
}

/** Yeni ipucu alanlari: eylem / hesap / hedef (UI'da ayri satirlarda gosterilir). */
export interface SemanticHints {
  action: string; // ne is yapiyor (fiil tabanli tahmin)
  computation: string; // ne hesapliyor/okuyor
  target: string; // nereye yaziyor/etkiliyor
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
    // can/HP/mana/stat/regen/olum - karakter saglik domani
    "health", "can", "hp", "life", "heal", "healing", "stamina", "mana", "armor", "regen",
    "invincible", "invulnerable", "immortal", "godmode", "player", "character", "pawn",
    "avatar", "karakter", "oyuncu", "playerstate", "alive", "dead", "death", "kill",
    "suicide", "revive", "hunger", "thirst", "oxygen", "fatigue", "sanity", "morale",
    "bleed", "poison", "maxhealth", "maxhp", "healthmax", "currenthealth", "hitpoint",
    "hitpoints", "vitality", "lifepool", "hpregen", "manapool", "maxmana", "manaregen",
    "shield", "shielding", "barrier", "ward", "defense", "defence", "resist", "resistance",
    "immunity", "immune", "cure", "curing", "bandage", "medkit", "firstaid", "potion",
    "elixir", "tonic", "syringe", "adrenaline", "stim", "injury", "wounded", "damageable",
    "mortal", "resurrection", "resurrect", "lives", "respawn", "downed", "knocked",
    "knockdown", "incapacitated", "regeneration", "regenerating", "lifesteal", "vampirism",
    "affliction", "ailment", "buff", "debuff", "sick", "disease", "infection", "starvation",
    "hydration", "breath", "suffocate", "drown", "drowning", "burning", "frostbite",
    "hypothermia", "blood", "bloodpool", "soul", "essence", "isdead", "isalive", "killcount",
    "friendlyfire", "hero", "protagonist", "secondwind", "healrate", "healingrate",
    "staminamax", "staminaregen", "energymax", "energy", "condition", "bodytemp",
  ]],
  [C.SILAH, [
    // hasar/ates/silah - silah domani
    "damage", "hasar", "atk", "attack", "dps", "ammo", "mermi", "magazine", "mag", "clip",
    "weapon", "silah", "gun", "rifle", "pistol", "bullet", "fire", "firerate", "reload",
    "shoot", "recoil", "spread", "crit", "critical", "melee", "grenade", "explosive",
    "bomb", "projectile", "muzzle", "caliber", "aim", "hit", "pierce", "range", "cannon",
    "shooter", "maxdamage", "mindamage", "damageperhit", "attackpower", "attackdamage",
    "attackrange", "attackspeed", "shooting", "firing", "firemode", "burst", "autofire",
    "singlefire", "trigger", "ammunition", "ammopool", "reserveammo", "ammoreserve",
    "reloading", "reloadtime", "shot", "shots", "shotcount", "bulletcount", "bulletspeed",
    "muzzlevelocity", "muzzleflash", "ballistic", "ballistics", "trajectory", "tracer",
    "hitmarker", "headshot", "bodyshot", "limb", "armorpen", "armorpenetration",
    "penetration", "explosion", "blast", "blastradius", "radiusdamage", "splash",
    "splashdamage", "detonate", "detonation", "fuse", "throwable", "crossbow", "bow",
    "arrow", "quiver", "shotgun", "smg", "lmg", "sniper", "carbine", "launcher", "rocket",
    "missile", "mortar", "flamethrower", "napalm", "blade", "sword", "katana", "dagger",
    "knife", "axe", "hammer", "spear", "stab", "slash", "sharpness", "enchant",
    "attachment", "scope", "optic", "suppressor", "silencer", "clipsize", "magsize",
    "ammocapacity", "overheat", "overheating", "chargedshot", "chargeup", "combo",
    "hitstun", "parry", "riposte", "feint", "counterattack", "gunfire", "gunshot",
    "ricochet", "multishot", "critchance", "critdamage", "critmultiplier", "wound",
  ]],
  [C.ENVANTER, [
    // esya/slot/kaynak - envanter domani
    "inventory", "item", "items", "slot", "envanter", "loot", "bag", "backpack", "stash",
    "equip", "gear", "pickup", "drop", "craft", "recipe", "chest", "crate", "container",
    "quantity", "stack", "consumable", "pouch", "holster", "relic", "artifact", "weight",
    "cargo", "inventoryslot", "slotcount", "itemcount", "itemid", "itemtype", "itemdef",
    "itemclass", "itemrarity", "rarity", "legendary", "epic", "uncommon", "drops",
    "droprate", "dropchance", "looting", "lootbox", "lootcrate", "lootable", "grounditem",
    "worlditem", "warehouse", "sack", "satchel", "equipped", "equipable", "equipping",
    "unequip", "wearable", "wearing", "carried", "carry", "carryweight", "encumbrance",
    "loadout", "kit", "gearset", "equipment", "materials", "resource", "resources",
    "ingot", "component", "components", "ingredient", "ingredients", "crafting",
    "craftable", "blueprint", "schematic", "workbench", "forge", "smelter", "smithing",
    "salvage", "scrap", "repairkit", "durability", "usable", "usecount", "charges",
    "itemlevel", "itemskin", "itemname", "items", "stackcount", "stacksize", "maxstack",
    "inventorygrid", "hotbar", "quickslot", "belt", "vault", "collectionbin", "transfer",
  ]],
  [C.EKONOMI, [
    // para/magaza/ticaret - ekonomi domani
    "money", "gold", "coin", "para", "cash", "credit", "credits", "bakiye", "currency",
    "wallet", "price", "shop", "store", "sell", "buy", "purchase", "trade", "payment",
    "transaction", "balance", "bank", "diamond", "gem", "premium", "donate", "salary",
    "revenue", "income", "tax", "iap", "microtransaction", "cashout", "coins", "goldcoin",
    "silver", "copper", "bronze", "gems", "jewels", "tokens", "pointshop", "storeitem",
    "shopitem", "shopkeeper", "merchant", "vendor", "market", "marketplace", "auction",
    "bid", "economy", "economic", "spend", "spending", "expense", "cost", "pricing",
    "discount", "sale", "profit", "earning", "earnings", "wage", "fund", "funds",
    "treasury", "deposit", "withdraw", "withdrawal", "loan", "debt", "interest",
    "invest", "investment", "cashregister", "receipt", "invoice", "billing",
    "subscription", "membership", "vip", "battlepoints", "arcadepoints", "currencies",
    "moneybag", "casino", "bet", "betting", "gamble", "gambling", "jackpot", "lottery",
    "wager", "poker", "blackjack", "roulette", "slotmachine", "payday", "paywall",
    "walletbalance", "totalprice", "unitprice", "itemprice", "sellprice", "buyprice",
    "refund", "refunding", "purchasable", "tradable", "trading", "barter", "swapfee",
  ]],
  [C.ILERLEME, [
    // seviye/xp/odul - ilerleme domani
    "level", "xp", "exp", "experience", "seviye", "rank", "ranking", "skill", "prestige",
    "quest", "mission", "achievement", "unlock", "progress", "score", "points",
    "reputation", "badge", "talent", "perk", "upgrade", "tier", "league", "rating", "mmr",
    "elo", "leaderboard", "battlepass", "mastery", "levelup", "levels", "levelcap",
    "maxlevel", "xpamount", "xpneeded", "xpreward", "exppoints", "levelsystem",
    "skillpoints", "skilltree", "skilllevel", "attribute", "attributes", "stat",
    "stats", "statpoints", "boost", "booster", "boosters", "progression", "progressing",
    "leveling", "rankup", "ranked", "rankpoints", "ranks", "division", "seasonreward",
    "reward", "rewards", "rewardtable", "unlockable", "unlocks", "challenge",
    "challenges", "achievementpoints", "trophy", "trophies", "medal", "medals", "ribbon",
    "questlog", "quests", "queststate", "questgiver", "objective", "objectives",
    "completed", "completion", "completionrate", "prestigelevel", "paragon",
    "ascension", "awakening", "evolve", "evolution", "evolved", "career", "careerlevel",
    "accountlevel", "accountxp", "profilelevel", "collectible", "collection", "collect",
    "collected", "explevel", "xpcurve", "xpbonus", "perkpoints", "talentpoints",
    "upgradelevel", "upgrades", "upgraded", "milestone", "milestones", "dailyquest",
    "weeklyquest", "seasonlevel", "passxp", "rankedpoints",
  ]],
  [C.KONUM, [
    // pozisyon/transform/xyz - konum domani
    "position", "pos", "location", "coordinate", "coords", "konum", "origin", "waypoint",
    "marker", "gps", "compass", "map", "worldmap", "zone", "area", "region", "chunk",
    "tile", "sector", "spawnpoint", "teleport", "latitude", "longitude", "altitude",
    "heading", "rotation", "yaw", "pitch", "transform", "world", "distance", "radius",
    "bounds", "quadrant", "posx", "posy", "posz", "xposition", "yposition", "zposition",
    "worldpos", "worldposition", "localpos", "localposition", "relativeposition",
    "coordinates", "coord", "gridpos", "cell", "cellx", "celly", "mapmarker", "locator",
    "zoneid", "zones", "areaid", "regionid", "biome", "biomes", "terrain", "landscape",
    "landmark", "landmarks", "portal", "portals", "fasttravel", "travel", "traveling",
    "spawner", "spawnlocation", "spawnzone", "boundingbox", "aabb", "extent", "extents",
    "dimension", "dimensions", "scale", "scalex", "scaley", "scalez", "quaternion",
    "quat", "euler", "eulerangle", "eulerangles", "matrix", "translate", "translation",
    "rotate", "rotator", "facing", "direction", "dir", "bearing", "azimuth", "elevation",
    "depth", "xyz", "rootlocation", "actorlocation", "getlocation", "setlocation",
    "navpoint", "homingpoint", "travelnode", "sectorid", "zonebounds", "mapbounds",
  ]],
  [C.HAREKET, [
    // hiz/ivme/fizik/ carpisma - hareket domani
    "velocity", "speed", "hiz", "move", "movement", "jump", "dash", "gravity", "physic",
    "physics", "momentum", "acceleration", "accel", "friction", "bounce", "ragdoll",
    "collision", "collider", "hitbox", "swim", "climb", "sprint", "walk", "run", "fall",
    "falling", "parachute", "glide", "roll", "dodge", "impulse", "force", "torque",
    "mass", "knockback", "slide", "crouch", "lean", "maxspeed", "movespeed", "walkspeed",
    "runspeed", "sprintspeed", "jumpspeed", "jumpforce", "jumpheight", "doublejump",
    "walljump", "ladder", "ladderclimb", "vault", "mantle", "ledge", "hang", "grab",
    "swimming", "diving", "buoyancy", "float", "floating", "sinking", "sink",
    "gravityscale", "gravitation", "terminalvelocity", "freefall", "fallspeed",
    "landing", "landed", "land", "grounded", "isgrounded", "onground", "groundcheck",
    "jumping", "crouching", "crouched", "standing", "stand", "prone", "sprinting",
    "angular", "linearvelocity", "lineardamping", "damping", "drag", "airdrag",
    "bounciness", "restitution", "elasticity", "rigidbody", "physx", "havok", "chaos",
    "physicsasset", "collisionprofile", "collisions", "collide", "colliding", "overlap",
    "sweep", "swept", "raycast", "raycasts", "linetrace", "hitresult", "impact",
    "impactpoint", "debris", "kinematic", "simulation", "simulate", "constraint",
    "constraints", "hinge", "joint", "joints", "spring", "pivot", "thrust", "propulsion",
    "locomotion", "climbing", "sliding", "rolling", "dodging", "dashes", "dashcount",
    "mobility", "airspeed", "groundspeed",
  ]],
  [C.ARAC, [
    // surus/yaris/tasit - arac domani
    "car", "vehicle", "wheel", "wheels", "engine", "arac", "araba", "plane", "aircraft",
    "helicopter", "heli", "boat", "ship", "tank", "truck", "bike", "motorcycle", "drift",
    "driving", "driver", "passenger", "chassis", "fuel", "nitro", "steer", "steering",
    "brake", "throttle", "flight", "jet", "submarine", "hover", "garage", "parking",
    "traffic", "cars", "vehicles", "vehiclestate", "vehiclehealth", "enginepower",
    "horsepower", "rpm", "gear", "gears", "gearbox", "transmission", "clutch", "shifting",
    "accelerate", "accelerating", "decelerate", "deceleration", "braking", "handbrake",
    "tire", "tyre", "tires", "tyres", "suspension", "drifting", "grip", "traction",
    "understeer", "oversteer", "racing", "race", "races", "racetrack", "track", "tracks",
    "lap", "laps", "laptime", "bestlap", "startline", "finishline", "fuellevel",
    "fueltank", "gasoline", "petrol", "diesel", "refuel", "refueling", "odometer",
    "speedometer", "dashboard", "cockpit", "hood", "trunk", "bumper", "spoiler",
    "fender", "exhaust", "turbo", "nitrous", "siren", "police", "ambulance",
    "firetruck", "taxi", "bus", "van", "trailer", "caravan", "atv", "snowmobile",
    "jetski", "yacht", "sail", "sailing", "ferry", "pilot", "piloting", "runway",
    "takeoff", "airspeed", "autopilot", "wing", "wings", "propeller", "rotor", "train",
    "locomotive", "railway", "metro", "tram", "wagon", "cart", "carriage", "enginehealth",
    "vehiclewheels", "drivable", "drivablestate", "vehicleteam",
  ]],
  [C.GORSEL, [
    // model/mesh/doku/skin/karakter ozellestirme - gorsel domani
    "skin", "skins", "skinid", "model", "mesh", "texture", "tex", "material", "apparel",
    "outfit", "cosmetic", "cloth", "clothing", "hair", "face", "body", "appearance",
    "costume", "color", "tint", "decal", "prop", "wardrobe", "customization", "dye",
    "palette", "morph", "modelid", "models", "meshes", "meshid", "staticmesh", "geometry",
    "polygon", "uv", "textureid", "texturing", "albedo", "normalmap", "roughness",
    "metallic", "glossiness", "emissive", "opacity", "transparency", "alpha",
    "materialinstance", "materialid", "mipmap", "mipmaps", "colors", "colorid", "hue",
    "saturation", "haircolor", "hairstyle", "beard", "mustache", "eyebrow", "eyes",
    "eyecolor", "complexion", "scars", "tattoo", "tattoos", "piercing", "makeup",
    "facial", "facialhair", "head", "torso", "arms", "legs", "hands", "feet", "gloves",
    "boots", "helmet", "hat", "cap", "shirt", "pants", "jacket", "coat", "dress",
    "skirt", "shoes", "accessory", "accessories", "jewelry", "necklace", "ring",
    "earring", "bracelet", "emblem", "logo", "sticker", "stickers", "paintjob", "paint",
    "livery", "camo", "camouflage", "pattern", "style", "blendshape", "blendshapes",
    "morphs", "bodytype", "physique", "muscle", "silhouette", "skinnable", "cosmetics",
    "customize", "customized", "customizer", "outfits", "clothes", "clothphysics",
    "jacketcolor", "shirtcolor", "viewmodel", "worldmodel", "attachmodel",
  ]],
  [C.ANIMASYON, [
    // animasyon/iskelet - animasyon domani
    "animation", "anim", "animations", "skeleton", "bone", "bones", "montage", "blend",
    "blendspace", "pose", "rig", "ik", "motion", "animgraph", "emote", "gesture", "dance",
    "playback", "keyframe", "retarget", "anims", "animinstance", "animbp", "animnotify",
    "notifies", "animstate", "statemachine", "transition", "blendweight", "additive",
    "layered", "upperbody", "fullbody", "locomotion", "idle", "hitreact", "hitreaction",
    "reactions", "stagger", "flinch", "physicalanimation", "boneindex", "bonename",
    "socket", "sockets", "footik", "rootmotion", "curves", "curve", "timeline",
    "sequences", "sequence", "sequencer", "playrate", "looping", "loop", "loops",
    "mirrored", "mirror", "mirroring", "procedural", "motionwarping", "aimoffset",
    "gestures", "wave", "cheer", "clap", "taunt", "taunts", "dances", "dancing",
    "emotes", "lipsync", "viseme", "animationblending", "animontage", "poses",
    "posing", "rigged", "rigging", "skeletonpose", "boneweight", "skinning",
    "skeletal", "playanim", "stopanim", "animlength", "animtime", "blendposes",
  ]],
  [C.GRAFIK, [
    // render/shader/golge - grafik domani
    "render", "rendering", "renderer", "shader", "draw", "drawcall", "lighting", "shadow",
    "postprocess", "fps", "frame", "framerate", "graphics", "d3d11", "d3d12", "dx11",
    "dx12", "dxgi", "vulkan", "opengl", "directx", "bloom", "raytracing", "resolution",
    "quality", "vertex", "pixel", "gpu", "rasterizer", "depthstencil", "swapchain",
    "present", "gamma", "brightness", "antialias", "vram", "renders", "drawcalls",
    "instancing", "instanced", "batching", "culling", "occlusion", "backface",
    "cullmode", "zbuffer", "depthbuffer", "stencilbuffer", "stencil", "shadowmap",
    "shadows", "castshadow", "light", "lights", "lightmap", "lightprobe",
    "globalillumination", "illumination", "ambient", "ambientocclusion", "diffuse",
    "reflection", "reflections", "refraction", "fresnel", "hdr", "tonemapping",
    "tonemap", "exposure", "colorgrading", "grading", "lut", "vignette",
    "chromaticaberration", "aberration", "motionblur", "blur", "dof", "depthoffield",
    "grain", "filmgrain", "lensflare", "godrays", "postfx", "posteffects", "fxaa",
    "smaa", "taa", "msaa", "antialiasing", "sharpening", "upscale", "upscaling", "dlss",
    "fsr", "displaymode", "fullscreen", "windowed", "borderless", "vsync", "refreshrate",
    "vertexbuffer", "indexbuffer", "constantbuffer", "hlsl", "glsl", "spirv",
    "renderpass", "pipeline", "gbuffer", "deferred", "forward", "lumen", "nanite",
    "pathtracing", "rtx", "scene", "scenecolor", "shadowquality", "graphicsettings",
    "graphicquality", "raycastshadows", "renderdistance", "drawdistance", "fogdensity",
  ]],
  [C.KAMERA, [
    // kamera/gorus - kamera domani
    "camera", "kamera", "cam", "viewtarget", "zoom", "shake", "springarm", "boom",
    "orbit", "cine", "cinematic", "focal", "firstperson", "thirdperson", "pov",
    "viewport", "lookat", "freelook", "frustum", "fisheye", "freecam", "cameras",
    "cameracomponent", "cameramanager", "maincamera", "editorcamera", "photomode",
    "replay", "replays", "spectate", "spectating", "spectator", "binocular",
    "binoculars", "zoomin", "zoomout", "zooming", "zoomed", "fov", "fieldofview",
    "aspectratio", "aspect", "lens", "aperture", "shutter", "focus", "focused",
    "focusing", "autofocus", "oscillation", "trauma", "shakes", "shaking",
    "cameralag", "follow", "following", "panning", "pan", "tilt", "tilting", "dolly",
    "crane", "headbob", "bobbing", "bob", "sway", "swaying", "perspective",
    "orthographic", "projection", "projectionmatrix", "viewmatrix", "znear", "zfar",
    "cutscene", "cutscenes", "camerashake", "camerarig", "cameraarm", "lookinput",
    "camerapitch", "camerayaw", "cameraroll", "viewpitch", "viewyaw", "eyeh",
    "photocamera", "replaycam", "spectatorview", "shoulderview", "aimcamera",
  ]],
  [C.HAVA, [
    // hava durumu/cevre/gun dongusu - hava domani
    "weather", "rain", "sun", "sunny", "snow", "temperature", "wind", "gunbatimi",
    "hava", "climate", "fog", "storm", "thunder", "lightning", "humidity", "forecast",
    "sunrise", "sunset", "dusk", "dawn", "moon", "cloud", "tide", "weathers",
    "weathertype", "weatherstate", "weathersystem", "raining", "rainy", "rainfall",
    "drizzle", "downpour", "monsoon", "hail", "snowing", "snowy", "snowfall",
    "blizzard", "frost", "freezing", "icy", "windy", "winddirection", "windspeed",
    "gust", "breeze", "tornado", "hurricane", "cyclone", "typhoon", "sandstorm",
    "dust", "ash", "clouds", "cloudy", "overcast", "sky", "skybox", "skydome",
    "sunlight", "sunshine", "daylight", "nighttime", "nightfall", "midnight", "noon",
    "afternoon", "morning", "evening", "twilight", "daycycle", "daynight",
    "daynightcycle", "puddle", "puddles", "wetness", "wet", "moisture", "drought",
    "heatwave", "heat", "cold", "warmth", "atmosphere", "atmospheric", "pressure",
    "smog", "haze", "mist", "misty", "thunderstorm", "stormy", "storms", "raindensity",
    "snowdensity", "weatherforecast", "lightningbolt", "sundirection", "moondirection",
    "skycolor", "skylight", "ambientsky", "tides", "waveheight", "oceanwave",
  ]],
  [C.SES, [
    // ses/muzik/efekt - ses domani
    "audio", "sound", "music", "voice", "sfx", "mixer", "volume", "mute", "soundtrack",
    "ambience", "reverb", "doppler", "audiomix", "playlist", "radio", "bass", "tone",
    "beep", "speaker", "microphone", "footsteps", "sounds", "soundcue", "soundclass",
    "soundwave", "audiostream", "audiosource", "audiolistener", "audiodevice",
    "audiosettings", "volumes", "master", "bus", "stereo", "surround", "spatial",
    "spatialize", "spatialization", "listener", "attenuation", "lowpass", "highpass",
    "eq", "equalizer", "playsound", "playing", "musictrack", "musicsystem",
    "musicmanager", "song", "songs", "melody", "jingle", "theme", "vocal", "vocals",
    "voiceline", "voicelines", "dialogue", "dialogues", "subtitle", "subtitles",
    "caption", "captions", "chatter", "bark", "barks", "grunt", "scream", "shout",
    "whisper", "laugh", "breathing", "heartbeat", "thump", "thud", "clang", "clank",
    "rattle", "creak", "hiss", "buzz", "hum", "whir", "click", "snap", "crack",
    "boom", "bang", "gunshot", "ricochetsound", "whistle", "whistling", "echo",
    "acoustics", "sfxvolume", "duck", "ducking", "fade", "fadein", "fadeout",
    "fading", "crossfade", "silence", "silent", "quiet", "loudness", "decibel",
    "gain", "amplitude", "frequency", "waveform", "oscillator", "synth",
    "synthesizer", "sampler", "modulation", "lfo", "footstep", "voiceover",
    "radiochannel", "musicvolume", "soundvolume", "voicechatvolume", "mixerbus",
  ]],
  [C.ARAYUZ, [
    // arayuz/hud/widget - arayuz domani
    "ui", "hud", "widget", "menu", "button", "panel", "overlay", "tooltip", "cursor",
    "crosshair", "minimap", "slider", "checkbox", "textbox", "dialog", "toast",
    "notification", "banner", "layout", "screen", "font", "healthbar", "progressbar",
    "icon", "tab", "userinterface", "interface", "uielement", "uimanager", "widgets",
    "indicators", "indicator", "gauge", "meter", "bar", "reticle", "dmgnumber",
    "damagenumber", "floatingtext", "popup", "popups", "modal", "toolbar", "submenu",
    "mainmenu", "pausemenu", "loadingscreen", "menus", "buttons", "labels", "label",
    "scrollbar", "scrollview", "dropdown", "combobox", "listbox", "radiobutton",
    "toggle", "picker", "inputfield", "portrait", "border", "anchoring", "anchor",
    "anchors", "alignment", "align", "margin", "margins", "padding", "spacing",
    "canvas", "theme", "themes", "theming", "localization", "localized", "locale",
    "language", "languages", "translation", "translations", "translated", "i18n",
    "stringtable", "fonts", "fontsize", "glyph", "glyphs", "letter", "letters",
    "hover", "hovered", "hovering", "clickable", "click", "clicked", "notice",
    "alert", "alerts", "confirmation", "confirm", "prompt", "prompts", "chatbox",
    "scoreboard", "infobox", "hudwidget", "hudelement", "compassui", "radarui",
    "uicolor", "uiscale", "hudscale", "menustate", "menumanager", "popupmenu",
    "contextmenu", "toastmessage", "notificationcenter", "iconlib", "spriteui",
  ]],
  [C.AG, [
    // ag/online/senkronizasyon - ag domani
    "network", "ping", "latency", "session", "socket", "replication", "rpc", "online",
    "multiplayer", "server", "client", "host", "join", "lobby", "match", "packet",
    "tcp", "udp", "http", "https", "websocket", "steam", "epic", "eos", "platform",
    "bandwidth", "netmode", "channel", "disconnect", "reconnect", "matchmaking",
    "login", "auth", "token", "downloader", "upload", "endpoint", "payload", "proxy",
    "relay", "hostname", "port", "ip", "networking", "netdriver", "netconnection",
    "netguid", "netid", "netrole", "dormancy", "relevancy", "relevant", "reliable",
    "unreliable", "ack", "resend", "retransmit", "packetloss", "jitter",
    "lagcompensation", "compensation", "prediction", "predicted", "interpolation",
    "extrapolation", "snapshots", "snapshot", "compression", "datagram", "hosting",
    "hosted", "dedicated", "dedicatedserver", "servers", "clients", "connecting",
    "connected", "connection", "connections", "connect", "handshake", "ssl", "tls",
    "ipaddress", "ipv4", "ipv6", "p2p", "peer", "peers", "broadcast", "multicast",
    "sendto", "send", "sending", "sent", "receive", "received", "receiving", "recv",
    "transmit", "transmission", "transfer", "transferring", "download", "downloads",
    "downloading", "uploaded", "uploading", "queue", "queued", "queuing", "party",
    "invite", "invites", "invitation", "invited", "chat", "chats", "chatting",
    "chatmessage", "messages", "message", "messaging", "typing", "voicechat", "voip",
    "discord", "richpresence", "presence", "steamworks", "steamapi", "steamid",
    "xbox", "playstation", "psn", "nintendo", "crossplay", "account", "accounts",
    "accountid", "credential", "credentials", "password", "username", "user", "users",
    "userid", "sessionid", "ticket", "oauth", "jwt", "logout", "signin", "signout",
    "authenticate", "authentication", "authenticator", "netguidcache", "replicated",
    "replicates", "replicating", "rpcserver", "rpcclient", "worldoriginrebase",
    "rebase", "relevances", "connectiontable", "nettraffic",
  ]],
  [C.KAYIT, [
    // kayit/yukleme/konfig - kayit domani
    "save", "saving", "autosave", "cloudsave", "config", "configuration", "setting",
    "settings", "profil", "profile", "kayit", "preference", "prefs", "persist",
    "persistence", "userdata", "checkpoint", "backup", "restore", "export", "import",
    "registry", "storage", "file", "files", "saved", "savegame", "savegames",
    "savefile", "savefiles", "savedata", "saves", "quicksave", "quickload",
    "loadgame", "loading", "loaded", "load", "loaddata", "deserialize", "json",
    "xml", "yaml", "toml", "csv", "writefile", "readfile", "filestream", "filepath",
    "filename", "extension", "directory", "directories", "folder", "folders",
    "disk", "cloud", "cloudsync", "sync", "syncing", "overwrite", "rollback",
    "undo", "redo", "revert", "reverting", "defaults", "configfile", "inifile",
    "ini", "registrykey", "appdata", "documents", "gamestate", "gameinstance",
    "persisted", "persistentlevel", "worldsave", "savelist", "userconfig",
    "usersettings", "settingsoverride", "configdata", "savepoint", "saveversion",
    "migrationdata", "backuprestore", "loadscreen", "saveload", "profiledata",
    "userprofile", "configmanager", "savemanager", "loadmanager", "storagewrite",
    "storageread", "serializedata", "unserializedata",
  ]],
  [C.GIRDI, [
    // tus/kontrol/girdi - girdi domani
    "input", "inputs", "key", "keys", "keyboard", "mouse", "touch", "gamepad",
    "controller", "joystick", "axis", "bind", "binding", "hotkey", "rumble",
    "vibration", "sensitivity", "deadzone", "keymap", "control", "controls", "hold",
    "press", "release", "tap", "swipe", "drag", "keypress", "keydown", "keyup",
    "keycode", "keyevent", "keystroke", "keystrokes", "mouseclick", "mousedown",
    "mouseup", "mousemove", "mousewheel", "wheel", "pointerposition", "touchstart",
    "touchend", "touchmove", "touchscreen", "multitouch", "pinch", "longpress",
    "doubleclick", "doubletap", "clicks", "taps", "tapping", "clicking", "swiping",
    "dragging", "dragged", "draggable", "stick", "sticks", "thumbstick", "analog",
    "bumper", "dpad", "buttons", "keybinding", "keybindings", "binds", "bindings",
    "remap", "remapping", "remapped", "rebind", "rebinding", "inputmapping",
    "inputaction", "inputactions", "enhancedinput", "inputcomponent", "poll",
    "polling", "rawinput", "directinput", "xinput", "hid", "usb", "device",
    "devices", "inputdevice", "controllerid", "controllers", "pad", "pads",
    "steeringwheel", "pedals", "pedal", "haptic", "haptics", "forcefeedback",
    "vibrations", "gyro", "gyroscope", "accelerometer", "mousex", "mousey",
    "mousedx", "mousedy", "lookinput", "lookaxis", "moveinput", "moveaxis",
    "inputaxis", "axisvalue", "pressed", "released", "held", "holding", "chord",
    "shortcut", "shortcuts", "macro", "macros", "inputbuffer", "inputcontext",
    "inputstate", "keystate", "buttonstate", "controllertype", "gamepads",
  ]],
  [C.YAPAYZEKA, [
    // davranis/algı/yol bulma - yapay zeka domani
    "ai", "behavior", "bt", "brain", "bot", "npc", "enemy", "enemies", "aggro",
    "pathfind", "pathfinding", "navmesh", "flee", "chase", "patrol", "perception",
    "threat", "difficulty", "companion", "crowd", "aware", "senses", "vision",
    "decision", "utility", "goap", "blackboard", "ais", "aiagent", "aicontroller",
    "behaviors", "behaviour", "behaviours", "behaviortree", "bttask", "btservice",
    "btdecorator", "selector", "planner", "planning", "plan", "plans", "goal",
    "goals", "intent", "intents", "intention", "strategy", "strategies", "strategic",
    "tactic", "tactics", "tactical", "aistate", "alerted", "alert", "suspicious",
    "suspicion", "suspect", "hunting", "hunt", "hunter", "hunted", "prey", "stalk",
    "stalking", "ambush", "attacker", "attackers", "target", "targets", "targeted",
    "los", "lineofsight", "sight", "seeing", "seen", "detect", "detection",
    "detected", "sensor", "sensors", "sensing", "hearing", "hear", "heard",
    "noise", "awareness", "spotted", "spot", "attention", "hatelist", "threats",
    "danger", "dangerous", "hazard", "hazards", "avoid", "avoidance", "avoiding",
    "evade", "evading", "evasion", "escape", "escaping", "fleeing", "pursuit",
    "pursuing", "pursue", "chasing", "follower", "followers", "formation",
    "formations", "squad", "squads", "swarm", "swarming", "herd", "flock",
    "flocking", "npcs", "monster", "monsters", "creature", "creatures", "mob",
    "mobs", "boss", "bosses", "hostile", "hostiles", "hostility", "ally", "allies",
    "faction", "factions", "crew", "stealth", "sneak", "sneaking", "visibility",
    "visible", "cover", "flanking", "flank", "leash", "navmeshdata", "navgraph",
    "navpoly", "pathpoint", "paths", "patrolpoint", "patrolling", "patrols",
    "spawnenemy", "enemycount", "enemylist", "aiperception", "aidamage", "aihealth",
  ]],
  [C.ZAMAN, [
    // zamanlayici/sayac/gun dongusu - zaman domani
    "timer", "clock", "day", "night", "season", "date", "time", "timeofday",
    "cooldown", "duration", "interval", "tickrate", "schedule", "countdown", "elapsed",
    "delta", "deltatime", "timestamp", "uptime", "calendar", "year", "month", "hour",
    "minute", "second", "delay", "realtime", "daytime", "timers", "timeout",
    "timeouts", "timeleft", "timeremaining", "expired", "expiry", "expire",
    "expiration", "period", "periodic", "timespan", "timestep", "ticks", "ticked",
    "ticking", "tickcount", "frametime", "gameclock", "gametime", "simtime",
    "localtime", "utc", "timezone", "stopwatch", "countdowns", "remaining",
    "millisecond", "milliseconds", "days", "week", "weeks", "weekday", "weekend",
    "months", "years", "era", "epoch", "age", "aging", "holiday", "holidays",
    "festival", "cron", "scheduled", "scheduler", "alarm", "reminder", "reminders",
    "sleep", "sleeping", "wake", "wakeup", "slowmotion", "slowmo", "timescale",
    "timedilation", "fastforward", "rewind", "nightday", "daycount", "hourcount",
    "timecycle", "clockcycle", "gameclockspeed", "cooldowns", "cooldownleft",
    "cooldownremaining", "spawninterval", "respawntime", "respawntimer", "uptimecount",
  ]],
  [C.DEBUG, [
    // hata ayiklama/dev/log - debug domani
    "debug", "debugger", "dev", "developer", "console", "cheat", "cheats", "test",
    "testing", "assert", "log", "logging", "logger", "dump", "dbg", "breakpoint",
    "profiling", "verbose", "warning", "error", "exception", "crash", "debugging",
    "devmode", "devbuild", "debugdraw", "debugprint", "print", "printf", "println",
    "trace", "tracing", "stacktrace", "backtrace", "callstack", "symbol", "symbols",
    "diagnostic", "diagnostics", "analytics", "telemetry", "metrics", "metric",
    "report", "reports", "reporting", "audit", "monitor", "monitoring", "watch",
    "watchdog", "inspector", "inspect", "hook", "hooks", "hooking", "hooked",
    "detour", "patch", "patching", "patched", "interceptor", "intercept",
    "intercepted", "inject", "injection", "injected", "attach", "detach", "cheater",
    "cheating", "experimental", "prototype", "unstable", "crashdump", "crashed",
    "crashes", "fatal", "panic", "abort", "terminate", "fail", "failed", "failure",
    "fault", "invalid", "broken", "fixme", "todo", "hack", "hacks", "hacked",
    "workaround", "temporary", "temp", "tmp", "placeholder", "stub", "mock",
    "unittest", "benchmark", "performance", "perf", "profiled", "timings", "sampling",
    "counters", "verbosity", "logged", "logs", "spew", "screenshot", "framecounter",
    "debughud", "debugspawn", "cheatmenu", "devtools", "internaltest", "diagnosticsdump",
  ]],
  [C.ANTIHILE, [
    // koruma/dogrulama/sifreleme - antihile domani
    "anticheat", "shield", "protect", "protection", "encrypt", "encryption", "decrypt",
    "obfus", "obfuscate", "integrity", "secure", "security", "guard", "ban",
    "validate", "verify", "signature", "checksum", "license", "drm", "hwid",
    "sandbox", "permission", "tamper", "jailbreak", "guardian", "defender",
    "battleye", "easyanticheat", "eac", "vanguard", "denuvo", "vmprotect", "themida",
    "obfuscated", "obfuscation", "scramble", "cipher", "ciphertext", "plaintext",
    "aes", "rsa", "sha", "md5", "hash", "hashed", "hashing", "digest", "nonce",
    "salt", "hmac", "signed", "signing", "verified", "verification", "validation",
    "crc", "parity", "flagged", "violation", "banned", "banning", "bans",
    "blacklist", "blacklisted", "whitelist", "allowlist", "blocklist", "restricted",
    "forbid", "deny", "denied", "revoke", "revoked", "piracy", "pirated", "crack",
    "cracked", "harden", "hardened", "tampered", "tampering", "corrupted",
    "anomaly", "intrusion", "intruder", "malware", "exploit", "exploits",
    "vulnerability", "mitigation", "defend", "sentinel", "watcher", "encrypted",
    "decrypted", "decrypting", "encrypting", "authenticity", "authentic",
    "whitelisting", "blacklisting", "protective", "protected", "unprotected",
    "integritycheck", "securitycheck", "banwave", "cheatdetection", "tampercheck",
  ]],
  [C.BELLEK, [
    // bellek/allocator/motor icleri - bellek domani
    "memory", "mem", "alloc", "allocation", "allocator", "heap", "pool", "malloc",
    "garbage", "gc", "refcount", "buffer", "arena", "leak", "vmem", "address",
    "pointer", "deref", "mmap", "paging", "virtualalloc", "readprocess",
    "writeprocess", "snapshot", "cache", "free", "memmgr", "memorypool", "memblock",
    "allocations", "allocated", "realloc", "calloc", "freeing", "freed", "freelist",
    "deallocation", "deallocate", "dealloc", "heapalloc", "heapsize", "stackalloc",
    "stack", "stacks", "buffered", "buffering", "buffers", "ringbuffer", "pooled",
    "pooling", "objectpool", "slab", "page", "pages", "paged", "pagefile", "virtual",
    "commit", "decommit", "mapping", "mapped", "unmap", "handle", "handles",
    "refcounted", "reference", "references", "referenced", "weakref", "owner",
    "owned", "ownership", "copymemory", "memcpy", "memset", "alignment", "aligned",
    "overrun", "underflow", "leaks", "leaking", "arenas", "lifo", "fifo",
    "virtualquery", "virtualfree", "openprocess", "closehandle", "processid",
    "baseaddress", "module", "modules", "dll", "imagebase", "iat", "rawpointer",
    "dereference", "indirect", "garbagecollection", "garbagecollector", "compact",
    "compaction", "oom", "outofmemory", "memorypressure", "cachehit", "cachemiss",
    "cached", "caching", "eviction", "lru", "workingset", "memalign", "byteswap",
    "modulebase", "modulebaseaddress", "peimage", "imagebuffer", "gnames",
    "guobjectarray", "fnamepool", "fmemory", "il2cppdomain", "monoalloc", "heapgrow",
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
// kategori meta tablosu: EN kimlik + Turkce aciklama
// (ne is yapar / ne hesaplar / nereye yazar-etkiler) - UI'da gosterilir
// ---------------------------------------------------------------------------

interface CategoryMeta {
  id: string; // makine okur EN kimlik (badge/rozet anahtari)
  ne: string; // ne is yapar
  hesap: string; // ne hesaplar/okur
  yazar: string; // nereye yazar/etkiler
  desc: string; // birlesik kisa TR aciklama (kullaniciya gosterilir)
}

const CATEGORY_META: Record<string, CategoryMeta> = {
  [C.SAGLIK]: {
    id: "character_health",
    ne: "Karakter sagligini/can durumunu yonetir",
    hesap: "HP/mana/stamina degerlerini ve yenilenme miktarini hesaplar",
    yazar: "Health/can ve stamina alanlarina yazar",
    desc: "Karakter sagligi domani: can/HP/mana/stamina degerlerini okuyup gunceller, hasar-iyilestirme ve yenilenme miktarini hesaplar; sonucu Health/can alanlarina yazar.",
  },
  [C.SILAH]: {
    id: "weapon_damage",
    ne: "Ates etme ve hasar uygulama mantigini yurutur",
    hesap: "Hasar/crit/spread/firerate gibi ates parametrelerini hesaplar",
    yazar: "Hasar, ammo ve ates hattina yazar",
    desc: "Silah/hasar domani: ates etme ve hasar uygulama mantigini yurutur; hasar, kritik sans ve mermi sayimi hesaplar; sonucu ammo/hasar alanlarina yazip ates hattini tetikler.",
  },
  [C.ENVANTER]: {
    id: "inventory_items",
    ne: "Esya ekleme/cikarma/slot yonetimi yapar",
    hesap: "Esya adedi, agirlik ve slot yerlesimini hesaplar",
    yazar: "Envanter slot/dizi alanlarina yazar",
    desc: "Envanter domani: esya ekleme-cikarma ve kuşanma yonetir; adet/agirlik/slot yerlesimi hesaplar; envanter slot ve dizi alanlarina yazar.",
  },
  [C.EKONOMI]: {
    id: "currency_economy",
    ne: "Para ekleme/harcama/ticaret islemlerini yurutur",
    hesap: "Bakiye, fiyat ve odul-para donusumunu hesaplar",
    yazar: "Para/bakiye alanlarina yazar",
    desc: "Ekonomi domani: para ekleme-harcama-ticaret islemlerini yurutur; bakiye ve fiyat hesaplar; para/bakiye alanlarina yazar.",
  },
  [C.ILERLEME]: {
    id: "progression",
    ne: "Seviye/skill/odul ilerlemesini yonetir",
    hesap: "XP toplamini, seviye esigi ve odul kosullarini hesaplar",
    yazar: "XP/level/progress alanlarina yazar",
    desc: "Ilerleme domani: seviye-skill-odul akisini yonetir; XP toplami ve seviye esigi hesaplar; XP/level/progress alanlarina yazar.",
  },
  [C.KONUM]: {
    id: "position_transform",
    ne: "Pozisyon/yon/olcek verisini tutar ve gunceller",
    hesap: "X/Y/Z koordinat, rotasyon ve mesafe hesaplar",
    yazar: "Transform/pozisyon verisine yazar",
    desc: "Konum domani: pozisyon-yon-olcek (transform) verisini tutup gunceller; X/Y/Z koordinat, rotasyon ve mesafe hesaplar; transform/pozisyon verisine yazar.",
  },
  [C.HAREKET]: {
    id: "movement_physics",
    ne: "Hareket ve fizik simulasyonunu calistirir",
    hesap: "Hiz/ivme/yercekimi ve carpisma tepkilerini hesaplar",
    yazar: "Hiz/ivme ve fizik durum degiskenlerine yazar",
    desc: "Hareket/fizik domani: hareket ve fizik simulasyonunu calistirir; hiz, ivme, yercekimi ve carpisma tepkilerini hesaplar; hiz/fizik durum degiskenlerine yazar.",
  },
  [C.ARAC]: {
    id: "vehicle_driving",
    ne: "Tasit surus/durum mantigini yurutur",
    hesap: "Motor hizi, vites, yakit ve surus fizigini hesaplar",
    yazar: "Arac durumu (hiz/hasar/yakit) alanlarina yazar",
    desc: "Arac domani: tasit surus ve durum mantigini yurutur; motor hizi, vites, yakit ve surus fizigi hesaplar; aracin hiz/hasar/yakit alanlarina yazar.",
  },
  [C.GORSEL]: {
    id: "visual_model",
    ne: "Model/skin/kostum ozelliklerini yonetir",
    hesap: "Model/tur secimi ve gorsel ozellik eslesmesini hesaplar",
    yazar: "Model/kostum ozellik alanlarina yazar",
    desc: "Gorsel domani: model-mesh-doku-skin ozelliklerini ve karakter ozellestirmeyi yonetir; gorsel eslesmeleri hesaplar; model/kostum ozellik alanlarina yazar.",
  },
  [C.ANIMASYON]: {
    id: "animation",
    ne: "Animasyon oynatma ve karisim (blend) yonetir",
    hesap: "Anim poz/karisim agirliklarini hesaplar",
    yazar: "Animasyon durum makinesine yazar",
    desc: "Animasyon domani: anim oynatma, karisim (blend) ve iskelet pozlarini yonetir; poz/karisim agirliklarini hesaplar; animasyon durum makinesine yazar.",
  },
  [C.GRAFIK]: {
    id: "graphics_render",
    ne: "Render hattini besler ve gorsel ayarlari uygular",
    hesap: "Cizim listesi, kalite ayarlari ve efekt parametrelerini hesaplar",
    yazar: "Render hattina parametre tasir",
    desc: "Grafik domani: render hattini besler; cizim listesi, golge/kalite ve efekt parametrelerini hesaplar; GPU'ya cikis parametreleri tasir.",
  },
  [C.KAMERA]: {
    id: "camera",
    ne: "Kamera konum/bakis acisini yonetir",
    hesap: "FOV, takip ve sarsinti (shake) degerlerini hesaplar",
    yazar: "Kamera hedef/parametre alanlarina yazar",
    desc: "Kamera domani: kamera konumu ve bakis acisini yonetir; FOV, takip ve sarsinti degerlerini hesaplar; kamera hedef/parametre alanlarina yazar.",
  },
  [C.HAVA]: {
    id: "weather_environment",
    ne: "Hava durumu/cevre ve gun dongusunu yonetir",
    hesap: "Hava turu, yogunluk ve gun-saat gecisini hesaplar",
    yazar: "Cevre/hava durum degiskenlerine yazar",
    desc: "Hava/cevre domani: hava durumu, gun dongusu ve cevre kosullarini yonetir; hava turu, yogunluk ve saat gecisini hesaplar; cevre durum degiskenlerine yazar.",
  },
  [C.SES]: {
    id: "audio",
    ne: "Ses/muzik oynatma ve mikserde karistirma yapar",
    hesap: "Ses seviyesi, mesafe duyulurlugu ve mikser degerlerini hesaplar",
    yazar: "Ses kanal/volume ayarlarina yazar",
    desc: "Ses domani: ses ve muzik oynatmayi yonetir; seviye, mesafe duyulurlugu ve mikser degerlerini hesaplar; ses kanal/volume ayarlarina yazar.",
  },
  [C.ARAYUZ]: {
    id: "ui_hud",
    ne: "Ekrandaki arayuz/HUD ogelerini cizer ve gunceller",
    hesap: "Gosterge degerleri ve yerlesim/pozisyon hizalamasi hesaplar",
    yazar: "HUD/widget durumuna yazar",
    desc: "Arayuz domani: HUD/widget/menu ogelerini cizer ve gunceller; gosterge degerleri ile yerlesim hizalamasini hesaplar; HUD/widget durumuna yazar.",
  },
  [C.AG]: {
    id: "network_multiplayer",
    ne: "Ag baglantisi ve veri senkronizasyonunu yonetir",
    hesap: "Gecikme, paket boyutu ve replikasyon farklarini hesaplar",
    yazar: "Ag akisina paket/parametre gonderir",
    desc: "Ag/online domani: baglanti ve cok oyunculu senkronizasyonu yonetir; gecikme, paket ve replikasyon farklarini hesaplar; ag akisina paket gonderir.",
  },
  [C.KAYIT]: {
    id: "save_config",
    ne: "Kayit/yukleme ve konfig yonetimini yapar",
    hesap: "Kayit verisi boyutu, surum gecisi ve varsayilan degerleri hesaplar",
    yazar: "Dosya/kayit akisina yazar",
    desc: "Kayit domani: save/load ve konfig yonetimini yapar; kayit verisi surumu ve varsayilanlari hesaplar; dosya/kayit akisina yazar.",
  },
  [C.GIRDI]: {
    id: "input_controls",
    ne: "Klavye/fare/kontrolcu girislerini isler",
    hesap: "Tus eslemesi, eksen degerleri ve duyarlilik hesaplar",
    yazar: "Girdi durum/tus tablosuna yazar",
    desc: "Girdi domani: klavye-fare-kontrolcu girislerini isler; tus eslemesi, eksen degerleri ve duyarlilik hesaplar; girdi durum tablosuna yazar.",
  },
  [C.YAPAYZEKA]: {
    id: "ai_behavior",
    ne: "NPC/dusman davranis kararlarini uretir",
    hesap: "Hedef secimi, yol bulma ve algı skorlarini hesaplar",
    yazar: "YZ davranis durumuna yazar",
    desc: "Yapay zeka domani: NPC/dusman davranisini yonetir; hedef secimi, yol bulma ve algı skorlarini hesaplar; davranis durum makinesine yazar.",
  },
  [C.ZAMAN]: {
    id: "timers_clocks",
    ne: "Zamanlayici/sayac ve oyun saatini yonetir",
    hesap: "Gecen sure, kalan sure ve kare deltasini hesaplar",
    yazar: "Zamanlayici/sayac alanlarina yazar",
    desc: "Zaman domani: zamanlayici, sayac ve oyun saatini yonetir; gecen/kalan sure ve kare deltasini hesaplar; zamanlayici/sayac alanlarina yazar.",
  },
  [C.DEBUG]: {
    id: "dev_debug",
    ne: "Gelistirici araclari, log ve test akisini yurutur",
    hesap: "Tanilama olcumleri ve durum raporlari olusturur",
    yazar: "Log/konsol akisina yazar",
    desc: "Debug/dev domani: gelistirici araclari, log ve test akisini yurutur; tanilama olcumleri olusturur; log/konsol akisina yazar.",
  },
  [C.ANTIHILE]: {
    id: "anticheat_security",
    ne: "Hile/butunluk kontrollerini ve korumayi yurutur",
    hesap: "Dogrulama ozeti (checksum/imza) ve tutarlik kontrolleri hesaplar",
    yazar: "Dogrulama sonucu/bayrak alanlarina yazar",
    desc: "Anti-hile/koruma domani: butunluk ve hile kontrollerini yurutur; checksum/imza ve tutarlik dogrulamasi hesaplar; dogrulama sonucu/bayrak alanlarina yazar.",
  },
  [C.BELLEK]: {
    id: "memory_engine",
    ne: "Bellek ayirma/serbest birakma ve motor ic yapisini yonetir",
    hesap: "Adres/offset cozumu ve bellek blok boyutlarini hesaplar",
    yazar: "Bellek bolgesini ayirir/yazar",
    desc: "Bellek/motor domani: bellek ayirma (allocator) ve motor ic yapisini yonetir; adres/offset cozumu ve blok boyutlarini hesaplar; bellek bolgesini ayirir/yazar.",
  },
  [C.GENEL]: {
    id: "general",
    ne: "Genel amacli islem",
    hesap: "Sozluk eslesmesi olmadigindan hesaplanan veri belirsiz",
    yazar: "Yazma hedefi belirsiz",
    desc: "Genel: ad icinde sozluge dusen bir oyun/program anahtar kelimesi bulunamadi; kategori tahmini icin yetersiz ipucu var.",
  },
};

function metaOf(cat: string): CategoryMeta {
  return CATEGORY_META[cat] ?? CATEGORY_META[C.GENEL]!;
}

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
  const lastIdx = tokens.length - 1;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;
    // sozlukte birebir var -> tam eslesme (son token = bas isim; +1 bonus)
    const direct = DICT[t];
    if (direct !== undefined) {
      bump(direct, t, i === lastIdx ? 4 : 3, true, i);
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

/** Kategori meta bilgisi + eylem ipucundan SemanticHints uretir. */
function hintsFor(cat: string, action?: string): SemanticHints {
  const meta = metaOf(cat);
  return {
    action: action ?? meta.ne,
    computation: meta.hesap,
    target: meta.yazar,
  };
}

function genelInfo(summaryTail = ""): SemanticInfo {
  const base = "Tahmin icin yeterli anahtar kelime bulunamadi";
  return {
    category: C.GENEL,
    categoryId: metaOf(C.GENEL).id,
    confidence: 0,
    summary: summaryTail ? `${base}; ${summaryTail}` : base,
    computes: "eslesen anahtar kelime yok (girdi adi anlamsiz/normalize edilemedi)",
    writes: "Yazma hedefi belirlenemedi (eslesme yok)",
    description: metaOf(C.GENEL).desc,
    hints: hintsFor(C.GENEL),
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
  const verb = tokens.find((t) => VERB_TEMPLATES[t] !== undefined);
  return {
    category: win.cat,
    categoryId: metaOf(win.cat).id,
    confidence: confidenceOf(win),
    summary: `"${name}": ${subject} baglaminda kullaniliyor olabilir`,
    computes: `Eslesen anahtar kelimeler: ${win.sc.words.join(", ")}`,
    writes: writesOf(win.cat),
    description: metaOf(win.cat).desc,
    hints: hintsFor(win.cat, verb ? VERB_TEMPLATES[verb]!.replace("{S}", subject) : undefined),
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
  const verb = tokens.find((t) => VERB_TEMPLATES[t] !== undefined);

  return {
    category: win.cat,
    categoryId: metaOf(win.cat).id,
    confidence: confidenceOf(win),
    summary: `${prefix}${cleaned}: ${subject} alanini isaret ediyor`,
    computes: computesParts.join("; "),
    writes: writesOf(win.cat),
    description: metaOf(win.cat).desc,
    hints: hintsFor(win.cat, verb ? VERB_TEMPLATES[verb]!.replace("{S}", subject) : isPointer ? "isaretci uzerinden bellek erisimi" : undefined),
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
    categoryId: metaOf(win.cat).id,
    confidence: confidenceOf(win),
    summary,
    computes,
    writes: writesOf(win.cat),
    description: metaOf(win.cat).desc,
    hints: hintsFor(win.cat, verb ? VERB_TEMPLATES[verb]!.replace("{S}", subject) : `${subject} ile ilgili islem yaptigi tahmin ediliyor`),
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
    categoryId: metaOf(win.cat).id,
    confidence: confidenceOf(win),
    summary: `${s.name} yapisi tarandi (${total} alan, ${matchedFields} eslesme): baskin kategori ${subject}${vftNote}`,
    computes: `eslesen alanlar/anahtar kelimeler: ${fieldWords.slice(0, 8).join(", ") || "yok"}`,
    writes: writesOf(win.cat),
    description: metaOf(win.cat).desc,
    hints: hintsFor(win.cat, `alanlar uzerinden ${subject} verisini yonetir`),
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
    categoryId: metaOf(win.cat).id,
    confidence: confidenceOf(win),
    summary: `"${shown}" dizesi ${subject} baglamina isaret ediyor`,
    computes: `Eslesen anahtar kelimeler: ${win.sc.words.join(", ")}`,
    writes: writesOf(win.cat),
    description: metaOf(win.cat).desc,
    hints: hintsFor(win.cat),
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
    categoryId: metaOf(win.cat).id,
    confidence: confidenceOf(win),
    summary: `${e.name}: ${subject} baglaminda kullanilan sabit degerleri tanimliyor (${e.members.length} uye)`,
    computes: `eslesen anahtar kelimeler: ${[...wordsOf(nm, 4), ...memberWords].slice(0, 8).join(", ") || "yok"}${membersShown ? ` | uyeler: ${membersShown}` : ""}`,
    writes: writesOf(win.cat),
    description: metaOf(win.cat).desc,
    hints: hintsFor(win.cat, `${subject} ile ilgili sabit deger kumesini tanimlar`),
    tags: tagsOf(merged, win.cat),
  };
}
