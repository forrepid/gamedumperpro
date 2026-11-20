// ----------------------------------------------------------------------------
// DumperPro Online - motor & guvenlik imzi taramasi
//
// Kaynak/teyit:
//  - UE surum stringleri: UnrealBuildTool build.version uretimi ("++UE4+Release-4.27.2-CL-0")
//  - Unity marker: libil2cpp.so + assets/bin/Data/Managed/global-metadata.dat
//  - UE Android: libUE4.so / libUE5.so / *.pak (assets)
//  - Anti-cheat isimleri: EasyAntiCheat(Epic), BattlEye(BEService), XIGNCODE(Wellbia),
//    nProtect GameGuard, FACEIT, Vanguard(Riot vgk), Denuvo(DRM), VMProtect/Themida(packer)
// ----------------------------------------------------------------------------

import { countNeedle, findUeVersionStrings } from "./util";
import type { EngineInfo, SecurityInfo, InterestingString } from "./types";

interface MarkerDef {
  name: string;
  needles: string[];
}

const MARKERS: MarkerDef[] = [
  { name: "Unreal Engine (genel)", needles: ["UnrealEngine", "Unreal Engine", "Engine\\Content", "FNamePool", "GUObjectArray"] },
  { name: "UE4 ipucu", needles: ["UE4Editor", "libUE4.so", "UE4Game", "++UE4+"] },
  { name: "UE5 ipucu", needles: ["UE5Editor", "libUE5.so", "UE5Game", "++UE5+", "UnrealEngine5"] },
  { name: "Unity (il2cpp)", needles: ["global-metadata.dat", "il2cpp", "libil2cpp.so"] },
  { name: "Unity (mono/player)", needles: ["UnityPlayer", "libunity.so", "UnityDataAssetInfo", "unity3d"] },
  { name: "Godot", needles: ["GodotEngine", "godot.engine", "libgodot"] },
  { name: "Source Engine", needles: ["Valve", "SourceEngine", "vphysics.dll", "source2"] },
  { name: "CryEngine", needles: ["CryEngine", "CrySystem.dll"] },
  { name: "Frostbite", needles: ["FrostbiteEngine", "frostbite"] },
  { name: "RED Engine", needles: ["redengine", "RED4ext", "cdprojekt"] },
  { name: "id Tech", needles: ["idTech", "DOOM Engine", "idlib"] },
];

const ANTI_CHEAT: MarkerDef[] = [
  { name: "EasyAntiCheat (Epic)", needles: ["EasyAntiCheat", "easyanticheat.sys", "EasyAntiCheat_EOS"] },
  { name: "EAC EOS", needles: ["EasyAntiCheat_EOS", "eac_plugin"] },
  { name: "BattlEye", needles: ["BattlEye", "BEService", "bedaisy.sys"] },
  { name: "Riot Vanguard", needles: ["vgk.sys", "vgtray", "Vanguard"] },
  { name: "XIGNCODE3 (Wellbia)", needles: ["XIGNCODE", "x6.tcd", "xhunter1.sys"] },
  { name: "nProtect GameGuard", needles: ["GameGuard", "nprotect", "npGameLib"] },
  { name: "FACEIT AC", needles: ["faceitclient", "FACEIT_AC", "faceit"] },
  { name: "ESEA", needles: ["eseaclient"] },
  { name: "TenProtect (Tencent)", needles: ["TenProtect", "TPHelper"] },
  { name: "Tencent ACE", needles: ["AntiCheatExpert", "ACE-BASE.sys", "SGuard64"] },
  { name: "mhyprot (HoYoverse)", needles: ["mhyprot", "HoYoKProtect"] },
];

const DRM: MarkerDef[] = [
  { name: "Denuvo", needles: ["Denuvo", "denuvoservices"] },
  { name: "Steam API", needles: ["steam_api64.dll", "steam_appid", "Steamworks"] },
  { name: "Epic Online Services", needles: ["EOSSDK-Win64", "epicgames"] },
  { name: "Windows Store/UWP", needles: ["MicrosoftStore", "AppXManifest"] },
  { name: "VMProtect", needles: ["VMProtect", ".vmp0", ".vmp1"] },
  { name: "Themida", needles: ["Themida", "winlice"] },
  { name: "UPX", needles: ["UPX0", "UPX!"] },
  { name: "Enigma Protector", needles: ["Enigma Protector", "EnigmaVB"] },
];

const ANTI_CHEAT_LOOSE = ["anticheat", "anti-cheat"];
const CRYPTO_LOOSE = ["openssl", "mbedtls", "libsodium", "bearssl", "wolfssl"];

function countMarkers(buf: Buffer, defs: MarkerDef[]): { name: string; hits: number }[] {
  const out: { name: string; hits: number }[] = [];
  for (const def of defs) {
    let hits = 0;
    for (const n of def.needles) {
      hits += countNeedle(buf, Buffer.from(n, "latin1"));
    }
    if (hits > 0) out.push({ name: def.name, hits });
  }
  return out.sort((a, b) => b.hits - a.hits);
}

function collectLoose(strings: string[], words: string[], cap = 6): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  for (const s of strings) {
    const low = s.toLowerCase();
    for (const w of words) {
      if (low.includes(w) && !seen.has(w)) {
        seen.add(w);
        found.push(s.slice(0, 160));
        if (found.length >= cap) return found;
      }
    }
  }
  return found;
}

export interface EngineScan {
  engine: EngineInfo;
  security: SecurityInfo;
}

export function scanEngineAndSecurity(
  buf: Buffer,
  asciiStrings: string[],
): EngineScan {
  const markers = countMarkers(buf, MARKERS);
  const ueVersions = findUeVersionStrings(buf, 24);
  const versionStrings = ueVersions.map((v) => v.raw);

  // motor karari
  let detected = "Bilinmiyor";
  let confidence = "dusuk";
  const mk = (n: string) => markers.find((m) => m.name === n)?.hits ?? 0;

  const ueVersionMarkers = mk("UE4 ipucu") + mk("UE5 ipucu") + mk("Unreal Engine (genel)");
  if (ueVersions.length > 0) {
    const ue5 = ueVersions.find((v) => v.engine === "UE5");
    const ue4 = ueVersions.find((v) => v.engine === "UE4");
    detected = ue5 ? "UE5" : ue4 ? "UE4" : ueVersions[0].engine;
    confidence = ueVersions.length > 1 || ueVersionMarkers > 0 ? "yuksek" : "orta";
  } else if (ueVersionMarkers >= 2) {
    detected = "Unreal Engine (surum stringi yok)";
    confidence = "orta";
  }

  if (detected === "Bilinmiyor") {
    if (mk("Unity (il2cpp)") > 0 || mk("Unity (mono/player)") > 0) {
      detected = "Unity";
      confidence = mk("Unity (il2cpp)") > 0 ? "yuksek" : "orta";
    } else if (mk("Godot") > 0) {
      detected = "Godot"; confidence = "yuksek";
    } else if (mk("Source Engine") > 0) {
      detected = "Source Engine"; confidence = "orta";
    } else if (mk("CryEngine") > 0) {
      detected = "CryEngine"; confidence = "orta";
    } else if (mk("Frostbite") > 0) {
      detected = "Frostbite"; confidence = "orta";
    } else if (mk("RED Engine") > 0) {
      detected = "RED Engine"; confidence = "orta";
    } else if (mk("id Tech") > 0) {
      detected = "id Tech"; confidence = "orta";
    }
  }

  // surum: motor tespitinden bagimsiz olarak ilk UE eslesmesi
  let version: string | undefined;
  if (detected === "UE4" || detected === "UE5") {
    const match = ueVersions.find((v) => v.engine === detected);
    version = match?.version;
  }

  // guvenlik
  const antiCheatMarkers = countMarkers(buf, ANTI_CHEAT);
  const drmMarkers = countMarkers(buf, DRM);
  const antiCheat = antiCheatMarkers.map((m) => `${m.name} (${m.hits})`);
  const drm = drmMarkers.map((m) => `${m.name} (${m.hits})`);
  const acLoose = collectLoose(asciiStrings, ANTI_CHEAT_LOOSE);
  const cryptoLoose = collectLoose(asciiStrings, CRYPTO_LOOSE, 4);

  return {
    engine: {
      detected,
      version,
      versionStrings,
      markers,
      confidence,
    },
    security: {
      antiCheat,
      drm,
      packer: drm.filter((d) => d.startsWith("VMProtect") || d.startsWith("Themida") || d.startsWith("UPX") || d.startsWith("Enigma")),
      packedHint: false, // PE yolunda entropy ile guncellenir
      notableStrings: [...acLoose, ...cryptoLoose],
    },
  };
}

/** Ilginci dizeleri sec (motor, yollar, ag protokolleri, oyun anahtar kelimeleri). */
export function pickInterestingStrings(strings: string[], cap = 250): InterestingString[] {
  const keywords = [
    "ue4", "ue5", "unreal", "engine", "shader", "pak", "manifest", "dumper",
    "gobjects", "gnames", "fname", "uobject", "sdk", "cheat", "anticheat",
    "steam", "epic", "eos", "xbox", "psn", "battleye", "easyanticheat",
    "denuvo", "vmp", "themida", "http", "ws://", "wss://", "api", "server",
    "player", "world", "game", "kernel", "driver", "inject", "hook",
    "il2cpp", "metadata", "unity", "mono", "glacier", "pakchunk",
  ];
  const seen = new Set<string>();
  const out: InterestingString[] = [];
  for (const s of strings) {
    if (s.length < 8 || s.length > 200) continue;
    const low = s.toLowerCase();
    if (!keywords.some((k) => low.includes(k))) continue;
    if (seen.has(low.slice(0, 60))) continue;
    seen.add(low.slice(0, 60));
    out.push({ value: s, kind: "ascii" });
    if (out.length >= cap) break;
  }
  return out;
}
