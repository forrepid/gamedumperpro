"use client";

// ----------------------------------------------------------------------------
// Save Editor sekmesi: Unreal/Epic .sav (GVAS) ve Steam .vdf dosyalarini
// canli duzenleme (online editor-writer). Agac gorunumu, tip duyarli deger
// alanlari, sifreli dosyalar icin AES anahtar paneli, degisiklikleri
// .edited kopyaya yazma ve indirme.
// ----------------------------------------------------------------------------

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  Download,
  FileKey2,
  KeyRound,
  Loader2,
  RotateCcw,
  Save,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import type { SavePropNode } from "@/lib/analysis/savegame";
import type { VdfNode } from "@/lib/analysis/vdf";

interface SaveGameGetResponse {
  ok: boolean;
  type: "savegame" | "vdf";
  editedFile: boolean;
  header?: Record<string, unknown>;
  meta?: {
    kind?: string;
    keyCount?: number;
    maxDepth?: number;
    typeCounts?: Record<string, number>;
    encrypted?: boolean;
    compressed?: boolean;
    propCount?: number;
    [k: string]: unknown;
  };
  props?: SavePropNode[];
  root?: Record<string, VdfNode>;
  summary?: {
    className?: string;
    propCount?: number;
    engineVersion?: string;
    encrypted?: boolean;
    compressed?: boolean;
    kind?: string;
    keyCount?: number;
    maxDepth?: number;
    [k: string]: unknown;
  };
  error?: string;
  hint?: string;
  truncated?: boolean;
}

const EDITABLE_KINDS = new Set([
  "int", "int64", "int16", "int8", "uint32", "uint64", "uint16",
  "float", "double", "bool", "byte", "enum", "str", "name", "object",
]);

function typeLabel(nd: SavePropNode): string {
  return nd.type || nd.kind;
}

function isEditable(nd: SavePropNode): boolean {
  return EDITABLE_KINDS.has(nd.kind) && !nd.opaqueBytes;
}

// --- GVAS agac dugumu -------------------------------------------------------

function PropNodeRow({
  node,
  path,
  depth,
  edits,
  onEdit,
}: {
  node: SavePropNode;
  path: string;
  depth: number;
  edits: Record<string, string>;
  onEdit: (path: string, value: string, original: string) => void;
}) {
  const [open, setOpen] = useState(depth < 2);
  const hasKids =
    (node.children && node.children.length > 0) || (node.pairs && node.pairs.length > 0);
  const editable = isEditable(node);
  const current = edits[path] ?? String(node.value ?? "");
  const original = String(node.value ?? "");
  const changed = editable && current !== original;

  return (
    <div>
      <div
        className="flex items-center gap-1.5 rounded px-1 py-0.5 hover:bg-zinc-900/60"
        style={{ paddingLeft: depth * 14 }}
      >
        {hasKids ? (
          <button onClick={() => setOpen((o) => !o)} className="shrink-0 text-zinc-500 hover:text-emerald-400">
            {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          </button>
        ) : (
          <span className="h-3.5 w-3.5 shrink-0" />
        )}
        <span className="shrink-0 font-medium text-zinc-200">{node.name || "(isimsiz)"}</span>
        <Badge variant="outline" className="shrink-0 border-zinc-700 text-[9px] text-zinc-500">
          {typeLabel(node)}
        </Badge>
        {node.structType && (
          <span className="shrink-0 text-[9px] text-emerald-400/70">{node.structType}</span>
        )}
        {editable && node.kind === "bool" ? (
          <button
            onClick={() => onEdit(path, String(!(current === "true")), original)}
            className={`rounded border px-1.5 text-[10px] ${current === "true" ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-300" : "border-zinc-700 text-zinc-400"}`}
          >
            {current === "true" ? "true" : "false"}
          </button>
        ) : editable ? (
          <Input
            value={current}
            onChange={(e) => onEdit(path, e.target.value, original)}
            className={`h-6 flex-1 border text-[11px] ${changed ? "border-amber-500/60 text-amber-200" : "border-zinc-800 bg-zinc-950/80 text-zinc-300"}`}
          />
        ) : (
          <span className="flex-1 truncate text-[11px] text-zinc-500">
            {node.kind === "opaque" ? "(opak veri - byte-perfect korunur)" : ""}
          </span>
        )}
        {changed && <span className="shrink-0 text-[9px] text-amber-400">duzenlendi</span>}
      </div>
      {open && node.children && (
        <div>
          {node.children.map((c, i) => {
            const childPath = node.kind === "array" || node.kind === "set" ? `${path}[${i}]` : c.name ? `${path}.${c.name}` : `${path}#${i}`;
            return <PropNodeRow key={`${childPath}-${i}`} node={c} path={childPath} depth={depth + 1} edits={edits} onEdit={onEdit} />;
          })}
        </div>
      )}
      {open && node.pairs && (
        <div>
          {node.pairs.map((p, i) => (
            <div key={`pair-${i}`}>
              <div className="flex items-center gap-1 px-1 text-[10px] text-zinc-500" style={{ paddingLeft: (depth + 1) * 14 }}>
                anahtar: {p.key.name ? `${p.key.name}=` : ""}
                {String(p.key.value ?? "")}
              </div>
              <PropNodeRow
                node={p.value}
                path={`${path}[key=${String(p.key.value ?? i)}]`}
                depth={depth + 1}
                edits={edits}
                onEdit={onEdit}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// --- VDF agac dugumu --------------------------------------------------------

function VdfNodeRow({
  name,
  node,
  path,
  depth,
  edits,
  onEdit,
}: {
  name: string;
  node: VdfNode;
  path: string;
  depth: number;
  edits: Record<string, string>;
  onEdit: (path: string, value: string, original: string) => void;
}) {
  const [open, setOpen] = useState(depth < 2);
  const childKeys = node.c ? Object.keys(node.c) : [];
  const isBlock = childKeys.length > 0;
  const original = node.v;
  const current = edits[path] ?? original;
  const changed = !isBlock && current !== original;

  return (
    <div>
      <div className="flex items-center gap-1.5 rounded px-1 py-0.5 hover:bg-zinc-900/60" style={{ paddingLeft: depth * 14 }}>
        {isBlock ? (
          <button onClick={() => setOpen((o) => !o)} className="shrink-0 text-zinc-500 hover:text-emerald-400">
            {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          </button>
        ) : (
          <span className="h-3.5 w-3.5 shrink-0" />
        )}
        <span className="shrink-0 font-medium text-zinc-200">{name}</span>
        {isBlock ? (
          <Badge variant="outline" className="shrink-0 border-zinc-700 text-[9px] text-zinc-500">
            blok ({childKeys.length})
          </Badge>
        ) : (
          <Input
            value={current}
            onChange={(e) => onEdit(path, e.target.value, original)}
            className={`h-6 flex-1 border text-[11px] ${changed ? "border-amber-500/60 text-amber-200" : "border-zinc-800 bg-zinc-950/80 text-zinc-300"}`}
          />
        )}
        {changed && <span className="shrink-0 text-[9px] text-amber-400">duzenlendi</span>}
      </div>
      {open && isBlock && childKeys.map((k) => (
        <VdfNodeRow
          key={`${path}.${k}`}
          name={k}
          node={node.c![k]!}
          path={path ? `${path}.${k}` : k}
          depth={depth + 1}
          edits={edits}
          onEdit={onEdit}
        />
      ))}
    </div>
  );
}

// --- ana bileşen ------------------------------------------------------------

export default function SaveEditorTab({ uploadId, isVdf }: { uploadId: string; isVdf: boolean }) {
  const { toast } = useToast();
  const [doc, setDoc] = useState<SaveGameGetResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [keyHex, setKeyHex] = useState("");
  const [cipher, setCipher] = useState("aes-256-ecb");
  const [saving, setSaving] = useState(false);
  const [saveResult, setSaveResult] = useState<{ applied: number; errors: string[]; downloadUrl: string } | null>(null);

  const keyQuery = keyHex.trim() ? `&keyHex=${encodeURIComponent(keyHex.trim())}&cipher=${cipher}` : "";

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/uploads/${uploadId}/savegame?1=1${keyQuery}`, { cache: "no-store" });
      const d = (await res.json()) as SaveGameGetResponse;
      setDoc(d);
    } catch {
      setDoc({ ok: false, type: isVdf ? "vdf" : "savegame", editedFile: false, error: "Save agaci yuklenemedi (ag)" });
    } finally {
      setLoading(false);
    }
  }, [uploadId, keyHex, cipher, isVdf]);

  useEffect(() => {
    void load();
  }, [load]);

  const onEdit = useCallback((path: string, value: string, original: string) => {
    setEdits((prev) => {
      const next = { ...prev };
      if (value === original) delete next[path];
      else next[path] = value;
      return next;
    });
  }, []);

  const editList = useMemo(
    () => Object.entries(edits).map(([path, value]) => ({ path, value })),
    [edits],
  );

  const saveEdits = useCallback(async () => {
    if (editList.length === 0) return;
    setSaving(true);
    try {
      const res = await fetch(`/api/uploads/${uploadId}/savegame`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          edits: editList,
          ...(keyHex.trim() ? { keyHex: keyHex.trim(), cipher } : {}),
        }),
      });
      const d = (await res.json()) as {
        ok: boolean;
        applied?: number;
        errors?: string[];
        downloadUrl?: string;
        error?: string;
      };
      if (d.ok) {
        setSaveResult({ applied: d.applied ?? 0, errors: d.errors ?? [], downloadUrl: d.downloadUrl ?? `/api/uploads/${uploadId}/savegame/download` });
        toast({ title: `${d.applied ?? 0} degisiklik yazildi` });
        // duzenlenen kopyayi yeniden yukle (editedFile=true doner)
        setEdits({});
        void load();
      } else {
        toast({ title: "Kaydetme basarisiz", description: d.error ?? "", variant: "destructive" });
      }
    } catch {
      toast({ title: "Kaydetme hatasi (ag)", variant: "destructive" });
    } finally {
      setSaving(false);
    }
  }, [uploadId, editList, keyHex, cipher, toast, load]);

  const summary = doc?.summary ?? {};

  return (
    <div className="space-y-3">
      {/* baslik + durum */}
      <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-400">
        {isVdf ? (
          <Badge variant="outline" className="border-emerald-500/40 text-emerald-300">
            Steam VDF ({String(summary.kind ?? doc?.meta?.kind ?? "?")})
          </Badge>
        ) : (
          <Badge variant="outline" className="border-emerald-500/40 text-emerald-300">
            UE GVAS save
          </Badge>
        )}
        {doc?.editedFile && (
          <Badge variant="outline" className="border-amber-500/40 text-amber-300">
            duzenlenmis kopya gosteriliyor
          </Badge>
        )}
        {!isVdf && (
          <>
            <span>sinif: {String(summary.className ?? "-")}</span>
            <span>· {String(summary.propCount ?? 0)} property</span>
            <span>· motor: {String(summary.engineVersion ?? "-")}</span>
            {summary.encrypted ? <span className="text-rose-400">sifreli</span> : null}
            {summary.compressed ? <span className="text-sky-400">zlib</span> : null}
          </>
        )}
        {isVdf && (
          <>
            <span>{String(summary.keyCount ?? doc?.meta?.keyCount ?? 0)} anahtar</span>
            <span>· {String(summary.maxDepth ?? doc?.meta?.maxDepth ?? 0)} derinlik</span>
          </>
        )}
      </div>

      {/* sifreli dosya anahtar paneli */}
      {!isVdf && (doc?.ok === false || summary.encrypted) && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-500/5 p-3">
          <p className="flex items-center gap-1.5 text-xs text-rose-200">
            <KeyRound className="h-3.5 w-3.5" />
            {doc?.error ?? "Bu save dosyasi sifreli olabilir - oyunun AES anahtarini girin (32 bayt / 64 hex)"}
          </p>
          {doc?.hint && <p className="mt-1 text-[10px] text-zinc-500">{doc.hint}</p>}
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <Input
              value={keyHex}
              onChange={(e) => setKeyHex(e.target.value)}
              placeholder="AES-256 anahtari (64 hex karakter)"
              className="h-8 w-full max-w-[420px] border-zinc-700 bg-zinc-950/80 font-mono text-[11px]"
            />
            <Select value={cipher} onValueChange={setCipher}>
              <SelectTrigger className="h-8 w-[150px] border-zinc-700 bg-zinc-950/70 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="border-zinc-700 bg-zinc-950 text-xs">
                <SelectItem value="aes-256-ecb">AES-256-ECB</SelectItem>
                <SelectItem value="aes-256-cbc">AES-256-CBC</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" size="sm" className="h-8 border-zinc-700 text-[11px]" onClick={() => void load()}>
              <RotateCcw className="mr-1 h-3 w-3" />
              Anahtar ile Ac
            </Button>
            <span className="text-[10px] text-zinc-500">
              <FileKey2 className="mr-1 inline h-3 w-3" />
              anahtar sunucuya yalnizca bu istek icin gonderilir
            </span>
          </div>
        </div>
      )}

      {/* agac */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-950/60">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-800 px-3 py-2">
          <p className="text-xs text-zinc-300">
            {loading ? (
              <span className="flex items-center gap-2">
                <Loader2 className="h-3.5 w-3.5 animate-spin" /> Agac yukleniyor...
              </span>
            ) : doc?.ok ? (
              <>
                {editList.length > 0 ? (
                  <span className="text-amber-300">{editList.length} bekleyen degisiklik</span>
                ) : (
                  "Duzenlemek icin bir deger alani tiklayin"
                )}
              </>
            ) : (
              <span className="text-rose-300">{doc?.error ?? "Agac okunamadi"}</span>
            )}
          </p>
          <div className="flex items-center gap-1.5">
            <Button
              variant="outline"
              size="sm"
              className="h-7 border-emerald-500/40 px-2 text-[11px] text-emerald-300 hover:bg-emerald-500/10"
              onClick={saveEdits}
              disabled={saving || editList.length === 0}
            >
              {saving ? <Loader2 className="mr-1 h-3 w-3 animate-spin" /> : <Save className="mr-1 h-3 w-3" />}
              Kaydet ({editList.length})
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-7 border-zinc-700 px-2 text-[11px]"
              onClick={() => {
                const url = saveResult?.downloadUrl ?? `/api/uploads/${uploadId}/savegame/download`;
                window.open(url, "_blank");
              }}
            >
              <Download className="mr-1 h-3 w-3" />
              Indir
            </Button>
          </div>
        </div>
        <div className="max-h-[460px] overflow-auto p-2 scrollbar-thin">
          {doc?.truncated && (
            <p className="p-2 text-[11px] text-amber-400">Dosya cok buyuk (20 MB uzeri) - agac kisaltildi.</p>
          )}
          {!loading && doc?.ok && doc.type === "vdf" && doc.root && (
            <div>
              {Object.keys(doc.root).map((k) => (
                <VdfNodeRow
                  key={k}
                  name={k}
                  node={doc.root![k]!}
                  path={k}
                  depth={0}
                  edits={edits}
                  onEdit={onEdit}
                />
              ))}
            </div>
          )}
          {!loading && doc?.ok && doc.type === "savegame" && doc.props && (
            <div>
              {doc.props.map((p, i) => (
                <PropNodeRow key={`${p.name}-${i}`} node={p} path={p.name} depth={0} edits={edits} onEdit={onEdit} />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* kaydetme sonucu */}
      {saveResult && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3 text-[11px] text-emerald-200">
          <p>
            {saveResult.applied} degisiklik <span className="text-emerald-400">.edited kopyaya</span> yazildi
            {saveResult.errors.length > 0 ? ` · ${saveResult.errors.length} hata` : ""} - indirilen dosya{" "}
            <code className="rounded bg-zinc-900 px-1">*_edited.sav</code> / <code className="rounded bg-zinc-900 px-1">*_edited.vdf</code>
          </p>
          {saveResult.errors.map((e) => (
            <p key={e} className="text-amber-400">
              {e}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}
