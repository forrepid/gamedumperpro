import fs from "fs";
import path from "path";

export interface ProjectFile {
  path: string; // relative to ue-dumper root, e.g. "src/main.cpp"
  name: string;
  dir: string;
  size: number;
  lines: number;
  lang: "cpp" | "c" | "ini" | "md" | "txt";
}

export const PROJECT_ROOT = path.join(process.cwd(), "DumperPro");

function langOf(name: string): ProjectFile["lang"] {
  const ext = path.extname(name).toLowerCase();
  if (ext === ".h" || ext === ".hpp" || ext === ".cpp") return "cpp";
  if (ext === ".c") return "c";
  if (ext === ".ini") return "ini";
  if (ext === ".md") return "md";
  return "txt";
}

export function getProjectFiles(): ProjectFile[] {
  const out: ProjectFile[] = [];
  const walk = (rel: string) => {
    const abs = path.join(PROJECT_ROOT, rel);
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(abs, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const child = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        walk(child);
      } else {
        try {
          const st = fs.statSync(path.join(PROJECT_ROOT, child));
          const content = fs.readFileSync(path.join(PROJECT_ROOT, child), "utf8");
          out.push({
            path: child,
            name: e.name,
            dir: path.dirname(child) === "." ? "" : path.dirname(child),
            size: st.size,
            lines: content.split("\n").length,
            lang: langOf(e.name),
          });
        } catch {
          // ignore unreadable entries
        }
      }
    }
  };
  walk("");
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

export function readProjectFile(rel: string): string | null {
  const abs = path.resolve(PROJECT_ROOT, rel);
  if (!abs.startsWith(path.resolve(PROJECT_ROOT) + path.sep)) return null;
  try {
    return fs.readFileSync(abs, "utf8");
  } catch {
    return null;
  }
}

export function readProjectFileBuffer(rel: string): Buffer | null {
  const abs = path.resolve(PROJECT_ROOT, rel);
  if (!abs.startsWith(path.resolve(PROJECT_ROOT) + path.sep)) return null;
  try {
    return fs.readFileSync(abs);
  } catch {
    return null;
  }
}
