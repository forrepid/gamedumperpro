import { NextRequest, NextResponse } from "next/server";
import { readProjectFile } from "@/lib/project-files";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const rel = req.nextUrl.searchParams.get("path") ?? "";
  if (!rel) {
    return NextResponse.json({ error: "path parametresi gerekli" }, { status: 400 });
  }
  const content = readProjectFile(rel);
  if (content === null) {
    return NextResponse.json({ error: "dosya bulunamadi" }, { status: 404 });
  }
  return NextResponse.json({ path: rel, content });
}
