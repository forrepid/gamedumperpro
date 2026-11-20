import { NextResponse } from "next/server";
import { getProjectFiles } from "@/lib/project-files";

export const dynamic = "force-dynamic";

export async function GET() {
  const files = getProjectFiles();
  const totalLines = files.reduce((acc, f) => acc + f.lines, 0);
  const totalSize = files.reduce((acc, f) => acc + f.size, 0);
  return NextResponse.json({ files, totalLines, totalSize });
}
