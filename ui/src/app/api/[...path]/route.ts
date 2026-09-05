import { NextRequest, NextResponse } from "next/server";

const BACKEND_BASE = process.env.CUSTOS_BACKEND_URL || "http://localhost:8000";

async function proxy(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  const targetPath = `/api/${path.join("/")}`;
  const url = new URL(targetPath, BACKEND_BASE);
  url.search = request.nextUrl.search;

  try {
    const headers = new Headers(request.headers);
    headers.delete("host");

    let body: BodyInit | undefined = undefined;
    if (request.method !== "GET" && request.method !== "HEAD") {
      body = await request.text();
    }

    const backendRes = await fetch(url.toString(), {
      method: request.method,
      headers: headers,
      body: body,
    });

    const responseBody = await backendRes.text();
    return new NextResponse(responseBody, {
      status: backendRes.status,
      statusText: backendRes.statusText,
      headers: {
        "Content-Type": backendRes.headers.get("Content-Type") || "application/json",
      },
    });
  } catch (err: unknown) {
    return NextResponse.json(
      { error: "Backend proxy error", detail: err instanceof Error ? err.message : String(err) },
      { status: 502 }
    );
  }
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const DELETE = proxy;
