import { randomBytes, timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import { prisma } from "@/lib/db/client";
import { ensureWorkspaceForUser } from "@/lib/workspace";

const MARKER = "__openreply_bootstrap__";
const SESSION_DAYS = 30;

function matchesSecret(candidate: string, expected: string) {
  const left = Buffer.from(candidate);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

/**
 * Private, one-time bootstrap for self-hosted instances that have not yet
 * configured email delivery. It is inert unless both env vars are present.
 * The verification-token table is used as a durable one-use marker.
 */
async function bootstrap(request: Request) {
  const configuredToken = process.env.BOOTSTRAP_TOKEN;
  const email = process.env.BOOTSTRAP_EMAIL?.trim().toLowerCase();
  if (!configuredToken || !email) {
    return NextResponse.json({ error: "Bootstrap is not enabled" }, { status: 404 });
  }

  const url = new URL(request.url);
  const candidate = request.method === "POST"
    ? String((await request.formData()).get("token") ?? "")
    : url.searchParams.get("token") ?? "";

  if (!matchesSecret(candidate, configuredToken)) {
    return NextResponse.json({ error: "Invalid bootstrap token" }, { status: 404 });
  }

  const tokenHash = Buffer.from(configuredToken).toString("base64url");
  const existingMarker = await prisma.verificationToken.findUnique({
    where: { identifier_token: { identifier: MARKER, token: tokenHash } },
  });
  if (existingMarker) {
    return NextResponse.json({ error: "Bootstrap token already used" }, { status: 410 });
  }

  try {
    await prisma.verificationToken.create({
      data: {
        identifier: MARKER,
        token: tokenHash,
        expires: new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000),
      },
    });
  } catch {
    return NextResponse.json({ error: "Bootstrap token already used" }, { status: 410 });
  }

  const user = await prisma.user.upsert({
    where: { email },
    update: { emailVerified: new Date() },
    create: { email, emailVerified: new Date() },
  });
  await ensureWorkspaceForUser(user.id, user.email);

  const sessionToken = randomBytes(32).toString("hex");
  await prisma.session.create({
    data: {
      sessionToken,
      userId: user.id,
      expires: new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000),
    },
  });

  const secure = url.protocol === "https:" || request.headers.get("x-forwarded-proto") === "https";
  const response = NextResponse.redirect(new URL("/dashboard", url));
  response.cookies.set(secure ? "__Secure-authjs.session-token" : "authjs.session-token", sessionToken, {
    httpOnly: true,
    sameSite: "lax",
    secure,
    path: "/",
    maxAge: SESSION_DAYS * 24 * 60 * 60,
  });
  return response;
}

export async function GET(request: Request) {
  return bootstrap(request);
}

export async function POST(request: Request) {
  return bootstrap(request);
}
