import type { Request } from "express";

export function isSignedIn(req: Request): boolean {
  return Boolean(req.session?.userId);
}
