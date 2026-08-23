import type { Request, Response } from "express";

const DEFAULT_LANDING = "/dashboard";

// Sends the user on after a successful sign-in, to wherever they were headed.
export function completeLogin(req: Request, res: Response) {
  const requested = String(req.query.next ?? "");
  const target =
    requested.startsWith("/") && !requested.startsWith("//")
      ? requested
      : DEFAULT_LANDING;
  res.redirect(target);
}
