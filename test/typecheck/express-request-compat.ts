/**
 * Compile-time regression guard for issue #626.
 *
 * 2.13.0 (commit 3d5788a) tightened `ESamlHttpRequest.query` / `.body`
 * from `any` to `Record<string, string | undefined>`. That type is NOT
 * structurally assignable from an Express `Request` — `req.query` is
 * `qs.ParsedQs`, whose values may be `string[]` or nested objects — so
 * every Express/Koa/Fastify caller passing `req` (or `req.query`) into
 * `parseLoginRequest` / `parseLoginResponse` / `parseLogoutRequest` /
 * `parseLogoutResponse` started failing to compile (TS2345 / TS2322).
 *
 * This file is type-checked (not run) via `tsconfig.typecheck.json`,
 * wired into `yarn test`. It has no runtime assertions on purpose: the
 * regression is purely at the type level, so a vitest runtime test
 * (types erased) cannot catch it.
 *
 * If `ESamlHttpRequest` ever regresses to a value type that rejects
 * `ParsedQs`, the positive assignments below stop compiling and this
 * guard fails. The `@ts-expect-error` block pins the exact #626 failure
 * mode and proves the Express mock genuinely reproduces it (if the mock
 * is weakened so it no longer reproduces, that line errors instead).
 */
import type { ESamlHttpRequest } from '../../src/types';

/**
 * Exact shape of Express's `req.query` (`qs.ParsedQs` from @types/qs,
 * as re-exported by @types/express-serve-static-core). Hand-rolled so
 * this guard needs no `@types/express` devDependency.
 */
interface ParsedQs {
  [key: string]: undefined | string | ParsedQs | (string | ParsedQs)[];
}

/** Minimal structural stand-in for an Express `Request`. */
interface ExpressLikeRequest {
  query: ParsedQs;
  // Express types `req.body` as `any` by default; model it faithfully.
  body: any;
}

declare const req: ExpressLikeRequest;

// --- positive: the supported caller patterns must all type-check ---

// raw Express request passed straight through (the common case)
const _whole: ESamlHttpRequest = req;

// destructured into the documented `{ query, body }` shape
const _split: ESamlHttpRequest = { query: req.query, body: req.body };

// redirect binding: query only
const _queryOnly: ESamlHttpRequest = { query: req.query };

// post / simpleSign binding: body only
const _bodyOnly: ESamlHttpRequest = { body: req.body };

// --- self-test: pin the exact pre-fix failure mode of #626 ---
// The 2.13.0 type genuinely rejected the Express query shape. If this
// stops erroring, the Express mock above no longer reproduces #626 and
// the positive assertions are no longer meaningful.
interface PreFixESamlHttpRequest {
  query?: Record<string, string | undefined>;
  body?: Record<string, string | undefined>;
  octetString?: string;
}
// @ts-expect-error -- ParsedQs is not assignable to Record<string, string | undefined>
const _regressed: PreFixESamlHttpRequest = { query: req.query };

// reference the bindings so unused-locals settings can't strip the file
export const __issue626Guard = [
  _whole,
  _split,
  _queryOnly,
  _bodyOnly,
  _regressed,
] as const;
