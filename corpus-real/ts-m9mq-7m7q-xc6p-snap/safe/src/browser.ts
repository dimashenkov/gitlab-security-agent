import {
  chromium,
  BrowserContext,
  Browser,
  Page,
  ConsoleMessage,
  Request,
  Response,
  CDPSession,
} from 'playwright';
import { mkdirSync, existsSync, writeFileSync, rmSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { logIssue } from './issues.js';
import { parseProxyEnv, parseFenceEnv, checkUrlAllowed } from './fence.js';



export const EPHEMERAL = (() => {
  const v = (process.env.BROWSE_MCP_EPHEMERAL ?? '').toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
})();

export interface ConsoleEntry {
  type: string;
  text: string;
  location?: string;
  ts: number;
  tabIndex?: number;
}

export interface NetworkEntry {
  method: string;
  url: string;
  status?: number;
  ok?: boolean;
  ts: number;
  tabIndex?: number;
}

export interface DialogArm {
  action: 'accept' | 'dismiss';
  promptText?: string;
  remaining: number;
}

export interface DialogRecord {
  type: string;
  message: string;
  handledWith: 'accept' | 'dismiss';
  promptText?: string;
  ts: number;
  tabIndex?: number;
}





export function resolveDialogAction(
  arm: DialogArm | null,
  dialogType: string,
): { handledWith: 'accept' | 'dismiss'; promptText?: string; armed: boolean } {
  if (arm && arm.remaining > 0) {
    return { handledWith: arm.action, promptText: arm.promptText, armed: true };
  }
  if (dialogType === 'beforeunload') return { handledWith: 'accept', armed: false };
  return { handledWith: 'dismiss', armed: false };
}

const PROXY = parseProxyEnv();
const FENCE = parseFenceEnv();
const FENCE_ACTIVE = FENCE.allowed.length > 0 || FENCE.blocked.length > 0;


export function navigationBlockReason(url: string): string | null {
  if (!FENCE_ACTIVE) return null;
  const v = checkUrlAllowed(url, FENCE);
  return v.allowed ? null : (v.reason ?? 'blocked by origin fence');
}

export const HOME_DIR = process.env.BROWSE_MCP_HOME || join(homedir(), '.browse-mcp');

export const DEFAULT_DATA_DIR = join(HOME_DIR, 'chromium-profile');




const CDP_PORT = (() => {
  const v = (process.env.BROWSE_MCP_CDP ?? '').trim().toLowerCase();
  if (!v) return 0;
  if (v === '1' || v === 'true' || v === 'yes') return 9223;
  const n = parseInt(v, 10);
  return Number.isInteger(n) && n > 0 && n < 65536 ? n : 0;
})();
export const CDP_FILE = join(HOME_DIR, 'cdp.json');



const NO_STEALTH = (() => {
  const v = (process.env.BROWSE_MCP_NO_STEALTH ?? '').toLowerCase();
  return v === '1' || v === 'true' || v === 'yes';
})();

class BrowserManager {
  private context: BrowserContext | null = null;
  private browser: Browser | null = null;
  private page: Page | null = null;
  private mode: 'headless' | 'headed' = 'headless';
  private dataDir: string = DEFAULT_DATA_DIR;
  private ephemeral: boolean = EPHEMERAL;
  private cdp: CDPSession | null = null;
  private loggerAttached: WeakSet<Page> = new WeakSet();
  private consoleLogs: WeakMap<Page, ConsoleEntry[]> = new WeakMap();
  private networkLogs: WeakMap<Page, NetworkEntry[]> = new WeakMap();
  lastSnapshot: string = '';
  handoffReason: string | null = null;
  private dialogArm: DialogArm | null = null;
  dialogLog: DialogRecord[] = [];
  private extraContexts: Map<string, BrowserContext> = new Map();
  private activeContextName = 'default';
  private isolatedBrowser: Browser | null = null;
  private wroteCdpFile = false;

  armDialog(action: 'accept' | 'dismiss', promptText?: string, count = 1): void {
    this.dialogArm = { action, promptText, remaining: Math.max(1, count) };
  }

  getDialogArm(): DialogArm | null {
    return this.dialogArm;
  }

  get consoleLog(): ConsoleEntry[] {
    if (!this.page) return [];
    return this.consoleLogs.get(this.page) ?? [];
  }

  get networkLog(): NetworkEntry[] {
    if (!this.page) return [];
    return this.networkLogs.get(this.page) ?? [];
  }

  getAllConsoleLogs(): ConsoleEntry[] {
    const out: ConsoleEntry[] = [];
    for (const p of this.getAllPages()) {
      const arr = this.consoleLogs.get(p);
      if (arr) out.push(...arr);
    }
    return out;
  }

  getAllNetworkLogs(): NetworkEntry[] {
    const out: NetworkEntry[] = [];
    for (const p of this.getAllPages()) {
      const arr = this.networkLogs.get(p);
      if (arr) out.push(...arr);
    }
    return out;
  }

  getDataDir(): string {
    return this.dataDir;
  }
  isEphemeral(): boolean {
    return this.ephemeral;
  }

  private tabIndexOf(page: Page): number {
    return page.context().pages().indexOf(page);
  }

  private buildContextOpts() {
    return {
      viewport: { width: 1280, height: 720 },
      userAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
      locale: 'en-US',
      timezoneId: 'America/Chicago',
      extraHTTPHeaders: {
        'Accept-Language': 'en-US,en;q=0.9',
        Accept:
          'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      },
      ...(PROXY ? { proxy: PROXY } : {}),
    };
  }


  private async applyContextPolicies(ctx: BrowserContext): Promise<void> {

    if (!NO_STEALTH) {
      await ctx.addInitScript(() => {
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
      });
    }



    if (FENCE_ACTIVE) {
      await ctx.route('**/*', (route) => {
        const req = route.request();
        if (req.isNavigationRequest() && req.resourceType() === 'document') {
          const v = checkUrlAllowed(req.url(), FENCE);
          if (!v.allowed) {
            void logIssue({
              kind: 'difficulty',
              tool: 'origin-fence',
              note: `blocked navigation: ${v.reason}`,
              url: req.url(),
            });


            return route.fulfill({
              status: 403,
              contentType: 'text/html',
              body: `<html><head><title>Blocked by origin fence</title></head><body><h1>Blocked by origin fence</h1><p>${v.reason}. This browse-mcp server restricts navigation via BROWSE_MCP_ALLOWED_ORIGINS / BROWSE_MCP_BLOCKED_ORIGINS. Do not retry this URL.</p></body></html>`,
            });
          }
        }
        return route.continue();
      });
    }
  }

  private async ensureDefaultContext(): Promise<BrowserContext> {
    if (this.context) return this.context;
    const contextOpts = this.buildContextOpts();
    const launchArgs = CDP_PORT ? { args: [`--remote-debugging-port=${CDP_PORT}`] } : {};
    if (this.ephemeral) {
      this.browser = await chromium.launch({ headless: this.mode === 'headless', ...launchArgs });
      this.context = await this.browser.newContext(contextOpts);
    } else {
      if (!existsSync(this.dataDir)) mkdirSync(this.dataDir, { recursive: true });
      this.context = await chromium.launchPersistentContext(this.dataDir, {
        headless: this.mode === 'headless',
        ...launchArgs,
        ...contextOpts,
      });
    }
    await this.applyContextPolicies(this.context);
    if (CDP_PORT) {
      try {
        if (!existsSync(HOME_DIR)) mkdirSync(HOME_DIR, { recursive: true });
        writeFileSync(CDP_FILE, JSON.stringify({ port: CDP_PORT, pid: process.pid }), {
          mode: 0o600,
        });
        this.wroteCdpFile = true;
      } catch {

      }
    }
    return this.context;
  }

  private async ensureActiveContext(): Promise<BrowserContext> {
    const def = await this.ensureDefaultContext();
    if (this.activeContextName === 'default') return def;
    const ctx = this.extraContexts.get(this.activeContextName);
    if (ctx) return ctx;

    this.activeContextName = 'default';
    return def;
  }

  async getPage(): Promise<Page> {
    const ctx = await this.ensureActiveContext();
    if (this.page && !this.page.isClosed() && this.page.context() === ctx) return this.page;
    const existing = ctx.pages();
    this.page = existing.length ? existing[0] : await ctx.newPage();
    this.attachLoggers(this.page);
    return this.page;
  }

  async openIsolatedContext(name: string): Promise<void> {
    if (name === 'default' || this.extraContexts.has(name)) {
      throw new Error(`Context ${JSON.stringify(name)} already exists`);
    }
    await this.ensureDefaultContext();


    const b =
      this.browser ??
      this.context!.browser() ??
      (this.isolatedBrowser ??= await chromium.launch({ headless: this.mode === 'headless' }));
    const ctx = await b.newContext(this.buildContextOpts());
    await this.applyContextPolicies(ctx);
    this.extraContexts.set(name, ctx);
    this.switchContext(name);
  }

  switchContext(name: string): void {
    if (name !== 'default' && !this.extraContexts.has(name)) {
      throw new Error(`No context named ${JSON.stringify(name)}`);
    }
    this.activeContextName = name;
    this.page = null;
    this.cdp = null;
  }

  async closeContext(name: string): Promise<void> {
    if (name === 'default') {
      throw new Error('The default context cannot be closed this way — use browser_close');
    }
    const ctx = this.extraContexts.get(name);
    if (!ctx) throw new Error(`No context named ${JSON.stringify(name)}`);
    await ctx.close().catch(() => {});
    this.extraContexts.delete(name);
    if (this.activeContextName === name) {
      this.activeContextName = 'default';
      this.page = null;
      this.cdp = null;
    }
  }

  listContexts(): Array<{ name: string; active: boolean; tabs: number; type: string }> {
    const out = [
      {
        name: 'default',
        active: this.activeContextName === 'default',
        tabs: this.context ? this.context.pages().length : 0,
        type: this.ephemeral ? 'ephemeral' : 'persistent profile',
      },
    ];
    for (const [name, ctx] of this.extraContexts) {
      out.push({
        name,
        active: this.activeContextName === name,
        tabs: ctx.pages().length,
        type: 'isolated (in-memory)',
      });
    }
    return out;
  }

  getActiveContextName(): string {
    return this.activeContextName;
  }

  async getCdp(): Promise<CDPSession> {
    const page = await this.getPage();
    if (this.cdp) return this.cdp;
    this.cdp = await page.context().newCDPSession(page);
    return this.cdp;
  }

  async switchMode(mode: 'headless' | 'headed', url?: string, reason?: string): Promise<void> {
    const currentUrl =
      url ?? (this.page && !this.page.isClosed() ? this.page.url() : 'about:blank');
    await this.closeInternal();
    this.mode = mode;
    if (mode === 'headed') this.handoffReason = reason ?? null;
    else this.handoffReason = null;
    const page = await this.getPage();
    if (currentUrl && currentUrl !== 'about:blank') {
      await page.goto(currentUrl, { waitUntil: 'domcontentloaded' }).catch(() => {});
    }
  }

  private attachLoggers(page: Page) {
    if (this.loggerAttached.has(page)) return;
    this.loggerAttached.add(page);
    if (!this.consoleLogs.has(page)) this.consoleLogs.set(page, []);
    if (!this.networkLogs.has(page)) this.networkLogs.set(page, []);
    const cLog = this.consoleLogs.get(page)!;
    const nLog = this.networkLogs.get(page)!;
    page.on('console', (msg: ConsoleMessage) => {
      cLog.push({
        type: msg.type(),
        text: msg.text(),
        location: msg.location()?.url,
        ts: Date.now(),
        tabIndex: this.tabIndexOf(page),
      });
      if (cLog.length > 500) cLog.shift();
    });
    page.on('pageerror', (err) => {
      cLog.push({
        type: 'error',
        text: err.message,
        ts: Date.now(),
        tabIndex: this.tabIndexOf(page),
      });
    });
    page.on('request', (req: Request) => {
      nLog.push({
        method: req.method(),
        url: req.url(),
        ts: Date.now(),
        tabIndex: this.tabIndexOf(page),
      });
      if (nLog.length > 500) nLog.shift();
    });
    page.on('response', (res: Response) => {
      const entry = nLog.find((e) => e.url === res.url() && e.status === undefined);
      if (entry) {
        entry.status = res.status();
        entry.ok = res.ok();
      }
    });
    page.on('dialog', async (dialog) => {
      const resolved = resolveDialogAction(this.dialogArm, dialog.type());
      if (resolved.armed && this.dialogArm) {
        this.dialogArm.remaining -= 1;
        if (this.dialogArm.remaining <= 0) this.dialogArm = null;
      }
      try {
        if (resolved.handledWith === 'accept') await dialog.accept(resolved.promptText);
        else await dialog.dismiss();
      } catch {

      }
      this.dialogLog.push({
        type: dialog.type(),
        message: dialog.message(),
        handledWith: resolved.handledWith,
        promptText: resolved.promptText,
        ts: Date.now(),
        tabIndex: this.tabIndexOf(page),
      });
      if (this.dialogLog.length > 50) this.dialogLog.shift();
      if (!resolved.armed && dialog.type() !== 'beforeunload') {


        void logIssue({
          kind: 'difficulty',
          tool: 'browser_handle_dialog',
          note: `auto-dismissed ${dialog.type()}: ${dialog.message().slice(0, 200)}`,
          url: page.url(),
        }).catch(() => {});
      }
    });
  }

  getAllPages(): Page[] {
    if (this.activeContextName !== 'default') {
      return this.extraContexts.get(this.activeContextName)?.pages() ?? [];
    }
    return this.context ? this.context.pages() : [];
  }

  setActivePage(page: Page): void {
    this.page = page;
    this.attachLoggers(page);
  }

  clearConsole() {
    if (this.page) this.consoleLogs.set(this.page, []);
  }
  clearNetwork() {
    if (this.page) this.networkLogs.set(this.page, []);
  }

  private async closeInternal() {
    this.cdp = null;
    if (this.wroteCdpFile) {
      try {
        rmSync(CDP_FILE, { force: true });
      } catch {

      }
      this.wroteCdpFile = false;
    }
    for (const ctx of this.extraContexts.values()) {
      await ctx.close().catch(() => {});
    }
    this.extraContexts.clear();
    this.activeContextName = 'default';
    if (this.isolatedBrowser) {
      await this.isolatedBrowser.close().catch(() => {});
      this.isolatedBrowser = null;
    }
    if (this.context) {
      await this.context.close().catch(() => {});
      this.context = null;
      this.page = null;
    }
    if (this.browser) {
      await this.browser.close().catch(() => {});
      this.browser = null;
    }
  }

  async close() {
    await this.closeInternal();
  }

  getMode(): 'headless' | 'headed' {
    return this.mode;
  }
  isHandoff(): boolean {
    return this.mode === 'headed' && this.handoffReason !== null;
  }
  getHandoffReason(): string | null {
    return this.handoffReason;
  }
}

export const browser = new BrowserManager();
