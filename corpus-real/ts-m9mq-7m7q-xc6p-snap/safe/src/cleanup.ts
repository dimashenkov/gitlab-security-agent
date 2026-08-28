import type { Page } from 'playwright';

export interface CleanupOptions {
  ads?: boolean;
  cookies?: boolean;
  sticky?: boolean;
  social?: boolean;
  all?: boolean;
}

const CLEANUP_FN = `(flags) => {
  const { ads, cookies, sticky, social } = flags;
  let removed = 0;

  const remove = (el) => {
    try { el.remove(); removed++; } catch {}
  };

  if (ads) {
    const adSelectors = [
      '[class*="ad-" i]','[class*="-ad" i]','[id*="ad-" i]','[id*="-ad" i]',
      '[class*="advert" i]','[id*="advert" i]',
      '[class*="banner" i]','[class*="sponsor" i]','[id*="sponsor" i]',
      'ins.adsbygoogle','iframe[src*="doubleclick"]','iframe[src*="googlesyndication"]',
      'iframe[src*="googletag"]','iframe[id*="google_ads"]',
      '[data-ad]','[data-ad-slot]','[aria-label*="advertisement" i]',
    ];
    document.querySelectorAll(adSelectors.join(',')).forEach(remove);
  }

  if (cookies) {
    const cookieSelectors = [
      '[class*="cookie" i][class*="banner" i]','[class*="cookie" i][class*="consent" i]',
      '[class*="cookie" i][class*="notice" i]','[id*="cookie" i][id*="banner" i]',
      '[id*="cookie-consent" i]','[id*="cookie-banner" i]','[id*="cookie-notice" i]',
      '#CybotCookiebotDialog','#onetrust-banner-sdk','#onetrust-consent-sdk',
      '[aria-label*="cookie" i]','[data-testid*="cookie" i]',
      '[class*="gdpr" i]','[id*="gdpr" i]',
    ];
    document.querySelectorAll(cookieSelectors.join(',')).forEach(remove);
  }

  if (sticky) {
    const all = document.querySelectorAll('*');
    for (const el of all) {
      const s = getComputedStyle(el);
      if (s.position === 'sticky' || s.position === 'fixed') {
        const r = el.getBoundingClientRect();
        // Only kill elements that span a significant area (not small floating buttons)
        if (r.width > window.innerWidth * 0.5 || r.height > 80) {
          remove(el);
        }
      }
    }
  }

  if (social) {
    const socialSelectors = [
      '[class*="share" i][class*="bar" i]','[class*="social" i][class*="bar" i]',
      '[class*="share-buttons" i]','[class*="social-buttons" i]',
      '[aria-label*="share" i]','[class*="newsletter" i][class*="popup" i]',
      '[class*="subscribe" i][class*="popup" i]','[class*="modal" i][class*="subscribe" i]',
    ];
    document.querySelectorAll(socialSelectors.join(',')).forEach(remove);
  }

  return removed;
}`;

export async function cleanup(page: Page, opts: CleanupOptions): Promise<number> {
  const flags = {
    ads: !!(opts.ads || opts.all),
    cookies: !!(opts.cookies || opts.all),
    sticky: !!(opts.sticky || opts.all),
    social: !!(opts.social || opts.all),
  };
  const removed = await page.evaluate(`(${CLEANUP_FN})(${JSON.stringify(flags)})`);
  return removed as number;
}
