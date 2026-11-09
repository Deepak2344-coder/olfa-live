/**
 * Ad and Pop-up Blocker module for Olfa Master Extension.
 * Identifies pop-up ad patterns, shady redirectors, and clickjacking overlay elements.
 */

export const POPUP_AD_PATTERNS = [
  /popads\.net/i,
  /propellerads\.com/i,
  /adcash\.com/i,
  /clickadu\.com/i,
  /trafficjunky\.com/i,
  /exoclick\.com/i,
  /juicyads\.com/i,
  /ad-maven\.com/i,
  /yllix\.com/i,
  /bet365-affiliates/i,
  /cleaner-update-alert/i,
  /urgent-system-alert/i,
  /claim-your-reward/i,
  /spin-the-wheel-prize/i,
];

export const TRACKING_PARAM_REGEX = /^(utm_|gclid|fbclid|msclkid|aff_|ref_id|click_id)/i;

/**
 * Checks if a URL or hostname belongs to a known pop-up / ad network.
 * @param {string} url
 * @returns {boolean}
 */
export function isPopupAdUrl(url) {
  if (!url || typeof url !== 'string') return false;
  for (const pattern of POPUP_AD_PATTERNS) {
    if (pattern.test(url)) return true;
  }
  return false;
}

/**
 * Checks if a tab creation is an unsolicited popup window that should be blocked.
 * @param {object} tabInfo - Information about the newly created tab.
 * @param {boolean} openedByPage - Whether it was created programmatically by a page script.
 * @param {boolean} userActive - Whether there was active user navigation.
 * @returns {boolean}
 */
export function shouldAutoClosePopup(tabInfo, openedByPage, userActive) {
  if (!openedByPage) return false;
  if (userActive) return false;
  if (!tabInfo || !tabInfo.url) return false;
  return isPopupAdUrl(tabInfo.url);
}

/**
 * Detects whether an element in the DOM is an ad-clickjacking or deceptive pop-up overlay.
 * @param {object} elProps - DOM element properties { width, height, zIndex, opacity, position }
 * @param {object} viewport - { width, height }
 * @returns {boolean}
 */
export function isClickjackOverlay(elProps, viewport = { width: 1024, height: 768 }) {
  if (!elProps) return false;
  const isFixed = elProps.position === 'fixed' || elProps.position === 'absolute';
  const coversViewport =
    elProps.width >= viewport.width * 0.8 &&
    elProps.height >= viewport.height * 0.8;
  const isTransparent = Number(elProps.opacity) <= 0.1;
  const isHighZ = Number(elProps.zIndex) >= 999;

  return isFixed && coversViewport && (isTransparent || isHighZ);
}

