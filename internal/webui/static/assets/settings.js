(() => {
  const ROUTES = {
    totpEnrollStart: ['/cfm-admin/me/security/mfa/totp/enroll/start', '/cfm-admin/mfa/totp/enroll/start'],
    totpEnrollConfirm: ['/cfm-admin/me/security/mfa/totp/enroll/confirm', '/cfm-admin/mfa/totp/enroll/confirm'],
    recoveryRegenerate: ['/cfm-admin/me/security/recovery-codes/regenerate', '/cfm-admin/mfa/recovery/regenerate'],
  };

  function normalizeCode(raw) {
    return String(raw || '').replace(/\D+/g, '').slice(0, 6);
  }

  async function parseAPIError(res, fallback = 'Request failed') {
    if (!res) return fallback;
    try {
      const payload = await res.json();
      if (payload && typeof payload.error === 'string' && payload.error.trim()) return payload.error;
    } catch (_) {}
    return `${fallback} (HTTP ${res.status})`;
  }

  async function requestJSON(path, { method = 'POST', body } = {}) {
    const res = await fetch(path, {
      method,
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: body == null ? undefined : JSON.stringify(body),
    });
    if (!res.ok) {
      const error = await parseAPIError(res, 'Security request failed');
      throw new Error(error);
    }
    try {
      return await res.json();
    } catch (_) {
      const rawText = typeof res.text === 'function' ? await res.text().catch(() => '') : '';
      const snippet = String(rawText || '').trim().slice(0, 200);
      throw new Error(
        `Security endpoint returned non-JSON payload (HTTP ${res.status}, path=${path}${snippet ? `, body=${snippet}` : ''}).`
      );
    }
  }

  async function requestJSONWithFallback(paths, options = {}) {
    let lastErr;
    for (const path of paths) {
      try {
        const payload = await requestJSON(path, options);
        return { payload, endpoint: path };
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr || new Error('Security request failed');
  }

  async function updatePassword({ currentPassword, newPassword }) {
    if (!String(currentPassword || '').trim() || !String(newPassword || '').trim()) {
      throw new Error('Current and new password are required.');
    }
    if (String(newPassword).length < 12) {
      throw new Error('New password must be at least 12 characters.');
    }
    try {
      await requestJSON('/cfm-admin/me/password', {
        body: { current_password: currentPassword, new_password: newPassword },
      });
      return { endpoint: '/cfm-admin/me/password' };
    } catch (_) {
      await requestJSON('/cfm-admin/api/v1/me/password', {
        body: { current_password: currentPassword, new_password: newPassword },
      });
      return { endpoint: '/cfm-admin/api/v1/me/password' };
    }
  }

  async function startTotpEnrollment() {
    const { payload, endpoint } = await requestJSONWithFallback(ROUTES.totpEnrollStart, { body: {} });
    const nested = payload && typeof payload.data === 'object' ? payload.data : {};

    const readFirstNonEmpty = (...values) => {
      for (const value of values) {
        if (typeof value === 'string' && value.trim()) return value.trim();
      }
      return '';
    };

    const otpauthURI = readFirstNonEmpty(payload?.otpauth_uri, payload?.otpauth_url, nested?.otpauth_uri, nested?.otpauth_url);
    const qrPayload = readFirstNonEmpty(payload?.qr_svg, payload?.qr, payload?.qr_data_url, nested?.qr_svg, nested?.qr, nested?.qr_data_url);

    if (!otpauthURI && !qrPayload) {
      const payloadKeys = Object.keys(payload || {});
      const nestedDataKeys = Object.keys(nested || {});
      console.warn('[TOTP enroll/start] Enrollment payload missing expected fields', { endpoint, payloadKeys, nestedDataKeys });
      throw new Error(
        `Enrollment start succeeded, but enrollment payload missing expected fields (Enrollment payload missing expected fields; endpoint=${endpoint}; keys=${payloadKeys.join(',') || 'none'}; nested=${nestedDataKeys.join(',') || 'none'}).`
      );
    }

    return {
      ...(payload || {}),
      otpauth_uri: otpauthURI || payload?.otpauth_uri || '',
      qr_svg: qrPayload || payload?.qr_svg || '',
      qr: qrPayload || payload?.qr || '',
    };
  }

  async function confirmTotpEnrollment({ code }) {
    const normalized = normalizeCode(code);
    if (normalized.length !== 6) throw new Error('Enter a valid 6-digit authenticator code.');
    const { payload } = await requestJSONWithFallback(ROUTES.totpEnrollConfirm, { body: { code: normalized } });
    return payload;
  }

  async function regenerateRecoveryCodes({ password }) {
    const trimmed = String(password || '').trim();
    if (!trimmed) throw new Error('Re-authentication password is required to regenerate recovery codes.');
    const { payload } = await requestJSONWithFallback(ROUTES.recoveryRegenerate, { body: { password: trimmed } });
    return payload;
  }

  function getRecoveryCodes(payload) {
    if (Array.isArray(payload?.codes)) return payload.codes;
    if (Array.isArray(payload?.recovery_codes)) return payload.recovery_codes;
    return [];
  }

  function mountSettingsPage() {
    const status = document.getElementById('settingsStatus');
    const totpQRSurface = document.getElementById('totpQRSurface');
    const recoveryCodesEl = document.getElementById('recoveryCodes');

    const showStatus = (msg, ok = true) => {
      if (!status) return;
      status.textContent = msg;
      status.style.color = ok ? '#4ade80' : '#f87171';
    };

    document.getElementById('changePasswordBtn')?.addEventListener('click', async () => {
      const currentPassword = document.getElementById('currentPassword')?.value || '';
      const newPassword = document.getElementById('newPassword')?.value || '';
      try {
        const result = await updatePassword({ currentPassword, newPassword });
        showStatus(`Password updated successfully via ${result.endpoint}.`);
      } catch (err) {
        showStatus(err.message || 'Failed to change password.', false);
      }
    });

    document.getElementById('startTotpBtn')?.addEventListener('click', async () => {
      try {
        const result = await startTotpEnrollment();
        const qrSVG = typeof result?.qr_svg === 'string' ? result.qr_svg.trim() : '';
        const otpauthURI = typeof result?.otpauth_uri === 'string' ? result.otpauth_uri.trim() : '';

        if (qrSVG.startsWith('<svg')) {
          totpQRSurface.innerHTML = qrSVG;
        } else if (qrSVG.startsWith('data:image/')) {
          totpQRSurface.innerHTML = `<img alt="TOTP enrollment QR code" src="${qrSVG}" />`;
        } else if (qrSVG) {
          const escapedQR = qrSVG
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
          totpQRSurface.innerHTML = `
            <p style="margin-bottom:0.5rem;">Scan is unavailable. Use this QR payload manually:</p>
            <pre style="white-space:pre-wrap;word-break:break-all;">${escapedQR}</pre>
          `;
        } else if (otpauthURI) {
          const escapedURI = otpauthURI
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
          totpQRSurface.innerHTML = `
            <p style="margin-bottom:0.5rem;">Scan is unavailable. Use this enrollment URI manually:</p>
            <pre style="white-space:pre-wrap;word-break:break-all;">${escapedURI}</pre>
          `;
        }

        showStatus('TOTP enrollment started. Scan the QR and confirm with your 6-digit code.');
      } catch (err) {
        showStatus(err.message || 'Failed to start TOTP enrollment.', false);
      }
    });

    document.getElementById('confirmTotpBtn')?.addEventListener('click', async () => {
      const code = document.getElementById('totpCode')?.value || '';
      try {
        await confirmTotpEnrollment({ code });
        showStatus('TOTP enrollment confirmed.');
      } catch (err) {
        showStatus(err.message || 'Failed to confirm TOTP enrollment.', false);
      }
    });

    document.getElementById('regenRecoveryBtn')?.addEventListener('click', async () => {
      const password = document.getElementById('reauthPassword')?.value || '';
      try {
        const result = await regenerateRecoveryCodes({ password });
        const codes = getRecoveryCodes(result);
        recoveryCodesEl.textContent = codes.length ? codes.join('\n') : 'No recovery codes returned.';
        showStatus('Recovery codes regenerated. Copy or download them now.');
      } catch (err) {
        showStatus(err.message || 'Failed to regenerate recovery codes.', false);
      }
    });
  }

  const api = {
    normalizeCode,
    updatePassword,
    startTotpEnrollment,
    confirmTotpEnrollment,
    regenerateRecoveryCodes,
    getRecoveryCodes,
    mountSettingsPage,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }

  if (typeof window !== 'undefined') {
    window.CFMSettings = api;
    if (typeof document !== 'undefined') {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', mountSettingsPage);
      } else {
        mountSettingsPage();
      }
    }
  }
})();
