(() => {
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
    return res.json().catch(() => ({}));
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
    const payload = await requestJSON('/cfm-admin/mfa/totp/enroll/start', { body: {} });
    if (!payload || typeof payload.qr_svg !== 'string' || payload.qr_svg.trim() === '') {
      throw new Error('Enrollment start succeeded but QR payload was missing.');
    }
    return payload;
  }

  async function confirmTotpEnrollment({ code }) {
    const normalized = normalizeCode(code);
    if (normalized.length !== 6) throw new Error('Enter a valid 6-digit authenticator code.');
    return requestJSON('/cfm-admin/mfa/totp/enroll/confirm', { body: { code: normalized } });
  }

  async function regenerateRecoveryCodes({ password }) {
    const trimmed = String(password || '').trim();
    if (!trimmed) throw new Error('Re-authentication password is required to regenerate recovery codes.');
    return requestJSON('/cfm-admin/mfa/recovery/regenerate', { body: { password: trimmed } });
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
        totpQRSurface.innerHTML = result.qr_svg;
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
        const codes = Array.isArray(result?.recovery_codes) ? result.recovery_codes : [];
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
