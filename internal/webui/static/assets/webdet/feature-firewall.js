// Firewall actions: single-IP block with TTL picker, and the bulk IP
// selection + batch block shared by the Global Top IPs and drilldown tables.

export const firewallMixin = {
  data() {
    return {
      // TTL applied by every Block button on the page. '' = permanent
      // (the block API skips the nft timeout when ttl is empty, same as
      // `cfm block <ip>`); guarded by a confirm() in blockIP().
      blockTTL: "1h",
      blockTTLChoices: [
        { value: "1h", label: "1h" },
        { value: "6h", label: "6h" },
        { value: "24h", label: "24h" },
        { value: "168h", label: "7d" }, // Go ParseDuration has no 'd' unit
        { value: "", label: "permanent" },
      ],
      // Bulk IP selection (ip -> true). Selection deliberately survives
      // auto-refresh and list rotation, so IPs picked during a bot storm
      // stay picked even when they drop out of the visible top-N.
      selectedIPs: {},
      bulkBusy: false,
      bulkProgress: "",
    };
  },

  computed: {
    blockTTLLabel() {
      const c = this.blockTTLChoices.find((x) => x.value === this.blockTTL);
      return c ? c.label : this.blockTTL;
    },
    selectedIPList() { return Object.keys(this.selectedIPs); },
    selectedIPCount() { return this.selectedIPList.length; },
  },

  methods: {
    async blockIP(ip) {
      if (!ip) return;
      const ttl = this.blockTTL;
      if (ttl === "" && !window.confirm(
        `PERMANENTLY block ${ip}?\n\nA permanent block never expires (it survives restarts). `
        + `Remove it later from the Firewall dashboard or with: cfm unblock ${ip}`,
      )) {
        return;
      }
      try {
        await this.postJSON("v1/firewall/block", {
          ip,
          ttl,
          reason: `cfm-admin-ui host=${this.activeHost || "-"}`,
        });
        this.actionMsg = ttl
          ? `Blocked IP ${ip} for ${this.blockTTLLabel}`
          : `Blocked IP ${ip} permanently`;
      } catch (err) {
        this.actionMsg = `IP block failed for ${ip}: ${err}`;
        console.error("[cfm-admin] block action failed", err);
      }
    },

    isIPSelected(ip) { return Boolean(this.selectedIPs[ip]); },
    toggleIPSelected(ip) {
      if (!ip) return;
      if (this.selectedIPs[ip]) delete this.selectedIPs[ip];
      else this.selectedIPs[ip] = true;
    },
    clearIPSelection() { this.selectedIPs = {}; },
    ipsFromRows(rows, key) {
      return (Array.isArray(rows) ? rows : []).map((r) => r && r[key]).filter(Boolean);
    },
    allRowsSelected(rows, key) {
      const ips = this.ipsFromRows(rows, key);
      return ips.length > 0 && ips.every((ip) => this.isIPSelected(ip));
    },
    toggleSelectAllRows(rows, key) {
      const ips = this.ipsFromRows(rows, key);
      if (ips.length && ips.every((ip) => this.isIPSelected(ip))) {
        for (const ip of ips) delete this.selectedIPs[ip];
      } else {
        for (const ip of ips) this.selectedIPs[ip] = true;
      }
    },
    // Quick-select every listed row sharing an enrichment value (CC, ASN,
    // company) — "these 20 bots are all the same datacenter" in one click.
    selectRowsMatching(rows, key, field, value) {
      if (!value || value === "-") return;
      let n = 0;
      for (const r of (Array.isArray(rows) ? rows : [])) {
        if (r && r[field] === value && r[key] && !this.selectedIPs[r[key]]) {
          this.selectedIPs[r[key]] = true;
          n++;
        }
      }
      this.actionMsg = n
        ? `Selected ${n} more IPs matching ${value} (${this.selectedIPCount} total)`
        : `No new IPs matching ${value}`;
    },
    async bulkBlockSelected() {
      if (this.bulkBusy) return;
      const ips = [...this.selectedIPList];
      if (!ips.length) return;
      const ttl = this.blockTTL;
      const confirmMsg = ttl
        ? `Block ${ips.length} selected IP(s) for ${this.blockTTLLabel}?`
        : `PERMANENTLY block ${ips.length} selected IP(s)?\n\nPermanent blocks never expire (they survive restarts). `
          + "Remove them later from the Firewall dashboard or with: cfm unblock <ip>";
      if (!window.confirm(confirmMsg)) return;
      this.bulkBusy = true;
      const blocked = [];
      const skipped = [];
      const failed = [];
      const errors = [];
      let kept = 0;
      try {
        // One request per 256-IP chunk (the server-side cap). The batch
        // endpoint guards against self-lockout: the server's own IPs and
        // the calling admin's IP come back as skipped, never blocked.
        const CHUNK = 256;
        for (let i = 0; i < ips.length; i += CHUNK) {
          const chunk = ips.slice(i, i + CHUNK);
          this.bulkProgress = `Blocking ${Math.min(i + chunk.length, ips.length)}/${ips.length}…`;
          const res = await this.postJSON("v1/firewall/block/batch", {
            ips: chunk,
            ttl,
            reason: `cfm-admin-ui-bulk host=${this.activeHost || "-"}`,
          });
          blocked.push(...(Array.isArray(res?.blocked) ? res.blocked : []));
          skipped.push(...(Array.isArray(res?.skipped) ? res.skipped : []));
          failed.push(...(Array.isArray(res?.failed) ? res.failed : []));
          // The batch only adds or extends: an IP already blocked at least as
          // long (or permanently) keeps its block and is counted as kept.
          kept += Number(res?.kept) || 0;
          if (res?.error) errors.push(String(res.error));
        }
      } catch (err) {
        this.bulkBusy = false;
        this.bulkProgress = "";
        this.actionMsg = `Bulk block request failed: ${err} — selection kept, retry`;
        console.error("[cfm-admin] bulk block failed", err);
        return;
      }
      this.bulkBusy = false;
      this.bulkProgress = "";
      // Unselect what was blocked and what can never succeed (self/caller/
      // invalid/duplicate); transient failures stay selected for retry.
      for (const ip of blocked) delete this.selectedIPs[ip];
      for (const s of skipped) { if (s && s.ip) delete this.selectedIPs[s.ip]; }
      const ttlText = ttl ? `for ${this.blockTTLLabel}` : "permanently";
      const parts = [`Bulk block: ${blocked.length} blocked ${ttlText}`];
      if (kept) {
        parts.push(`${kept} of them already blocked at least as long (kept as is)`);
      }
      if (skipped.length) {
        parts.push(`${skipped.length} skipped (${skipped.map((s) => `${s.ip}: ${s.reason}`).join(", ")})`);
      }
      if (failed.length) {
        const why = errors.length ? `: ${[...new Set(errors)].join("; ")}` : "";
        parts.push(`${failed.length} FAILED (${failed.map((f) => f.ip).join(", ")})${why} — kept selected, retry`);
      }
      this.actionMsg = parts.join(" · ");
    },
  },
};
