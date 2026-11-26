// The Protection page's markup (feature-protection.js holds its state, the
// tested wording is protection-model.js). A template literal, registered in
// partials.js like every other section: no backtick and no dollar-brace
// inside, the Vue template needs neither.

export const PROTECTION_PARTIAL = `<template v-if="shouldShow('protection')">
<section class="card wide">
  <div class="pt-head">
    <div>
      <h2>Protection</h2>
      <p class="muted">What the edge stopped, and why. A reading of the node's own history: nothing here acts by itself.</p>
    </div>
    <div class="toolbar wrap">
      <label class="muted" for="pt-host">Vhost</label>
      <input id="pt-host" class="input input-wide pt-host" type="text" list="cfm-vhost-list" :placeholder="isScoped ? 'one of your vhosts' : 'all vhosts'" :value="ptHost" @change="ptSetFilter('host', $event.target.value)" />
      <datalist id="cfm-vhost-list"><option v-for="h in knownVhosts" :key="h" :value="h"></option></datalist>
      <label class="muted" for="pt-window">Window</label>
      <select id="pt-window" class="input" v-model.number="ptHours" @change="ptReload">
        <option v-for="w in ptWindows" :key="w.hours" :value="w.hours">{{ w.label }}</option>
      </select>
    </div>
  </div>
  <div class="vp-tabs" role="tablist" aria-label="Protection views">
    <button v-for="t in ptTabs" :key="t.key" type="button" role="tab" class="vp-tab" :class="{ on: ptTab === t.key }" :aria-selected="ptTab === t.key ? 'true' : 'false'" @click="ptSetTab(t.key)">{{ t.label }}</button>
  </div>
  <div class="chip-row" v-if="ptActiveFilters.length && ptTab !== 'events'">
    <span class="muted">Filtered by</span>
    <button v-for="f in ptActiveFilters" :key="f.key" type="button" class="chip on" :title="'Remove the ' + f.label + ' filter'" @click="ptClearFilter(f.key)">{{ f.label }}: {{ f.value }} ×</button>
  </div>
  <p v-if="actionMsg" class="statusline" role="status">{{ actionMsg }}</p>
</section>

<!-- WAF log -->
<template v-if="ptTab === 'waf'">
<section class="card wide">
  <div class="pt-head">
    <h2>WAF log</h2>
    <div class="chip-row" role="group" aria-label="Group the log by">
      <span class="muted">Group by</span>
      <button v-for="g in ptGroupings" :key="g.key" type="button" class="chip" :class="{ on: ptGroupBy === g.key }" :aria-pressed="ptGroupBy === g.key ? 'true' : 'false'" @click="ptSetGroup(g.key)">{{ g.label }}</button>
    </div>
  </div>
  <p class="danger-text" v-if="ptSummaryError">{{ ptSummaryError }}</p>
  <p class="muted" v-else-if="ptSummary">{{ ptGroupsNote }} Open a group for its requests.</p>
  <p class="muted" v-else>Loading the WAF log…</p>
  <div class="table-wrap" v-if="ptGroups.length">
    <table>
      <thead><tr><th>{{ ptGroupHead }}</th><th>Tier</th><th class="pt-r">Hits</th><th>Share</th><th>Last</th></tr></thead>
      <tbody>
        <template v-for="g in ptGroups" :key="g.key">
          <tr :class="{ 'pinned-row': ptOpenKey === g.key }">
            <td>
              <button type="button" class="pt-link" :aria-expanded="ptOpenKey === g.key ? 'true' : 'false'" @click="ptToggleGroup(g.key)"><span aria-hidden="true">{{ ptOpenKey === g.key ? '▾' : '▸' }}</span> <span class="mono">{{ g.key }}</span></button>
              <span v-if="ptGroupBy === 'rule' && g.ruleIDs.length" class="muted"> · rule{{ g.ruleIDs.length === 1 ? '' : 's' }} {{ g.ruleIDs.join(', ') }}</span>
              <button v-if="ptGroupBy === 'ip'" type="button" class="btn-quiet btn-sm" @click="ptOpenIP(g.key, $event.currentTarget)">Who is it</button>
              <div class="muted pt-sub" v-if="g.who">{{ g.who }}</div>
            </td>
            <td><span v-for="t in g.tiers" :key="t" class="pill" :class="ptTierTone(t)">{{ t }}</span><span v-if="!g.tiers.length" class="muted" title="No request of this group is among the most recent ones loaded">–</span></td>
            <td class="pt-r">{{ ptCount(g.count) }}</td>
            <td class="vp-minibar-cell"><div class="vp-minibar" :style="{ width: (g.width * 100) + '%' }"></div><span class="muted">{{ ptPct(g.share) }}</span></td>
            <td class="muted pt-nowrap">{{ g.last ? ptAge(g.last) : '–' }}</td>
          </tr>
          <tr v-if="ptOpenKey === g.key">
            <td colspan="5" class="pt-open">
              <p class="muted" v-if="!ptOpen">Loading its requests…</p>
              <p class="danger-text" v-else-if="ptOpen.error">Its requests could not be read: {{ ptOpen.error }}</p>
              <template v-else>
                <p class="muted" v-if="!ptOpenRows.length">No request of this group in the window any more: refresh the log.</p>
                <template v-else>
                <p class="muted"><span v-if="ptGroupBy === 'rule' && ptOpen.summary.total_events > g.count">Other families whose name holds this one are listed too. </span>{{ ptCount(ptOpen.summary.total_events) }} hits from {{ ptCount(ptOpen.summary.unique_ips) }} addresses on {{ ptCount(ptOpen.summary.unique_hosts) }} vhost{{ ptOpen.summary.unique_hosts === 1 ? '' : 's' }}, {{ ptCount(ptOpen.summary.blocked_events) }} blocked. The {{ ptOpenRows.length }} most recent:</p>
                <div class="table-wrap">
                  <table class="compact-table">
                    <thead><tr><th>Time</th><th>Address</th><th>Network</th><th>Vhost</th><th>Request</th><th>Rule</th><th>Tier</th><th></th></tr></thead>
                    <tbody>
                      <tr v-for="(r, i) in ptOpenRows" :key="i">
                        <td class="muted pt-nowrap" :title="ptTime(r.ts_unix)">{{ ptAge(r.ts_unix) }}</td>
                        <td><button type="button" class="pt-link mono" @click="ptOpenIP(r.ip, $event.currentTarget)">{{ r.ip }}</button></td>
                        <td class="muted pt-nowrap">{{ ptWho(r) }}</td>
                        <td><button type="button" class="pt-link" title="Filter the log by this vhost" @click="ptSetFilter('host', r.host)">{{ r.host }}</button></td>
                        <td class="mono pt-uri" :title="r.uri">{{ (r.method || '').toUpperCase() }} {{ r.uri }}</td>
                        <td class="mono">{{ r.rule }}<span v-if="r.waf_rule_id" class="muted"> ({{ r.waf_rule_id }})</span></td>
                        <td><span class="pill" :class="ptTierTone(ptTier(r))">{{ ptTier(r) }}</span></td>
                        <td class="pt-nowrap"><template v-if="ptExcludeOffer(r) && isScoped"><span class="muted pt-sub">Let through for</span> <button type="button" class="btn-quiet btn-sm" :title="'Let ' + ptPath(r.uri) + ' through rule ' + r.waf_rule_id + ' on ' + r.host + ' for 24 hours'" @click="ptExclude(r, '24h')">24 h</button> <button type="button" class="btn-quiet btn-sm" :title="'Let ' + ptPath(r.uri) + ' through rule ' + r.waf_rule_id + ' on ' + r.host + ' for 7 days'" @click="ptExclude(r, '7d')">7 d</button></template><button v-else-if="ptExcludeOffer(r)" type="button" class="btn-quiet btn-sm" :title="'Let ' + ptPath(r.uri) + ' through rule ' + r.waf_rule_id + ' on ' + r.host" @click="ptExclude(r)">Exclude this path</button><a v-else class="btn-quiet btn-sm pt-a" :href="ptExceptionsURL(r.host)" title="The WAF exceptions of this vhost">Exceptions</a></td>
                      </tr>
                    </tbody>
                  </table>
                </div>
                </template>
              </template>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>
</section>
</template>

<!-- Events -->
<template v-if="ptTab === 'events'">
<section class="card wide">
  <div class="pt-head">
    <h2>Events</h2>
    <div class="toolbar wrap">
      <label class="muted" for="pt-ev-ip">Address</label>
      <input id="pt-ev-ip" class="input" type="text" placeholder="any" v-model.trim="ptEventIP" @change="ptReload" />
    </div>
  </div>
  <div class="chip-row" role="group" aria-label="Kind of event">
    <button v-for="t in ptEventTypes" :key="t.key" type="button" class="chip" :class="{ on: ptEventType === t.key }" :aria-pressed="ptEventType === t.key ? 'true' : 'false'" @click="ptSetEventType(t.key)">{{ t.label }}</button>
    <label class="muted" title="Of the page shown, only the solves whose User-Agent contradicts itself"><input type="checkbox" v-model="ptOnlyImpossibleUA" /> impossible UA only</label>
  </div>
  <p class="danger-text" v-if="ptEventsError">{{ ptEventsError }}</p>
  <p class="muted" v-if="ptEventTotals.length">In this window: <span v-for="(t, i) in ptEventTotals" :key="t.label">{{ i ? ' · ' : '' }}{{ t.label }} <strong>{{ t.value }}</strong></span></p>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Time</th><th>Event</th><th>Vhost</th><th>Address</th><th>Network</th><th>What</th><th>Solve</th><th>Browser</th></tr></thead>
      <tbody>
        <tr v-for="ev in ptEventsShown" :key="ev.id">
          <td class="muted pt-nowrap" :title="ptTime(ev.ts_unix)">{{ ptAge(ev.ts_unix) }}</td>
          <td><span class="pill" :class="ptEventTone(ev.event_type)">{{ ptEventLabel(ev.event_type) }}</span></td>
          <td>{{ ev.host || '–' }}</td>
          <td><button v-if="ev.ip" type="button" class="pt-link mono" @click="ptOpenIP(ev.ip, $event.currentTarget)">{{ ev.ip }}</button><span v-else class="muted">–</span></td>
          <td class="muted pt-nowrap">{{ ptWho(ev) }}</td>
          <td class="mono pt-uri" :title="ptEventDetail(ev)">{{ ptEventDetail(ev) }}</td>
          <td class="pt-nowrap">{{ ptSolveTime(ev) || '–' }}</td>
          <td class="muted pt-uri pt-uri-narrow" :title="ptEventUA(ev)"><span class="pill danger" v-if="ptImpossibleUA(ev)" :title="ptImpossibleUA(ev)">impossible</span> {{ ptEventUA(ev) || '–' }}</td>
        </tr>
        <tr v-if="!ptEventsShown.length && !ptEventsError"><td colspan="8" class="muted">No event matches.</td></tr>
      </tbody>
    </table>
  </div>
  <div class="toolbar wrap pt-pager">
    <span class="muted">{{ ptEventsShown.length }} events, newest first{{ ptEventCursors.length ? ' · page ' + (ptEventCursors.length + 1) : '' }}</span>
    <span class="toolbar-gap"></span>
    <button type="button" class="btn-quiet" :disabled="!ptEventCursors.length" @click="ptEventsNewer">Newer</button>
    <button type="button" class="btn-quiet" :disabled="!ptEventNext" @click="ptEventsOlder">Older</button>
  </div>
</section>
</template>

<!-- Overview -->
<!-- Challenges -->
<template v-if="ptTab === 'challenges'">
<section class="card wide">
  <p class="danger-text" v-if="ptChError">{{ ptChError }}</p>
  <p class="muted" v-if="ptChWindow.capped">The edge keeps 24 hours: these are the last 24.</p>
  <div class="ch-tiles">
    <div class="summary-card" v-for="t in ptChTiles" :key="t.key"><h4>{{ t.label }}</h4><div class="vp-big">{{ t.value }}</div><div class="muted pt-sub">{{ t.sub }}</div></div>
  </div>
</section>
<section class="card wide">
  <div class="pt-head"><h2>What the edge did with the requests</h2><span class="muted">{{ ptChScopeLine }}</span></div>
  <p class="muted" v-if="!ptChBreak">No reply from the node yet.</p>
  <template v-else-if="ptChBreak.total > 0">
    <p class="muted">Every request of the visitors ends one of these ways (the check's own page and answers are not counted twice). Hover a part for its count.</p>
    <div class="ch-split" role="img" :aria-label="ptChSplitAria">
      <span v-for="p in ptChBreak.parts" v-show="p.value > 0" :key="p.key" :style="{ flexGrow: p.value, background: p.color }" :title="p.label + ': ' + ptChCount(p.value) + ' (' + p.pct + ')'"></span>
    </div>
    <div class="ch-legend">
      <span v-for="p in ptChBreak.parts" :key="p.key"><i class="ch-sw" :style="{ background: p.color }"></i>{{ p.label }} <span class="muted">{{ p.pct }} · {{ ptChCount(p.value) }}</span></span>
    </div>
    <h3 class="pt-h3">Sent to the check or stopped, per {{ ptChEdge.step_sec >= 3600 ? 'hour' : (ptChEdge.step_sec / 60) + ' minutes' }}</h3>
    <p class="muted pt-sub">The requests that reached the site are left out: they would flatten the rest.</p>
    <div class="ch-cols" role="img" :aria-label="'Requests sent to the check or stopped per step, highest ' + ptChCount(ptChStack.max)">
      <div class="ch-gl" style="bottom: 100%"><b>{{ ptChCount(ptChStack.max) }}</b></div>
      <div class="ch-gl" style="bottom: 50%"><b>{{ ptChCount(ptChStack.max / 2) }}</b></div>
      <div v-for="c in ptChStack.points" :key="c.t" class="ch-col" :title="c.tip">
        <span :style="{ height: (c.h.limited * 100) + '%', background: 'var(--ch-4)' }"></span>
        <span :style="{ height: (c.h.blocked * 100) + '%', background: 'var(--ch-3)' }"></span>
        <span :style="{ height: (c.h.sent * 100) + '%', background: 'var(--ch-2)' }"></span>
      </div>
    </div>
    <div class="ch-axis"><span v-for="(x, i) in ptChAxis" :key="i">{{ x }}</span></div>
    <div class="ch-legend">
      <span><i class="ch-sw" style="background: var(--ch-2)"></i>Sent to the check</span>
      <span><i class="ch-sw" style="background: var(--ch-3)"></i>Blocked (WAF, ban, policy)</span>
      <span><i class="ch-sw" style="background: var(--ch-4)"></i>Traffic rule or rate limit</span>
    </div>
  </template>
  <p class="muted" v-else>No request in this window.</p>
</section>
<div class="ch-pair" v-if="ptChFunnel">
<section class="card">
  <h2>Did they pass the check?</h2>
  <p class="muted">The share of the challenge pages served in each step that were passed. A low step is usually a script that never runs the page.</p>
  <div class="ch-cols ch-cols-short" role="img" aria-label="Share of challenge pages passed, per step">
    <div class="ch-gl" style="bottom: 100%"><b>100%</b></div>
    <div class="ch-gl" style="bottom: 50%"><b>50%</b></div>
    <div v-for="p in ptChPass" :key="p.t" class="ch-col" :title="p.tip"><span :style="{ height: (p.h * 100) + '%', background: 'var(--ch-1)' }"></span></div>
  </div>
  <div class="ch-axis"><span v-for="(x, i) in ptChAxis" :key="i">{{ x }}</span></div>
</section>
<section class="card">
  <h2>From page served to page passed</h2>
  <p class="muted" v-if="ptChFunnel.noPages">This node answered checks but counted no page: the page count starts with this version.</p>
  <p class="muted" v-else-if="!ptChFunnel.pages">No challenge page was served in this window.</p>
  <p class="muted" v-else>"Never answered" is a client that did not run the page: almost always a script. "Refused" includes the confirm step a person then clicks through.</p>
  <div class="ch-funnel">
    <template v-for="f in ptChFunnel.rows" :key="f.key">
      <span>{{ f.label }}</span>
      <div class="ch-fbar"><div :style="{ width: Math.max(f.value ? 0.6 : 0, f.share * 100) + '%', opacity: f.strong ? 1 : 0.55 }"></div></div>
      <span class="pt-r">{{ ptChCount(f.value) }} <span class="muted" v-if="f.key !== 'pages'">{{ ptChPct(f.value, ptChFunnel.pages, 0) }}</span></span>
    </template>
  </div>
</section>
</div>
<section class="card wide" v-if="!isScoped && !ptEffectiveHost">
  <div class="pt-head"><h2>Vhosts, most sent to the check first</h2><span class="muted">vhosts with 200 requests or more; click one for its own view</span></div>
  <p class="muted" v-if="!ptChHosts.length">No vhost with enough requests in this window.</p>
  <div class="table-wrap" v-else>
    <table>
      <thead><tr><th>Vhost</th><th class="pt-r">Requests</th><th class="pt-r">Sent to the check</th><th class="pt-r">Passed</th><th class="pt-r">Blocked</th><th>Split</th></tr></thead>
      <tbody>
        <tr v-for="h in ptChHosts" :key="h.host">
          <td><button type="button" class="pt-link" @click="ptChOpenHost(h.host)">{{ h.host }}</button></td>
          <td class="pt-r">{{ h.requests }}</td><td class="pt-r">{{ h.sent }}</td><td class="pt-r">{{ h.passed }}</td><td class="pt-r">{{ h.blocked }}</td>
          <td><div class="ch-mini"><span v-for="p in h.parts" v-show="p.value > 0" :key="p.key" :style="{ flexGrow: p.value, background: p.color }" :title="p.label + ' ' + p.pct"></span></div></td>
        </tr>
      </tbody>
    </table>
  </div>
</section>
<div class="ch-pair">
<section class="card" v-if="!isScoped">
  <h2>Addresses sent to the check, by reason</h2>
  <p class="muted">The per-address decisions of the window (a detector, a WAF rule at challenge level, odd paths). A vhost under challenge covers every visitor and is not listed here.</p>
  <p class="muted" v-if="!ptChReasons.length">None in this window.</p>
  <div class="table-wrap" v-else>
    <table>
      <thead><tr><th>Reason</th><th class="pt-r">Decisions</th><th class="pt-r">Addresses</th></tr></thead>
      <tbody><tr v-for="r in ptChReasons" :key="r.reason"><td><code>{{ r.reason }}</code> <span class="muted pt-sub">{{ r.kind }}</span></td><td class="pt-r">{{ r.decisions }}</td><td class="pt-r">{{ r.addresses }}</td></tr></tbody>
    </table>
  </div>
</section>
<section class="card">
  <h2>{{ isScoped ? 'WAF on your site: the rules that fired' : 'WAF rules by hits' }}</h2>
  <p class="muted">Hits against the requests the WAF inspected. A rule far above the rest on one site is usually that site's own traffic (a false positive), not an attack.</p>
  <p class="muted" v-if="!ptChWafSum">The WAF's counts could not be read.</p>
  <p class="muted" v-else-if="!ptChWafSum.rules.length">No WAF hit in this window.</p>
  <div class="table-wrap" v-else>
    <table>
      <thead><tr><th>Rule</th><th class="pt-r">Hits</th><th class="pt-r">Of inspected</th><th>Level</th></tr></thead>
      <tbody><tr v-for="r in ptChWafSum.rules" :key="r.id"><td><code>{{ r.id }}</code> <span class="muted pt-sub">{{ r.family }}</span></td><td class="pt-r">{{ ptChCount(r.hits) }}</td><td class="pt-r">{{ r.pct }}</td><td><span class="pill">{{ r.mode }}</span></td></tr></tbody>
    </table>
  </div>
</section>
</div>
</template>

<template v-if="ptTab === 'overview'">
<section class="card wide">
  <h2>WAF</h2>
  <p class="danger-text" v-if="ptSummaryError">{{ ptSummaryError }}</p>
  <div class="summary-grid">
    <div class="summary-card" v-for="t in ptTiles" :key="t.key"><h4>{{ t.title }}</h4><div class="vp-big">{{ t.value }}</div><div class="muted pt-sub">{{ t.sub }}</div></div>
  </div>
  <template v-if="ptHist.length > 1">
    <h3 class="pt-h3">Hits per hour</h3>
    <div class="pt-hist" role="img" :aria-label="'WAF hits per hour over the window, ' + ptHist.length + ' hours'">
      <div v-for="b in ptHist" :key="b.ts" class="pt-hist-col" :title="ptTime(b.ts) + ': ' + b.count + ' hits, ' + b.blocked + ' blocked'">
        <div class="pt-hist-bar" :style="{ height: (b.height * 100) + '%' }"><div class="pt-hist-blocked" :style="{ height: (b.blockedShare * 100) + '%' }"></div></div>
      </div>
    </div>
    <div class="vp-legend"><span><i class="pt-sw pt-sw-hit"></i>hits</span><span><i class="pt-sw pt-sw-blocked"></i>of them blocked</span></div>
  </template>
</section>
<section class="card wide" v-if="!isScoped">
  <h2>What the edge did with all traffic</h2>
  <p class="muted" v-if="!ptMixWindow">The edge outcomes are kept for 24 hours: pick a shorter window.</p>
  <p class="muted" v-else-if="!ptOutcome">This node reports no edge outcomes (an older build, or no traffic yet).</p>
  <template v-else>
    <p class="muted">{{ ptOutcomeLine }}. Per class, vhost and client: <a href="/cfm-admin/webdetector/traffic/">Web Traffic</a>.</p>
    <div v-for="s in ptOutcomeStops" :key="s.key" class="vp-bar-row pt-out-row">
      <span class="muted">{{ s.label }}</span>
      <div class="vp-minibar-cell"><div class="vp-minibar" :style="{ width: (s.width * 100) + '%', background: s.color }"></div><span class="muted">{{ ptCount(s.value) }}</span></div>
    </div>
  </template>
</section>
</template>

<!-- Tools (admin) -->
<template v-if="ptTab === 'tools' && !isScoped">
<section class="card wide">
  <h2>Analyze a client or a vhost</h2>
  <p class="muted">Reads the edge's own access log for one address or vhost (the offline analyze of <code>cfm webtop</code>).</p>
  <div class="toolbar wrap">
    <label class="muted" for="pt-an-target">Target</label>
    <input id="pt-an-target" class="input input-wide" type="text" v-model.trim="analyzeTarget" placeholder="address or vhost" />
    <label class="muted" for="pt-an-last">Last</label>
    <input id="pt-an-last" class="input" type="text" v-model.trim="analyzeLast" placeholder="30m, 1h" />
    <button type="button" class="btn-quiet" :disabled="analyzeLoading" @click="runAnalyze('ip')">Analyze address</button>
    <button type="button" class="btn-quiet" :disabled="analyzeLoading" @click="runAnalyze('host')">Analyze vhost</button>
  </div>
  <pre class="pt-pre" v-if="analyzeResult">{{ rawAnalyzePretty }}</pre>
</section>
<section class="card wide">
  <h2>History store</h2>
  <p class="muted" v-if="!ptStore">The store's size could not be read.</p>
  <template v-else>
    <p class="muted">{{ ptCount(ptStore.events) }} events from {{ ptCount(ptStore.unique_ips) }} addresses on {{ ptCount(ptStore.unique_hosts) }} vhosts, {{ ptBytes(ptStore.size_bytes) }}, kept {{ ptStore.retention_days }} days. <span class="mono">{{ ptStore.path }}</span></p>
  </template>
  <div class="toolbar wrap">
    <button type="button" class="btn-quiet" :disabled="ptStoreBusy" @click="ptPruneHistory(30)">Prune older than 30 days</button>
    <button type="button" class="btn-danger" :disabled="ptStoreBusy" @click="ptTruncateHistory">Delete all history</button>
  </div>
</section>
</template>

<!-- The address panel -->
<div class="pt-panel-backdrop" v-if="ptPanelIP" @click.self="ptCloseIP">
  <aside ref="ptPanelEl" class="pt-panel" role="dialog" aria-modal="true" aria-labelledby="pt-panel-title">
    <div class="pt-head">
      <div>
        <div class="muted pt-sub">Address</div>
        <h2 id="pt-panel-title" class="mono">{{ ptPanelIP }}</h2>
        <div class="muted" v-if="ptPanelWho">{{ ptPanelWho }}</div>
      </div>
      <button ref="ptPanelClose" type="button" class="btn-quiet" @click="ptCloseIP">Close</button>
    </div>
    <p class="muted" v-if="!ptPanel">Loading…</p>
    <template v-else>
      <template v-if="ptPanel.live">
        <h3 class="pt-h3">Right now</h3>
        <p class="muted" v-if="!ptPanel.live.req">No request from it in the live window.</p>
        <template v-else>
          <p>{{ ptCount(ptPanel.live.req) }} requests on {{ ptCount(ptPanel.live.vhosts) }} vhost{{ ptPanel.live.vhosts === 1 ? '' : 's' }} in the last {{ Math.round(ptPanel.live.window_sec || 0) }} s.</p>
          <div class="chip-row"><span v-for="h in ptPanelLiveHosts" :key="h.key" class="pill">{{ h.key }} {{ h.count }}</span></div>
        </template>
      </template>
      <h3 class="pt-h3">WAF, this window</h3>
      <p class="danger-text" v-if="!ptPanel.waf">Its WAF hits could not be read.</p>
      <template v-else>
        <p class="muted" v-if="!ptPanel.waf.total_events">No WAF hit from this address.</p>
        <template v-else>
          <p>{{ ptCount(ptPanel.waf.total_events) }} hits, {{ ptCount(ptPanel.waf.blocked_events) }} blocked, on {{ ptCount(ptPanel.waf.unique_hosts) }} vhost{{ ptPanel.waf.unique_hosts === 1 ? '' : 's' }}.</p>
          <div class="chip-row"><span class="muted">Rules</span><span v-for="r in ptPanelRules" :key="r.key" class="pill">{{ r.key }} {{ r.count }}</span></div>
          <div class="table-wrap">
            <table class="compact-table">
              <thead><tr><th>Time</th><th>Vhost</th><th>Request</th><th>Tier</th><th></th></tr></thead>
              <tbody>
                <tr v-for="(r, i) in ptPanelRows" :key="i">
                  <td class="muted pt-nowrap" :title="ptTime(r.ts_unix)">{{ ptAge(r.ts_unix) }}</td>
                  <td>{{ r.host }}</td>
                  <td class="mono pt-uri pt-uri-narrow" :title="r.rule + ' · ' + r.uri">{{ (r.method || '').toUpperCase() }} {{ r.uri }}</td>
                  <td><span class="pill" :class="ptTierTone(ptTier(r))">{{ ptTier(r) }}</span></td>
                  <td class="pt-nowrap"><template v-if="ptExcludeOffer(r) && isScoped"><span class="muted pt-sub">Let through for</span> <button type="button" class="btn-quiet btn-sm" @click="ptExclude(r, '24h')">24 h</button> <button type="button" class="btn-quiet btn-sm" @click="ptExclude(r, '7d')">7 d</button></template><button v-else-if="ptExcludeOffer(r)" type="button" class="btn-quiet btn-sm" @click="ptExclude(r)">Exclude this path</button></td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>
      </template>
      <h3 class="pt-h3">Events</h3>
      <p class="muted" v-if="ptPanel.events === null">{{ isScoped ? 'Pick one of your vhosts to list its events.' : 'Its events could not be read.' }}</p>
      <p class="muted" v-else-if="!ptPanel.events.length">No event from this address.</p>
      <div class="table-wrap" v-else>
        <table class="compact-table">
          <thead><tr><th>Time</th><th>Event</th><th>Vhost</th><th>What</th></tr></thead>
          <tbody>
            <tr v-for="ev in ptPanel.events" :key="ev.id">
              <td class="muted pt-nowrap" :title="ptTime(ev.ts_unix)">{{ ptAge(ev.ts_unix) }}</td>
              <td><span class="pill" :class="ptEventTone(ev.event_type)">{{ ptEventLabel(ev.event_type) }}</span></td>
              <td>{{ ev.host || '–' }}</td>
              <td class="mono pt-uri" :title="ptEventDetail(ev)">{{ ptEventDetail(ev) }}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="toolbar wrap pt-pager">
        <button type="button" class="btn-quiet" @click="ptShowEventsOf(ptPanelIP)">All its events</button>
        <button type="button" class="btn-quiet" @click="ptFilterWAFBy(ptPanelIP)">Filter the WAF log by it</button>
        <button v-if="!isScoped" type="button" class="btn-quiet" @click="ptAnalyzeIP(ptPanelIP)">Analyze it</button>
      </div>
    </template>
  </aside>
</div>
</template>`;
