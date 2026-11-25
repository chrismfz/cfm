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
                <p class="muted"><span v-if="ptGroupBy === 'rule' && ptOpen.summary.total_events !== g.count">Other families whose name holds this one are listed too. </span>{{ ptCount(ptOpen.summary.total_events) }} hits from {{ ptCount(ptOpen.summary.unique_ips) }} addresses on {{ ptCount(ptOpen.summary.unique_hosts) }} vhost{{ ptOpen.summary.unique_hosts === 1 ? '' : 's' }}, {{ ptCount(ptOpen.summary.blocked_events) }} blocked. The {{ ptOpen.summary.rows.length }} most recent:</p>
                <div class="table-wrap">
                  <table class="compact-table">
                    <thead><tr><th>Time</th><th>Address</th><th>Network</th><th>Vhost</th><th>Request</th><th>Rule</th><th>Tier</th><th></th></tr></thead>
                    <tbody>
                      <tr v-for="(r, i) in ptOpen.summary.rows" :key="i">
                        <td class="muted pt-nowrap" :title="ptTime(r.ts_unix)">{{ ptAge(r.ts_unix) }}</td>
                        <td><button type="button" class="pt-link mono" @click="ptOpenIP(r.ip, $event.currentTarget)">{{ r.ip }}</button></td>
                        <td class="muted pt-nowrap">{{ ptWho(r) }}</td>
                        <td><button type="button" class="pt-link" title="Filter the log by this vhost" @click="ptSetFilter('host', r.host)">{{ r.host }}</button></td>
                        <td class="mono pt-uri" :title="r.uri">{{ (r.method || '').toUpperCase() }} {{ r.uri }}</td>
                        <td class="mono">{{ r.rule }}<span v-if="r.waf_rule_id" class="muted"> ({{ r.waf_rule_id }})</span></td>
                        <td><span class="pill" :class="ptTierTone(ptTier(r))">{{ ptTier(r) }}</span></td>
                        <td class="pt-nowrap"><button v-if="ptExcludeOffer(r)" type="button" class="btn-quiet btn-sm" :title="'Let ' + ptPath(r.uri) + ' through rule ' + r.waf_rule_id + ' on ' + r.host" @click="ptExclude(r)">Exclude this path</button></td>
                      </tr>
                    </tbody>
                  </table>
                </div>
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
  </div>
  <p class="danger-text" v-if="ptEventsError">{{ ptEventsError }}</p>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Time</th><th>Event</th><th>Vhost</th><th>Address</th><th>Network</th><th>What</th></tr></thead>
      <tbody>
        <tr v-for="ev in ptEvents" :key="ev.id">
          <td class="muted pt-nowrap" :title="ptTime(ev.ts_unix)">{{ ptAge(ev.ts_unix) }}</td>
          <td><span class="pill" :class="ptEventTone(ev.event_type)">{{ ptEventLabel(ev.event_type) }}</span></td>
          <td>{{ ev.host || '–' }}</td>
          <td><button v-if="ev.ip" type="button" class="pt-link mono" @click="ptOpenIP(ev.ip, $event.currentTarget)">{{ ev.ip }}</button><span v-else class="muted">–</span></td>
          <td class="muted pt-nowrap">{{ ptWho(ev) }}</td>
          <td class="mono pt-uri" :title="ptEventDetail(ev)">{{ ptEventDetail(ev) }}</td>
        </tr>
        <tr v-if="!ptEvents.length && !ptEventsError"><td colspan="6" class="muted">No event matches.</td></tr>
      </tbody>
    </table>
  </div>
  <div class="toolbar wrap pt-pager">
    <span class="muted">{{ ptEvents.length }} events, newest first{{ ptEventCursors.length ? ' · page ' + (ptEventCursors.length + 1) : '' }}</span>
    <span class="toolbar-gap"></span>
    <button type="button" class="btn-quiet" :disabled="!ptEventCursors.length" @click="ptEventsNewer">Newer</button>
    <button type="button" class="btn-quiet" :disabled="!ptEventNext" @click="ptEventsOlder">Older</button>
  </div>
</section>
</template>

<!-- Overview -->
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
      <h3 class="pt-h3">WAF, this window</h3>
      <p class="danger-text" v-if="!ptPanel.waf">Its WAF hits could not be read.</p>
      <template v-else>
        <p class="muted" v-if="!ptPanel.waf.total_events">No WAF hit from this address.</p>
        <template v-else>
          <p>{{ ptCount(ptPanel.waf.total_events) }} hits, {{ ptCount(ptPanel.waf.blocked_events) }} blocked, on {{ ptCount(ptPanel.waf.unique_hosts) }} vhost{{ ptPanel.waf.unique_hosts === 1 ? '' : 's' }}.</p>
          <div class="chip-row"><span class="muted">Rules</span><span v-for="r in ptPanel.waf.top_rule_bases" :key="r.key" class="pill">{{ r.key }} {{ r.count }}</span></div>
          <div class="table-wrap">
            <table class="compact-table">
              <thead><tr><th>Time</th><th>Vhost</th><th>Request</th><th>Tier</th><th></th></tr></thead>
              <tbody>
                <tr v-for="(r, i) in ptPanel.waf.rows" :key="i">
                  <td class="muted pt-nowrap" :title="ptTime(r.ts_unix)">{{ ptAge(r.ts_unix) }}</td>
                  <td>{{ r.host }}</td>
                  <td class="mono pt-uri pt-uri-narrow" :title="r.rule + ' · ' + r.uri">{{ (r.method || '').toUpperCase() }} {{ r.uri }}</td>
                  <td><span class="pill" :class="ptTierTone(ptTier(r))">{{ ptTier(r) }}</span></td>
                  <td class="pt-nowrap"><button v-if="ptExcludeOffer(r)" type="button" class="btn-quiet btn-sm" @click="ptExclude(r)">Exclude this path</button></td>
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
        <button type="button" class="btn-quiet" @click="ptCloseIP(); ptSetFilter('ip', ptPanelIP)">Filter the WAF log by it</button>
        <a v-if="!isScoped" class="btn-quiet pt-a" :href="'/cfm-admin/webdetector/forensics/?ip=' + encodeURIComponent(ptPanelIP)">Live drilldown</a>
      </div>
    </template>
  </aside>
</div>
</template>`;
