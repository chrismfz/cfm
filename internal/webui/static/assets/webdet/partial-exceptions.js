// The Exceptions page's markup (feature-exceptions.js; the lists and their
// add / remove actions are feature-excludes.js, the Trusted clients tab is
// the Challenge access editor). A template literal: no backtick and no
// dollar-brace inside.

import { CHALLENGE_ACCESS_PARTIAL } from "./partial-challenge-access.js";

export const EXCEPTIONS_PARTIAL = `<template v-if="shouldShow('exceptions')">
<section class="card wide">
  <div class="pt-head">
    <div>
      <h2>Exceptions</h2>
      <p class="muted">Everything that is let through on purpose: what the WAF skips, where the visitor check is off, and which clients are never asked to verify.</p>
    </div>
    <div class="toolbar wrap" v-if="exTab !== 'trusted'">
      <label class="muted" for="ex-filter">Find</label>
      <input id="ex-filter" class="input input-wide pt-host" type="text" placeholder="vhost or path" v-model.trim="exFilter" />
    </div>
  </div>
  <div class="vp-tabs" role="tablist" aria-label="Kinds of exception">
    <button v-for="t in exTabs" :key="t.key" type="button" role="tab" class="vp-tab" :class="{ on: exTab === t.key }" :aria-selected="exTab === t.key ? 'true' : 'false'" @click="exSetTab(t.key)">{{ t.label }} <span class="muted">{{ t.count }}</span></button>
  </div>
  <p v-if="actionMsg" class="statusline" role="status">{{ actionMsg }}</p>
</section>

<section class="card wide" v-if="exTab === 'waf'">
  <h2>WAF exceptions</h2>
  <p class="muted" v-if="!exExcludesShown">This session cannot manage excludes.</p>
  <template v-else>
  <p class="muted" v-if="!isScoped">A request that matches is not checked by the rules named. Prefer the narrowest: one rule on one path beats the whole WAF on a host. Widest entries are listed first.</p>
  <p class="muted" v-else>For a request of your own site that the WAF stops by mistake: let it through one rule, on your site or on one path of it, for 24 hours or 7 days. Without a rule, a host entry switches your site's WAF off ({{ exKeptNote() }}). The server's administrator is told of each change.</p>
  <div class="toolbar wrap ex-add">
    <label class="muted" for="ex-waf-type">Let through</label>
    <select id="ex-waf-type" class="input" v-model="wafExcludeType" aria-label="Kind of WAF exclude">
      <option value="host">a host</option>
      <option value="path" v-if="pathTypeAllowedFor('waf')">a path</option>
    </select>
    <input class="input input-wide" type="text" v-model.trim="wafExcludeValue" :placeholder="wafExcludeType === 'path' ? '/api/callback' : 'example.com'" aria-label="Host or path" />
    <label class="muted" for="ex-waf-rules">for rules</label>
    <input id="ex-waf-rules" class="input" style="width: 9rem" type="text" v-model.trim="wafExcludeRules" :placeholder="isScoped ? 'one rule, e.g. 402' : 'all (or 402, 431-436)'" :title="isScoped ? 'One WAF rule ID (shown in the WAF log). Empty = the WAF of your site off.' : 'Comma-separated WAF rule IDs. Empty = the whole WAF.'" />
    <template v-if="!isScoped || wafExcludeType === 'path'">
      <label class="muted" for="ex-waf-scope">on</label>
      <input id="ex-waf-scope" class="input" style="width: 12rem" type="text" v-model.trim="wafExcludeScope" :placeholder="isScoped ? 'your site (all of yours if empty)' : 'every vhost (or a.gr, b.gr)'" :title="isScoped ? 'One or more of your own sites, comma-separated.' : 'Comma-separated vhosts. Empty = every vhost.'" />
    </template>
    <template v-if="!isScoped || wafExcludeRules">
      <label class="muted" for="ex-waf-ttl">for</label>
      <select id="ex-waf-ttl" class="input" v-model="wafExcludeTTL" aria-label="How long the exclude lasts">
        <option value="" v-if="!isScoped">no expiry</option>
        <option v-for="t in wafExcludeTTLs" :key="t.key" :value="t.key">{{ t.label }}</option>
      </select>
    </template>
    <button type="button" class="btn-quiet" @click="addExclude('waf')">Add</button>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Lets through</th><th>Skips</th><th>Where</th><th>Added</th><th>Expires</th><th></th></tr></thead>
      <tbody>
        <tr v-for="row in exWAFRows" :key="'w-' + row.type + '-' + row.value + '-' + (row.rule_ids || []).join('.') + '-' + (row.scope_hosts || []).join('.')">
          <td><span class="muted">{{ row.type }}</span> <code>{{ row.value }}</code></td>
          <td><span class="pill" :class="exSkips(row).whole ? 'warn' : ''">{{ exSkips(row).text }}</span></td>
          <td>{{ exWhere(row) }}</td>
          <td class="muted pt-nowrap" :title="row.created_at || ''">{{ exWhen(row) || '–' }} <span v-if="exBy(row)" class="pill info">{{ exBy(row) }}</span></td>
          <td class="pt-nowrap"><span v-if="exExpires(row).text" class="pill" :class="exExpires(row).soon ? 'warn' : ''">{{ exExpires(row).text }}</span><span v-else class="muted">never</span></td>
          <td class="pt-nowrap"><button type="button" class="btn-quiet btn-sm" @click="removeExclude('waf', row)">Remove</button></td>
        </tr>
        <tr v-if="!exWAFRows.length"><td colspan="6" class="muted">{{ wafExcludes.length ? 'No WAF exception matches.' : 'No WAF exception.' }}</td></tr>
      </tbody>
    </table>
  </div>
  </template>
</section>

<section class="card wide" v-if="exTab === 'challenge'">
  <h2>Challenge exceptions</h2>
  <p class="muted" v-if="!exExcludesShown">This session cannot manage excludes.</p>
  <template v-else>
  <p class="muted">A host the visitor check never covers, or a path taken off the malpath challenge and ban on the sites named. The WAF still applies to both.</p>
  <div class="toolbar wrap ex-add">
    <label class="muted" for="ex-ch-type">Never challenge</label>
    <select id="ex-ch-type" class="input" v-model="challengeExcludeType" aria-label="Kind of challenge exclude">
      <option value="host">a host</option>
      <option value="path" v-if="pathTypeAllowedFor('challenge')">a path</option>
    </select>
    <input class="input input-wide" type="text" v-model.trim="challengeExcludeValue" :placeholder="challengeExcludeType === 'path' ? '/images/.tmb/' : 'example.com'" aria-label="Host or path" />
    <template v-if="challengeExcludeType === 'path'">
      <label class="muted" for="ex-ch-scope">on</label>
      <input id="ex-ch-scope" class="input" style="width: 14rem" type="text" v-model.trim="challengeExcludeScope" :placeholder="isScoped ? 'your site(s), required' : 'vhost(s), required'" title="Comma-separated vhosts this path exclude applies to; each also covers its www. alias. Required." />
    </template>
    <button type="button" class="btn-quiet" @click="addExclude('challenge')">Add</button>
  </div>
  <p class="muted" v-if="challengeExcludeType === 'path'">A path exclude stops the malpath challenge and the malpath ban from counting requests under this path (e.g. <code>/images/.tmb/</code>) on these sites only. Every other path, and this path on any other site, is still checked. The first path segment must be a name, not a wildcard.</p>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Never challenged</th><th>Where</th><th>Added</th><th></th></tr></thead>
      <tbody>
        <tr v-for="row in exChallengeRows" :key="'c-' + row.type + '-' + row.value + '-' + (row.scope_hosts || []).join(',') + '-' + (row.created_at || '')">
          <td><span class="muted">{{ row.type }}</span> <code>{{ row.value }}</code></td>
          <td>{{ formatChallengeExcludeScope(row) }}</td>
          <td class="muted pt-nowrap" :title="row.created_at || ''">{{ exWhen(row) || '–' }}</td>
          <td class="pt-nowrap"><button type="button" class="btn-quiet btn-sm" @click="removeExclude('challenge', row)">Remove</button></td>
        </tr>
        <tr v-if="!exChallengeRows.length"><td colspan="4" class="muted">{{ challengeExcludes.length ? 'No challenge exception matches.' : 'No challenge exception.' }}</td></tr>
      </tbody>
    </table>
  </div>
  </template>
</section>

<template v-if="exTab === 'trusted'">
` + CHALLENGE_ACCESS_PARTIAL + `
</template>
</template>`;
