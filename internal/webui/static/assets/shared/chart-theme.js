// Theme-aware ECharts styling shared by every page that draws charts
// (vhost live, MySQL governor, debug). Registers a cfm-dark and cfm-light
// ECharts theme matching the palette in style.css, so axis text, gridlines
// and series colors follow the UI theme instead of the hardcoded dark-only
// values each page used to carry.
//
// Usage:
//   import { initChart, chartColors, onThemeChange } from "../shared/chart-theme.js";
//   let chart = initChart(el);            // themed echarts.init
//   chart.setOption({... lineStyle: { color: chartColors().warn } ...});
//   onThemeChange(() => { /* dispose + re-init + re-render */ });
//
// The theme toggle in nav.js dispatches "cfm-themechange" on window.

const DARK = {
  text: "#dbe7f7",
  axis: "#7f93ad",
  split: "rgba(159,176,195,0.18)",
  tooltipBg: "#1a2338",
  palette: ["#38bdd4", "#eec35e", "#e5647f", "#7fc95e", "#c07ae8", "#4da3ff"],
  colors: { cyan: "#38bdd4", yellow: "#eec35e", red: "#e5647f", green: "#7fc95e", purple: "#c07ae8", blue: "#4da3ff" },
};
const LIGHT = {
  text: "#1f2a44",
  axis: "#64748d",
  split: "rgba(100,116,141,0.18)",
  tooltipBg: "#ffffff",
  palette: ["#0d94a8", "#b07d1e", "#c94263", "#3f8f2f", "#8f4fb8", "#2f7fd6"],
  colors: { cyan: "#0d94a8", yellow: "#b07d1e", red: "#c94263", green: "#3f8f2f", purple: "#8f4fb8", blue: "#2f7fd6" },
};

function themeSpec(t) {
  const axisCommon = {
    axisLine: { lineStyle: { color: t.axis } },
    axisTick: { lineStyle: { color: t.axis } },
    axisLabel: { color: t.axis },
    splitLine: { lineStyle: { color: t.split } },
    nameTextStyle: { color: t.axis },
  };
  return {
    color: t.palette,
    backgroundColor: "transparent",
    textStyle: { color: t.text },
    title: { textStyle: { color: t.text }, subtextStyle: { color: t.axis } },
    legend: { textStyle: { color: t.text } },
    tooltip: {
      backgroundColor: t.tooltipBg,
      borderColor: t.split,
      textStyle: { color: t.text },
    },
    categoryAxis: axisCommon,
    valueAxis: axisCommon,
    timeAxis: axisCommon,
    logAxis: axisCommon,
  };
}

let registered = false;
function ensureRegistered() {
  if (registered || !window.echarts) return;
  window.echarts.registerTheme("cfm-dark", themeSpec(DARK));
  window.echarts.registerTheme("cfm-light", themeSpec(LIGHT));
  registered = true;
}

export function currentTheme() {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export function chartThemeName() {
  return currentTheme() === "light" ? "cfm-light" : "cfm-dark";
}

// Semantic series colors for the active theme — use these instead of
// hardcoded hex so lines stay readable in both themes.
export function chartColors() {
  return (currentTheme() === "light" ? LIGHT : DARK).colors;
}

// Themed replacement for echarts.init.
export function initChart(el) {
  if (!el || !window.echarts) return null;
  ensureRegistered();
  return window.echarts.init(el, chartThemeName());
}

// Runs cb whenever the sidebar theme toggle flips. Chart holders should
// dispose + re-init + re-render inside cb (a registered theme is fixed at
// init time).
export function onThemeChange(cb) {
  window.addEventListener("cfm-themechange", cb);
}

// Also expose as a window global for debugging.
window.CFMChartTheme = { initChart, chartColors, chartThemeName, currentTheme, onThemeChange };
