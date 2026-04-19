(function (window, document) {
  const CUSTOM_CSS_ID = 'xui-customization-css';
  const CUSTOM_CLASS = 'xui-customization';
  let appliedVariables = [];
  let config = {
    enable: false,
    theme: 'local',
    variables: '{}',
    css: ''
  };

  function normalizeTheme(theme) {
    return ['local', 'light', 'dark', 'ultra-dark'].includes(theme) ? theme : 'local';
  }

  function parseVariables(value) {
    if (!value) return {};
    if (typeof value === 'object') return value;
    try {
      const parsed = JSON.parse(value);
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
    } catch (_) {
      return {};
    }
  }

  function applyTheme(theme) {
    theme = normalizeTheme(theme);
    if (theme === 'local') return;

    if (window.themeSwitcher && typeof window.themeSwitcher.setTheme === 'function') {
      window.themeSwitcher.setTheme(theme, false);
      return;
    }

    const isDark = theme === 'dark' || theme === 'ultra-dark';
    const isUltra = theme === 'ultra-dark';
    document.body.className = isDark ? 'dark' : 'light';

    if (isUltra) {
      document.documentElement.setAttribute('data-theme', 'ultra-dark');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
  }

  function clearVariables() {
    appliedVariables.forEach(key => document.documentElement.style.removeProperty(key));
    appliedVariables = [];
  }

  function applyVariables(variables) {
    clearVariables();
    Object.keys(variables).forEach(key => {
      if (!key.startsWith('--')) return;
      document.documentElement.style.setProperty(key, variables[key]);
      appliedVariables.push(key);
    });
  }

  function applyCustomCSS(css) {
    let style = document.getElementById(CUSTOM_CSS_ID);
    if (!css) {
      if (style) style.remove();
      return;
    }
    if (!style) {
      style = document.createElement('style');
      style.id = CUSTOM_CSS_ID;
      document.head.appendChild(style);
    }
    style.textContent = css;
  }

  function apply(nextConfig) {
    config = Object.assign({}, config, nextConfig || {});
    config.theme = normalizeTheme(config.theme);

    document.documentElement.classList.toggle(CUSTOM_CLASS, !!config.enable);

    if (!config.enable) {
      clearVariables();
      applyCustomCSS('');
      return;
    }

    applyTheme(config.theme);
    applyVariables(parseVariables(config.variables));
    applyCustomCSS(config.css || '');
  }

  async function init() {
    if (!window.HttpUtil) return;

    const msg = await window.HttpUtil.post('/getCustomization');
    if (msg && msg.success && msg.obj) {
      apply(msg.obj);
    }
  }

  window.CustomizationEngine = {
    apply,
    init,
    parseVariables,
    getConfig() {
      return config;
    },
    applyThemePreference(themeSwitcher) {
      if (!config.enable || normalizeTheme(config.theme) === 'local') return;
      themeSwitcher.setTheme(config.theme, false);
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init, { once: true });
  } else {
    init();
  }
})(window, document);
