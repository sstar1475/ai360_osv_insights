/**
 * dark_fixes.js
 * Правильные CSS классы Dash 4.x dropdown:
 *   .dash-dropdown-content   — popup-контейнер
 *   .dash-dropdown-options   — список опций
 *   .dash-dropdown-option    — одна опция
 *   .dash-dropdown-search    — search input
 *   .dash-dropdown-wrapper   — outer wrapper
 */

function injectDarkDropdownCSS() {
    if (document.getElementById('__dark-dd-css')) return;

    const s = document.createElement('style');
    s.id = '__dark-dd-css';
    s.textContent = `

        /* ── Dash 4.x Dropdown ── */

        /* Popup контейнер */
        .dash-dropdown-content {
            background-color: #21262d !important;
            border: 1px solid #30363d !important;
            border-radius: 8px !important;
            box-shadow: 0 6px 24px rgba(0,0,0,0.65) !important;
            color: #f0f6fc !important;
            overflow: hidden !important;
        }

        /* Список опций */
        .dash-dropdown-options {
            background-color: #21262d !important;
        }

        /* Одна опция */
        .dash-dropdown-option {
            background-color: #21262d !important;
            color: #f0f6fc !important;
            font-size: 13px !important;
            cursor: pointer !important;
        }
        .dash-dropdown-option:hover,
        .dash-dropdown-option[aria-selected="true"],
        .dash-dropdown-option.selected,
        .dash-dropdown-option.focused {
            background-color: rgba(230,126,34,0.15) !important;
            color: #e67e22 !important;
        }
        .dash-dropdown-option.is-selected,
        .dash-dropdown-option[data-selected="true"] {
            background-color: rgba(230,126,34,0.25) !important;
            color: #e67e22 !important;
            font-weight: 600 !important;
        }

        /* Search контейнер */
        .dash-dropdown-search-container {
            background-color: #161b22 !important;
            border-bottom: 1px solid #30363d !important;
        }

        /* Search input */
        .dash-dropdown-search {
            background-color: #161b22 !important;
            color: #f0f6fc !important;
            border: none !important;
            outline: none !important;
            caret-color: #e67e22 !important;
        }
        .dash-dropdown-search::placeholder {
            color: #6e7681 !important;
        }

        /* Search icon */
        .dash-dropdown-search-icon {
            color: #6e7681 !important;
        }

        /* Placeholder в закрытом дропдауне */
        .dash-dropdown-placeholder {
            color: #8b949e !important;
        }

        /* Value tags (multi) */
        .dash-dropdown-value-item {
            background-color: rgba(230,126,34,0.2) !important;
            border: 1px solid rgba(230,126,34,0.5) !important;
            color: #e67e22 !important;
            border-radius: 4px !important;
        }

        /* Grid container (если используется) */
        .dash-dropdown-grid-container {
            background-color: #21262d !important;
        }

        /* Actions bar (select all / clear) */
        .dash-dropdown-actions {
            background-color: #21262d !important;
            border-top: 1px solid #30363d !important;
        }
        .dash-dropdown-action-button {
            color: #e67e22 !important;
            background-color: transparent !important;
        }
        .dash-dropdown-action-button:hover {
            background-color: rgba(230,126,34,0.1) !important;
        }

        /* ── Совместимость с react-select (legacy) ── */
        .Select-menu-outer {
            background-color: #21262d !important;
            border: 1px solid #30363d !important;
            border-radius: 8px !important;
            box-shadow: 0 6px 24px rgba(0,0,0,0.65) !important;
        }
        .Select-menu { background-color: #21262d !important; }
        .Select-option { background-color: #21262d !important; color: #f0f6fc !important; }
        .Select-option.is-focused { background-color: rgba(230,126,34,0.15) !important; color: #e67e22 !important; }
        .Select-option.is-selected { background-color: rgba(230,126,34,0.25) !important; color: #e67e22 !important; }
        .Select-noresults { background-color: #21262d !important; color: #8b949e !important; }
        .Select-search, .Select-input { background-color: #161b22 !important; }
    `;
    document.head.appendChild(s);
}

/* ─── Inline патч для search input (у него могут быть js-inline стили) ─── */
function patchInlineStyles() {
    document.querySelectorAll(
        '.dash-dropdown-search, .Select-input input, .Select-search input'
    ).forEach(el => {
        el.style.setProperty('background-color', '#161b22', 'important');
        el.style.setProperty('color',            '#f0f6fc', 'important');
        el.style.setProperty('caret-color',      '#e67e22', 'important');
    });
    document.querySelectorAll('.dash-dropdown-search-container, .Select-search, .Select-input').forEach(el => {
        el.style.setProperty('background-color', '#161b22', 'important');
    });
}

/* ─── MutationObserver (только childList) ─── */
const _obs = new MutationObserver(patchInlineStyles);

function _init() {
    injectDarkDropdownCSS();
    _obs.observe(document.body, { childList: true, subtree: true });
    patchInlineStyles();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _init);
} else {
    _init();
}
