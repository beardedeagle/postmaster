// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

(() => {
    const darkThemes = ['ayu', 'navy', 'coal'];
    const lightThemes = ['light', 'rust'];
    const instances = [];

    function isDarkTheme() {
        const classList = document.documentElement.classList;
        return darkThemes.some((theme) => classList.contains(theme));
    }

    function getThemeButton(theme) {
        const mdbookButton = document.getElementById(`mdbook-theme-${theme}`);
        return mdbookButton !== null ? mdbookButton : document.getElementById(theme);
    }

    function addThemeReloadHandlers(lastThemeWasLight) {
        for (const darkTheme of darkThemes) {
            const button = getThemeButton(darkTheme);
            if (button !== null) {
                button.addEventListener('click', () => {
                    if (lastThemeWasLight) {
                        window.location.reload();
                    }
                });
            }
        }

        for (const lightTheme of lightThemes) {
            const button = getThemeButton(lightTheme);
            if (button !== null) {
                button.addEventListener('click', () => {
                    if (!lastThemeWasLight) {
                        window.location.reload();
                    }
                });
            }
        }
    }

    function setWrapperHeight(wrapper, svg) {
        const viewBox = svg.viewBox && svg.viewBox.baseVal;
        const width = viewBox && viewBox.width > 0 ? viewBox.width : 800;
        const height = viewBox && viewBox.height > 0 ? viewBox.height : 480;
        const containerWidth = wrapper.clientWidth > 0 ? wrapper.clientWidth : 720;
        const maxHeight = window.innerHeight * 0.72;
        const calculatedHeight = Math.min(containerWidth * (height / width), maxHeight);
        wrapper.style.height = `${Math.max(calculatedHeight, 320)}px`;
    }

    function resizeInstance(instance) {
        window.requestAnimationFrame(() => {
            instance.resize();
            instance.fit();
            instance.center();
        });
    }

    function resizeAllDiagrams() {
        for (const instance of instances) {
            resizeInstance(instance);
        }
    }

    function wrapDiagram(mermaidDiv) {
        const existingWrapper = mermaidDiv.parentElement;
        if (existingWrapper !== null && existingWrapper.classList.contains('mermaid-wrapper')) {
            return existingWrapper;
        }

        const wrapper = document.createElement('div');
        wrapper.className = 'mermaid-wrapper';
        mermaidDiv.parentNode.insertBefore(wrapper, mermaidDiv);
        wrapper.appendChild(mermaidDiv);
        return wrapper;
    }

    function initPanZoom() {
        if (typeof svgPanZoom === 'undefined') {
            return;
        }

        for (const svg of document.querySelectorAll('.mermaid svg')) {
            if (svg.getAttribute('data-pan-zoom-init') === 'true') {
                continue;
            }

            const mermaidDiv = svg.parentElement;
            if (mermaidDiv === null || !mermaidDiv.classList.contains('mermaid')) {
                continue;
            }

            const wrapper = wrapDiagram(mermaidDiv);
            setWrapperHeight(wrapper, svg);
            svg.setAttribute('data-pan-zoom-init', 'true');

            try {
                const instance = svgPanZoom(svg, {
                    zoomEnabled: true,
                    controlIconsEnabled: true,
                    fit: true,
                    center: true,
                    contain: true,
                    minZoom: 0.5,
                    maxZoom: 10,
                    zoomScaleSensitivity: 0.3
                });
                instances.push(instance);
                resizeInstance(instance);
            } catch (error) {
                svg.removeAttribute('data-pan-zoom-init');
                console.error('failed to initialize Mermaid pan/zoom', error);
            }
        }
    }

    async function renderDiagrams(theme) {
        mermaid.initialize({ startOnLoad: false, theme });

        if (typeof mermaid.run === 'function') {
            await mermaid.run({ querySelector: '.mermaid' });
        } else {
            mermaid.init(undefined, '.mermaid');
        }

        initPanZoom();
    }

    function start() {
        const lastThemeWasLight = !isDarkTheme();
        const theme = lastThemeWasLight ? 'default' : 'dark';

        addThemeReloadHandlers(lastThemeWasLight);

        if (typeof mermaid === 'undefined') {
            return;
        }

        renderDiagrams(theme).catch((error) => {
            console.error('failed to render Mermaid diagrams', error);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start, { once: true });
    } else {
        start();
    }

    window.addEventListener('resize', resizeAllDiagrams);
})();
