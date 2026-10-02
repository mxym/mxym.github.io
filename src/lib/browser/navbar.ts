let delegatedListenerInstalled = false;

/**
 * Keep navigation controls working after Swup replaces the navbar markup.
 * Delegation also avoids adding a new listener to every button on each view.
 */
export function initNavbar() {
    if (delegatedListenerInstalled) return;
    delegatedListenerInstalled = true;

    document.addEventListener("click", (event) => {
        const target = event.target;
        if (!(target instanceof Element)) return;

        if (target.closest("#display-settings-switch")) {
            document
                .getElementById("display-setting")
                ?.classList.toggle("float-panel-closed");
            return;
        }

        if (target.closest("#more-menu-switch")) {
            document
                .getElementById("more-menu-panel")
                ?.classList.toggle("float-panel-closed");
            document
                .querySelector("#more-menu-group .rotate-icon")
                ?.classList.toggle("open");
            return;
        }

        if (target.closest("#nav-menu-switch")) {
            document
                .getElementById("nav-menu-panel")
                ?.classList.toggle("float-panel-closed");
        }
    });
}
