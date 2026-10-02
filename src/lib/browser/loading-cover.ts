let hidden = false;

/** Hide the loading cover as soon as the initial document is ready. */
function hideLoadingCover() {
    if (hidden) return;

    const loadingCover = document.getElementById("loading-cover");
    if (loadingCover) {
        hidden = true;
        loadingCover.classList.add("loaded");
        // Remove from DOM after animation completes
        setTimeout(() => {
            loadingCover.remove();
        }, 500); // Match the CSS transition duration
    }
}

/**
 * Initialize loading cover functionality without waiting for every image,
 * font, or third-party resource to finish loading.
 */
export function initLoadingCover() {
    const showPage = () => requestAnimationFrame(hideLoadingCover);

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", showPage, { once: true });
    } else {
        showPage();
    }

    document.addEventListener("astro:page-load", showPage, { once: true });

    // Keep a short fallback for documents that fail before DOMContentLoaded.
    window.setTimeout(hideLoadingCover, 1200);
}
