/**
 * Hide the loading cover with a smooth fade-out animation
 */
function hideLoadingCover() {
    const loadingCover = document.getElementById("loading-cover");
    if (loadingCover) {
        loadingCover.classList.add("loaded");
        // Remove from DOM after animation completes
        setTimeout(() => {
            loadingCover.remove();
        }, 500); // Match the CSS transition duration
    }
}

/**
 * Initialize loading cover functionality
 * Hides the loading cover when the page is fully loaded
 */
export function initLoadingCover() {
    // Hide on window load (all resources loaded)
    window.addEventListener("load", hideLoadingCover);

    // Fallback: hide after maximum 3 seconds
    setTimeout(hideLoadingCover, 3000);
}
