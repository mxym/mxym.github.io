/**
 * TableOfContents custom element for tracking and highlighting active headings
 * in a document based on scroll position
 */
class TableOfContents extends HTMLElement {
    tocEl: HTMLElement | null = null;
    visibleClass = "visible";
    observer: IntersectionObserver;
    anchorNavTarget: HTMLElement | null = null;
    headingIdxMap = new Map<string, number>();
    headings: HTMLElement[] = [];
    sections: HTMLElement[] = [];
    tocEntries: HTMLAnchorElement[] = [];
    active: boolean[] = [];
    activeIndicator: HTMLElement | null = null;
    private updatePending = false;
    private lastScrollTarget: number | null = null;
    private lastIndicatorStyle = "";
    private readonly desktopMediaQuery: MediaQueryList;

    constructor() {
        super();
        this.desktopMediaQuery = window.matchMedia("(min-width: 1536px)");
        this.observer = new IntersectionObserver(this.handleIntersections, {
            threshold: 0,
        });
    }

    private isTocVisible() {
        return (
            this.desktopMediaQuery.matches &&
            this.tocEl !== null &&
            this.tocEl.getClientRects().length > 0
        );
    }

    private observeSections() {
        if (!this.isTocVisible()) return;
        this.sections.forEach((section) => {
            if (section) this.observer.observe(section);
        });
    }

    private unobserveSections() {
        this.sections.forEach((section) => {
            if (section) this.observer.unobserve(section);
        });
    }

    private handleViewportChange = () => {
        if (this.isTocVisible()) {
            this.observeSections();
            this.applyFallbackActiveSection();
            this.lastScrollTarget = null;
            this.update();
        } else {
            // The TOC is `hidden` below the 2xl breakpoint. There is no value
            // in keeping an observer on every heading of a long post then.
            this.unobserveSections();
        }
    };

    private getHeadingIndexFromEntry(entry: IntersectionObserverEntry) {
        const target = entry.target as HTMLElement;
        const heading = target.firstElementChild as HTMLElement | null;
        const id = heading?.getAttribute("id") ?? null;
        if (!id) return undefined;
        return this.headingIdxMap.get(id);
    }

    handleIntersections = (entries: IntersectionObserverEntry[]) => {
        if (!this.isTocVisible()) return;

        entries.forEach((entry) => {
            const idx = this.getHeadingIndexFromEntry(entry);
            if (idx !== undefined) {
                this.active[idx] = entry.isIntersecting;
            }

            const target = entry.target as HTMLElement;
            const heading = target.firstElementChild as HTMLElement | null;
            if (entry.isIntersecting && this.anchorNavTarget === heading) {
                this.anchorNavTarget = null;
            }
        });

        if (!this.active.some(Boolean)) {
            this.applyFallbackActiveSection();
        }

        this.update();
    };

    toggleActiveHeading = () => {
        if (!this.tocEntries.length) return;

        let min = this.active.length;
        let max = -1;

        // First pass: find min and max indices
        for (let i = this.active.length - 1; i >= 0; i--) {
            if (this.active[i]) {
                if (i < min) min = i;
                if (i > max) max = i;
            }
        }

        // Batch DOM reads first to prevent layout thrashing
        let parentRect: DOMRect | undefined;
        let scrollOffset: number | undefined;
        let topRect: DOMRect | undefined;
        let bottomRect: DOMRect | undefined;

        if (min <= max && this.tocEl) {
            parentRect = this.tocEl.getBoundingClientRect();
            scrollOffset = this.tocEl.scrollTop;
            topRect = this.tocEntries[min].getBoundingClientRect();
            bottomRect = this.tocEntries[max].getBoundingClientRect();
        }

        // Then batch DOM writes
        for (let i = this.active.length - 1; i >= 0; i--) {
            this.tocEntries[i].classList.toggle(
                this.visibleClass,
                this.active[i],
            );
        }

        if (
            min > max ||
            !this.tocEl ||
            !parentRect ||
            !topRect ||
            !bottomRect
        ) {
            if (this.lastIndicatorStyle !== "opacity: 0") {
                this.activeIndicator?.setAttribute("style", "opacity: 0");
                this.lastIndicatorStyle = "opacity: 0";
            }
            return;
        }

        if (scrollOffset === undefined) return;

        const top = topRect.top - parentRect.top + scrollOffset;
        const bottom = bottomRect.bottom - parentRect.top + scrollOffset;

        const indicatorStyle = `top: ${top}px; height: ${bottom - top}px`;
        if (indicatorStyle !== this.lastIndicatorStyle) {
            this.activeIndicator?.setAttribute("style", indicatorStyle);
            this.lastIndicatorStyle = indicatorStyle;
        }
    };

    scrollToActiveHeading = () => {
        if (this.anchorNavTarget || !this.tocEl || !this.isTocVisible()) return;

        const activeEntries = this.tocEl.querySelectorAll<HTMLElement>(
            `.${this.visibleClass}`,
        );
        if (!activeEntries.length) return;

        const topmost = activeEntries[0];
        const bottommost = activeEntries[activeEntries.length - 1];
        const tocHeight = this.tocEl.clientHeight;

        let top: number;
        const visibleSpan =
            bottommost.getBoundingClientRect().bottom -
            topmost.getBoundingClientRect().top;

        if (visibleSpan < 0.9 * tocHeight) {
            top = topmost.offsetTop - 32;
        } else {
            top = bottommost.offsetTop - tocHeight * 0.8;
        }

        // IntersectionObserver can report multiple entries for one scroll
        // event. Avoid restarting the same smooth scroll on every callback.
        if (
            this.lastScrollTarget !== null &&
            Math.abs(this.lastScrollTarget - top) < 1
        ) {
            return;
        }
        this.lastScrollTarget = top;

        this.tocEl.scrollTo({
            top,
            left: 0,
            behavior: this.prefersReducedMotion() ? "auto" : "smooth",
        });
    };

    private prefersReducedMotion() {
        return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    }

    update = () => {
        if (this.updatePending) return;
        this.updatePending = true;

        requestAnimationFrame(() => {
            this.updatePending = false;
            if (!this.isTocVisible()) return;
            this.toggleActiveHeading();
            this.scrollToActiveHeading();
        });
    };

    applyFallbackActiveSection = () => {
        if (!this.sections.length) return;

        for (let i = 0; i < this.sections.length; i++) {
            const section = this.sections[i];
            if (!section) continue;

            const rect = section.getBoundingClientRect();
            const offsetTop = rect.top;
            const offsetBottom = rect.bottom;

            if (
                this.isInRange(offsetTop, 0, window.innerHeight) ||
                this.isInRange(offsetBottom, 0, window.innerHeight) ||
                (offsetTop < 0 && offsetBottom > window.innerHeight)
            ) {
                this.active[i] = true;
            } else if (offsetTop > window.innerHeight) {
                break;
            }
        }
    };

    handleAnchorClick = (event: Event) => {
        const anchor = event
            .composedPath()
            .find((el) => el instanceof HTMLAnchorElement) as
            | HTMLAnchorElement
            | undefined;

        if (!anchor) return;

        const id = decodeURIComponent(anchor.hash?.substring(1));
        const idx = this.headingIdxMap.get(id);

        this.anchorNavTarget = idx !== undefined ? this.headings[idx] : null;
        this.lastScrollTarget = null;
    };

    private isInRange(value: number, min: number, max: number) {
        return min < value && value < max;
    }

    connectedCallback() {
        this.desktopMediaQuery.addEventListener(
            "change",
            this.handleViewportChange,
        );

        // Wait for the onload animation to finish so `getBoundingClientRect`
        // returns correct values.
        const animatedElement = document.querySelector(".prose");
        if (animatedElement) {
            animatedElement.addEventListener(
                "animationend",
                () => this.init(),
                {
                    once: true,
                },
            );
        } else {
            // If the animated element isn't found, just initialize immediately.
            this.init();
        }
    }

    init() {
        this.tocEl = document.getElementById("toc-inner-wrapper");

        if (!this.tocEl) return;

        this.tocEl.addEventListener("click", this.handleAnchorClick, {
            capture: true,
        });

        this.activeIndicator = document.getElementById("active-indicator");

        this.tocEntries = Array.from(
            document.querySelectorAll<HTMLAnchorElement>("#toc a[href^='#']"),
        );

        if (!this.tocEntries.length) return;

        this.sections = new Array(this.tocEntries.length);
        this.headings = new Array(this.tocEntries.length);

        for (let i = 0; i < this.tocEntries.length; i++) {
            const id = decodeURIComponent(
                this.tocEntries[i].hash?.substring(1),
            );
            const heading = document.getElementById(id);
            const section = heading?.parentElement;

            if (
                heading instanceof HTMLElement &&
                section instanceof HTMLElement
            ) {
                this.headings[i] = heading;
                this.sections[i] = section;
                this.headingIdxMap.set(id, i);
            }
        }

        this.active = new Array(this.tocEntries.length).fill(false);

        if (this.isTocVisible()) {
            this.observeSections();
            this.applyFallbackActiveSection();
            this.update();
        }
    }

    disconnectedCallback() {
        this.desktopMediaQuery.removeEventListener(
            "change",
            this.handleViewportChange,
        );
        this.unobserveSections();
        this.observer.disconnect();
        this.tocEl?.removeEventListener("click", this.handleAnchorClick, {
            capture: true,
        });
    }
}

/**
 * Initialize the TableOfContents custom element
 * Registers the custom element if not already defined
 */
export function initTableOfContents() {
    if (!customElements.get("table-of-contents")) {
        customElements.define("table-of-contents", TableOfContents);
    }
}
