<script lang="ts">
import I18nKey from "@i18n/i18nKey";
import { i18n } from "@i18n/translation";
import Icon from "@iconify/svelte";
import { url } from "@utils/url";
import { loadPagefind } from "@lib/browser/search";
import { onDestroy, onMount } from "svelte";
import { fade } from "svelte/transition";
import type { SearchResult } from "@/global";

let keywordDesktop = "";
let keywordMobile = "";
let result: SearchResult[] = [];
let isSearching = false;
let initialized = false;

const DEBOUNCE_MS = 200;
let debounceId: ReturnType<typeof setTimeout> | null = null;
let searchRevision = 0;
let activeField: "desktop" | "mobile" = "desktop";
let activeKeyword = "";
let activeIsDesktop = true;

const fakeResult: SearchResult[] = [
    {
        url: url("/"),
        meta: { title: "This Is a Fake Search Result" },
        excerpt:
            "Because the search cannot work in the <mark>dev</mark> environment.",
    },
    {
        url: url("/"),
        meta: { title: "If You Want to Test the Search" },
        excerpt: "Try running <mark>npm build && npm preview</mark> instead.",
    },
];

const togglePanel = () => {
    activeField = "mobile";
    requestPagefind();
    const panel = document.getElementById("search-panel");
    panel?.classList.toggle("float-panel-closed");
};

const requestPagefind = () => {
    if (import.meta.env.PROD) {
        void loadPagefind().catch(() => {
            // Search reports a useful empty state when the index is unavailable.
        });
    }
};

const setPanelVisibility = (show: boolean, isDesktop: boolean): void => {
    const panel = document.getElementById("search-panel");
    if (!panel || !isDesktop) return;
    panel.classList.toggle("float-panel-closed", !show);
};

/**
 * Core search executor (no debounce). Sets loading state and guards against
 * out-of-order responses using a monotonically increasing revision.
 */
const runSearch = async (
    keyword: string,
    isDesktop: boolean,
    revision: number,
): Promise<void> => {
    isSearching = true;

    try {
        let searchResults: SearchResult[] = [];

        if (import.meta.env.PROD) {
            const pagefind = await loadPagefind();
            if (revision !== searchRevision) return;
            const response = await pagefind.search(keyword);
            // Search previews only need a few entries; avoid fetching every result's data.
            const dataPromises = response.results
                .slice(0, 12)
                .map((item) => item.data());
            searchResults = await Promise.all(dataPromises);
        } else if (import.meta.env.DEV) {
            searchResults = fakeResult;
        } else {
            console.error(
                "Pagefind is not available in production environment.",
            );
            searchResults = [];
        }

        if (revision === searchRevision) {
            result = searchResults;
            setPanelVisibility(result.length > 0, isDesktop);
        }
    } catch (error) {
        if (revision === searchRevision) {
            console.error("Search error:", error);
            result = [];
            setPanelVisibility(false, isDesktop);
        }
    } finally {
        if (revision === searchRevision) {
            isSearching = false;
        }
    }
};

/** Debounced wrapper so we don’t spam pagefind. */
const queueSearch = (keyword: string, isDesktop: boolean) => {
    const query = keyword.trim();
    const revision = ++searchRevision;
    if (debounceId) clearTimeout(debounceId);

    if (!query) {
        isSearching = false;
        result = [];
        setPanelVisibility(false, isDesktop);
        return;
    }

    isSearching = initialized;
    debounceId = setTimeout(() => {
        void runSearch(query, isDesktop, revision);
    }, DEBOUNCE_MS);
};

onMount(() => {
    initialized = true;
});

onDestroy(() => {
    if (debounceId) clearTimeout(debounceId);
    searchRevision++;
});

// A single active query prevents the empty hidden input from cancelling searches.
$: activeKeyword = activeField === "desktop" ? keywordDesktop : keywordMobile;
$: activeIsDesktop = activeField === "desktop";
$: initialized && queueSearch(activeKeyword, activeIsDesktop);
</script>

<!-- search bar for desktop view -->
<div
	id="search-bar"
	class="relative hidden lg:flex transition-all items-center h-11 mr-2 rounded-[var(--radius-large)]
         bg-black/[0.04] hover:bg-black/[0.06] focus-within:bg-black/[0.06]
         dark:bg-white/5 dark:hover:bg-white/10 dark:focus-within:bg-white/10"
	aria-busy={isSearching}
>
	<Icon
		icon="material-symbols:search"
		class="absolute text-[1.25rem] pointer-events-none ml-3 transition my-auto text-black/30 dark:text-white/30"
	/>
	<input
		placeholder={i18n(I18nKey.search)}
		bind:value={keywordDesktop}
		on:focus={() => {
			activeField = "desktop";
			requestPagefind();
		}}
		class="transition-all pl-10 pr-8 text-sm bg-transparent outline-0
           h-full w-40 active:w-60 focus:w-60 text-black/50 dark:text-white/50"
	/>
	{#if isSearching}
		<span
			class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2"
			in:fade={{ duration: 150 }}
			out:fade={{ duration: 150 }}
			aria-hidden="true"
		>
			<Icon icon="eos-icons:loading" class="text-[1.1rem]" />
		</span>
	{/if}
</div>

<!-- toggle btn for phone/tablet view -->
<button
	on:click={togglePanel}
	aria-label="Search Panel"
	id="search-switch"
	class="btn-plain scale-animation lg:!hidden rounded-lg w-11 h-11 active:scale-90"
	aria-busy={isSearching}
>
	<Icon icon="material-symbols:search" class="text-[1.25rem]" />
</button>

<!-- search panel -->
<div
	id="search-panel"
	class="float-panel float-panel-closed search-panel absolute md:w-[30rem]
top-20 left-4 md:left-[unset] right-4 shadow-2xl rounded-2xl p-2"
	aria-busy={isSearching}
>
	<!-- search bar inside panel for phone/tablet -->
	<div
		id="search-bar-inside"
		class="flex relative lg:hidden transition-all items-center h-11 rounded-xl
         bg-black/[0.04] hover:bg-black/[0.06] focus-within:bg-black/[0.06]
         dark:bg-white/5 dark:hover:bg-white/10 dark:focus-within:bg-white/10"
	>
		<Icon
			icon="material-symbols:search"
			class="absolute text-[1.25rem] pointer-events-none ml-3 transition my-auto text-black/30 dark:text-white/30"
		/>
		<input
			placeholder={i18n(I18nKey.search)}
			bind:value={keywordMobile}
			on:focus={() => {
				activeField = "mobile";
				requestPagefind();
			}}
			class="pl-10 pr-8 absolute inset-0 text-sm bg-transparent outline-0
           focus:w-60 text-black/50 dark:text-white/50"
		/>
		{#if isSearching}
			<span
				class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2"
				in:fade={{ duration: 150 }}
				out:fade={{ duration: 150 }}
				aria-hidden="true"
			>
				<Icon icon="eos-icons:loading" class="text-[1.1rem]" />
			</span>
		{/if}
	</div>

	<!-- search results -->
	{#if isSearching}
		<div class="px-3 py-3 text-sm text-50">Searching...</div>
	{:else if activeKeyword && result.length === 0}
		<div class="px-3 py-3 text-sm text-50">No results found.</div>
	{:else}
		{#each result as item}
			<a
				href={item.url}
				class="transition first-of-type:mt-2 lg:first-of-type:mt-0 group block
       rounded-xl text-lg px-3 py-2 hover:bg-[var(--btn-plain-bg-hover)] active:bg-[var(--btn-plain-bg-active)]"
			>
				<div
					class="transition text-90 inline-flex font-bold group-hover:text-[var(--primary)]"
				>
					{item.meta.title}
					<Icon
						icon="fa6-solid:chevron-right"
						class="transition text-[0.75rem] translate-x-1 my-auto text-[var(--primary)]"
					/>
				</div>
				<div class="transition text-sm text-50">
					{@html item.excerpt}
				</div>
			</a>
		{/each}
	{/if}
</div>

<style>
	input:focus {
		outline: 0;
	}
	.search-panel {
		max-height: calc(100vh - 100px);
		overflow-y: auto;
	}
</style>
