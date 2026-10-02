import { url } from "@utils/url";
import type { PagefindAPI } from "@/global";

let pagefindPromise: Promise<PagefindAPI> | null = null;

/** Load the search runtime once, when a visitor first uses search. */
export function loadPagefind(): Promise<PagefindAPI> {
    if (window.pagefind) return Promise.resolve(window.pagefind);
    if (pagefindPromise) return pagefindPromise;

    const scriptUrl = url("/pagefind/pagefind.js");
    pagefindPromise = import(/* @vite-ignore */ scriptUrl)
        .then(async (pagefind: PagefindAPI) => {
            await pagefind.options({ excerptLength: 20 });
            window.pagefind = pagefind;
            return pagefind;
        })
        .catch((error) => {
            // A failed network request can be retried on the next interaction.
            pagefindPromise = null;
            throw error;
        });

    return pagefindPromise;
}
