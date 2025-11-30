import { type CollectionEntry, getCollection } from "astro:content";
import I18nKey from "@i18n/i18nKey";
import { i18n } from "@i18n/translation";
import { getCategoryUrl } from "@utils/url";

async function fetchPosts() {
    const isProd = import.meta.env.PROD;
    return getCollection("posts", ({ data }) =>
        isProd ? data.draft !== true : true,
    );
}

function toTimeDesc(d?: unknown): number {
    if (!d) return 0;
    const t = new Date(String(d)).getTime();
    return Number.isFinite(t) ? t : 0;
}

/** Get posts sorted by published desc */
async function getRawSortedPosts() {
    const all = await fetchPosts();
    // Copy before sort to avoid mutating the original array reference
    return [...all].sort(
        (a, b) => toTimeDesc(b.data.published) - toTimeDesc(a.data.published),
    );
}

export type PostWithNav = CollectionEntry<"posts"> & {
    data: CollectionEntry<"posts">["data"] & {
        prevSlug?: string;
        prevTitle?: string;
        nextSlug?: string;
        nextTitle?: string;
    };
};

/** Sorted posts with prev/next info */
export async function getSortedPosts(): Promise<PostWithNav[]> {
    const sorted = await getRawSortedPosts();

    return sorted.map((post, idx, arr) => {
        const prev = arr[idx + 1];
        const next = arr[idx - 1];

        return {
            ...post,
            data: {
                ...post.data,
                prevSlug: prev?.slug,
                prevTitle: prev?.data.title,
                nextSlug: next?.slug,
                nextTitle: next?.data.title,
            },
        };
    });
}

export type PostForList = {
    slug: string;
    data: CollectionEntry<"posts">["data"];
};

export async function getSortedPostsList(): Promise<PostForList[]> {
    const sorted = await getRawSortedPosts();
    return sorted.map((post) => ({
        slug: post.slug,
        data: post.data,
    }));
}

export type Tag = {
    name: string;
    count: number;
};

export async function getTagList(): Promise<Tag[]> {
    const posts = await fetchPosts();

    const counts = new Map<string, number>();

    for (const p of posts) {
        const tags = Array.isArray(p.data.tags) ? p.data.tags : [];
        for (const raw of tags) {
            const tag = String(raw).trim();
            if (!tag) continue;
            counts.set(tag, (counts.get(tag) ?? 0) + 1);
        }
    }

    const keys = [...counts.keys()].sort((a, b) =>
        a.toLowerCase().localeCompare(b.toLowerCase()),
    );

    return keys.map((name) => ({ name, count: counts.get(name) ?? 0 }));
}

export type Category = {
    name: string;
    count: number;
    url: string;
};

/** Categories aggregated (includes "Uncategorized") */
export async function getCategoryList(): Promise<Category[]> {
    const posts = await fetchPosts();

    const counts = new Map<string, number>();
    const uncategorizedKey = i18n(I18nKey.uncategorized);

    for (const p of posts) {
        const raw = p.data.category;
        const name =
            raw == null || String(raw).trim() === ""
                ? uncategorizedKey
                : String(raw).trim();

        counts.set(name, (counts.get(name) ?? 0) + 1);
    }

    const names = [...counts.keys()].sort((a, b) =>
        a.toLowerCase().localeCompare(b.toLowerCase()),
    );

    return names.map((name) => ({
        name,
        count: counts.get(name) ?? 0,
        url: getCategoryUrl(name),
    }));
}
