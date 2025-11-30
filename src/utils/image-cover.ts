import sharp from "sharp";

export async function generateImageCover(
    imagePath: string,
): Promise<string | null> {
    try {
        const image = sharp(imagePath).ensureAlpha();
        const metadata = await image.metadata();

        if (!metadata.width || !metadata.height) {
            return null;
        }

        const target = image.resize({
            width: Math.min(metadata.width, 512),
            height: Math.min(metadata.height, 512),
            fit: "inside",
        });

        const buffer = await target
            .tint("#101018")
            .toFormat("webp", {
                quality: 20,
            })
            .toBuffer();

        return `data:image/webp;base64,${buffer.toString("base64")}`;
    } catch (error) {
        console.error(
            `Failed to generate image cover for ${imagePath}:`,
            error instanceof Error ? error.message : error,
        );
        return null;
    }
}
