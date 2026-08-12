const fs = require("fs");
const path = require("path");
const sharp = require("sharp");

// Go up one level from index/ to project root, then into public/
const PUBLIC_DIR = path.join(__dirname, "..", "public");
const THUMB_SUFFIX = "_thumb";
const THUMB_WIDTH = 40;
const QUALITY = 40;

// Collect all files from directory tree
function getAllFiles(dir) {
    const files = [];

    try {
        const entries = fs.readdirSync(dir);

        for (const entry of entries) {
            const fullPath = path.join(dir, entry);
            const stat = fs.statSync(fullPath);

            if (stat.isDirectory()) {
                files.push(...getAllFiles(fullPath));
            } else {
                files.push(fullPath);
            }
        }
    } catch (err) {
        console.error(`✗ Cannot read directory: ${dir}`);
        console.error(`  Error: ${err.message}`);
    }

    return files;
}

function isImage(file) {
    return /\.(jpg|jpeg|png|webp)$/i.test(file);
}

async function generateThumbnail(imagePath) {
    const ext = path.extname(imagePath);
    const base = imagePath.slice(0, -ext.length);
    const relativePath = path.relative(PUBLIC_DIR, imagePath);

    // Skip if already a thumbnail
    if (base.endsWith(THUMB_SUFFIX)) {
        console.log(`  ⊘ Skipping: ${relativePath} (already a thumbnail)`);
        return { status: 'skipped', reason: 'thumbnail' };
    }

    const thumbPath = `${base}${THUMB_SUFFIX}${ext}`;
    const relativeThumbPath = path.relative(PUBLIC_DIR, thumbPath);

    // Skip if thumbnail exists
    if (fs.existsSync(thumbPath)) {
        console.log(`  ⊙ Exists: ${relativeThumbPath}`);
        return { status: 'exists' };
    }

    try {
        // Preserve original format
        const sharpInstance = sharp(imagePath).resize(THUMB_WIDTH);

        if (ext.match(/\.jpe?g$/i)) {
            sharpInstance.jpeg({ quality: QUALITY });
        } else if (ext.match(/\.png$/i)) {
            sharpInstance.png({ quality: QUALITY });
        } else if (ext.match(/\.webp$/i)) {
            sharpInstance.webp({ quality: QUALITY });
        }

        await sharpInstance.toFile(thumbPath);
        console.log(`  ✓ Created: ${relativeThumbPath}`);
        return { status: 'created' };
    } catch (err) {
        console.error(`  ✗ Failed: ${relativePath}`);
        console.error(`    Error: ${err.message}`);
        return { status: 'failed', error: err.message };
    }
}

async function generateAllThumbnails() {
    console.log("\n" + "=".repeat(60));
    console.log("THUMBNAIL GENERATOR");
    console.log("=".repeat(60));
    console.log(`Working directory: ${process.cwd()}`);
    console.log(`Public directory:  ${PUBLIC_DIR}`);
    console.log(`Thumbnail width:   ${THUMB_WIDTH}px`);
    console.log(`Quality:           ${QUALITY}%`);
    console.log("=".repeat(60) + "\n");

    // Check if public directory exists
    if (!fs.existsSync(PUBLIC_DIR)) {
        console.error("❌ ERROR: Public directory not found!\n");
        console.error(`Expected location: ${PUBLIC_DIR}\n`);
        console.error("Please ensure:");
        console.error("  1. You're running this from your project root");
        console.error("  2. A 'public' folder exists");
        console.error("\nCurrent directory structure should be:");
        console.error("  your-project/");
        console.error("  ├── public/          ← This folder is missing!");
        console.error("  │   └── (your images here)");
        console.error("  └── thumbnail_generator.js\n");
        return;
    }

    console.log("📁 Scanning for images...\n");

    const allFiles = getAllFiles(PUBLIC_DIR);
    const imageFiles = allFiles.filter(isImage);

    console.log(`Total files found: ${allFiles.length}`);
    console.log(`Image files found: ${imageFiles.length}`);

    if (imageFiles.length === 0) {
        console.log("\n⚠️  No images found in public directory!");
        console.log("\nSupported formats: .jpg, .jpeg, .png, .webp");
        console.log("\nExpected structure:");
        console.log("  public/");
        console.log("  ├── image1.jpg");
        console.log("  ├── image2.png");
        console.log("  └── subfolder/");
        console.log("      └── image3.webp\n");
        return;
    }

    console.log("\n" + "-".repeat(60));
    console.log("Processing images:");
    console.log("-".repeat(60) + "\n");

    const results = { created: 0, exists: 0, skipped: 0, failed: 0 };

    for (const imagePath of imageFiles) {
        const result = await generateThumbnail(imagePath);
        if (result.status === 'created') results.created++;
        else if (result.status === 'exists') results.exists++;
        else if (result.status === 'skipped') results.skipped++;
        else if (result.status === 'failed') results.failed++;
    }

    console.log("\n" + "-".repeat(60));
    console.log("SUMMARY");
    console.log("-".repeat(60));
    console.log(`✓ Created:  ${results.created}`);
    console.log(`⊙ Existing: ${results.exists}`);
    console.log(`⊘ Skipped:  ${results.skipped}`);
    console.log(`✗ Failed:   ${results.failed}`);
    console.log("-".repeat(60) + "\n");

    if (results.created > 0) {
        console.log("✅ Thumbnail generation complete!\n");
    } else if (results.exists > 0) {
        console.log("ℹ️  All thumbnails already exist.\n");
    }
}

// Run if executed directly
if (require.main === module) {
    generateAllThumbnails().catch(err => {
        console.error("\n💥 Fatal error:", err.message);
        console.error(err.stack);
        process.exit(1);
    });
}

module.exports = { generateAllThumbnails };