/**
 * EU Age Verification Wallet - Build Script
 * 
 * Builds the browser extension for Chrome and Firefox.
 * Uses esbuild for fast TypeScript compilation.
 */

import * as esbuild from 'esbuild';
import * as fs from 'fs';
import * as path from 'path';
import { deflateSync } from 'zlib';

const isWatch = process.argv.includes('--watch');
const distDir = 'dist';

// Ensure dist directory exists
if (!fs.existsSync(distDir)) {
  fs.mkdirSync(distDir, { recursive: true });
}

// Build configuration for each entry point
const buildConfigs = [
  {
    entryPoints: ['background/service-worker.ts'],
    outfile: `${distDir}/background/service-worker.js`,
    format: 'esm',
  },
  {
    entryPoints: ['popup/popup.ts'],
    outfile: `${distDir}/popup/popup.js`,
    format: 'iife',
  },
  {
    entryPoints: ['content/content-script.ts'],
    outfile: `${distDir}/content/content-script.js`,
    format: 'iife',
  },
];

// Common build options
const commonOptions = {
  bundle: true,
  minify: !isWatch,
  sourcemap: isWatch,
  target: ['chrome100', 'firefox100'],
  define: {
    'process.env.NODE_ENV': isWatch ? '"development"' : '"production"',
  },
};

// ============================================================================
// PNG Icon Generation
// ============================================================================

let crc32Table = null;
function getCRC32Table() {
  if (crc32Table) return crc32Table;
  
  crc32Table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    crc32Table[i] = c;
  }
  return crc32Table;
}

function crc32(buf) {
  let crc = 0xffffffff;
  const table = getCRC32Table();
  
  for (let i = 0; i < buf.length; i++) {
    crc = table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  
  return crc ^ 0xffffffff;
}

function createPNGChunk(type, data) {
  const typeBuffer = Buffer.from(type);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  
  const crcData = Buffer.concat([typeBuffer, data]);
  const crc = crc32(crcData);
  const crcBuffer = Buffer.alloc(4);
  crcBuffer.writeUInt32BE(crc >>> 0, 0);
  
  return Buffer.concat([length, typeBuffer, data, crcBuffer]);
}

function encodePNG(pixels, width, height) {
  // PNG signature
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  
  // IHDR chunk
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr.writeUInt8(8, 8);  // bit depth
  ihdr.writeUInt8(6, 9);  // color type (RGBA)
  ihdr.writeUInt8(0, 10); // compression
  ihdr.writeUInt8(0, 11); // filter
  ihdr.writeUInt8(0, 12); // interlace
  const ihdrChunk = createPNGChunk('IHDR', ihdr);
  
  // IDAT chunk - add filter byte (0 = none) before each row
  const rawData = Buffer.alloc(height * (1 + width * 4));
  for (let y = 0; y < height; y++) {
    rawData[y * (1 + width * 4)] = 0; // Filter byte
    for (let x = 0; x < width * 4; x++) {
      rawData[y * (1 + width * 4) + 1 + x] = pixels[y * width * 4 + x];
    }
  }
  
  const compressed = deflateSync(rawData);
  const idatChunk = createPNGChunk('IDAT', compressed);
  
  // IEND chunk
  const iendChunk = createPNGChunk('IEND', Buffer.alloc(0));
  
  return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
}

function generateShieldIconPNG(size) {
  const pixels = new Uint8Array(size * size * 4);
  
  // Create gradient background (indigo #6366f1 to purple #7c3aed)
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 4;
      const t = (x + y) / (size * 2); // Diagonal gradient
      
      // Interpolate between indigo and purple
      pixels[i] = Math.round(99 + (124 - 99) * t);      // R: 99 -> 124
      pixels[i + 1] = Math.round(102 + (58 - 102) * t); // G: 102 -> 58
      pixels[i + 2] = Math.round(241 + (237 - 241) * t); // B: 241 -> 237
      pixels[i + 3] = 255; // Alpha
    }
  }
  
  // Draw a white shield shape
  const cx = size / 2;
  const cy = size / 2;
  const shieldWidth = size * 0.6;
  const shieldHeight = size * 0.7;
  
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const dx = (x - cx) / (shieldWidth / 2);
      const dy = (y - cy * 0.9) / (shieldHeight / 2);
      
      // Shield shape: rounded top, pointed bottom
      const topRadius = 0.3;
      const inTop = dy < 0 && Math.abs(dx) < 1 - Math.abs(dy) * topRadius;
      const inBottom = dy >= 0 && Math.abs(dx) < 1 - dy * 1.2;
      
      if ((inTop || inBottom) && dy > -0.8 && dy < 0.9) {
        const i = (y * size + x) * 4;
        pixels[i] = 255;     // R
        pixels[i + 1] = 255; // G
        pixels[i + 2] = 255; // B
        pixels[i + 3] = 255; // Alpha
      }
    }
  }
  
  // Draw checkmark in center (purple color)
  const checkSize = size * 0.25;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const dx = x - cx;
      const dy = y - cy * 1.1;
      
      // Simple checkmark: two lines
      const lineWidth = size * 0.08;
      const onLine1 = Math.abs(dx + dy + checkSize * 0.3) < lineWidth && 
                      dx > -checkSize * 0.5 && dx < checkSize * 0.1;
      const onLine2 = Math.abs(dx - dy * 0.5 - checkSize * 0.1) < lineWidth && 
                      dx >= checkSize * 0.1 && dx < checkSize * 0.6;
      
      if (onLine1 || onLine2) {
        const i = (y * size + x) * 4;
        pixels[i] = 124;     // R (purple)
        pixels[i + 1] = 58;  // G
        pixels[i + 2] = 237; // B
        pixels[i + 3] = 255; // Alpha
      }
    }
  }
  
  return encodePNG(pixels, size, size);
}

// ============================================================================
// Static Files
// ============================================================================

function copyStaticFiles() {
  // Copy manifest
  fs.copyFileSync('manifest.json', `${distDir}/manifest.json`);
  
  // Copy popup HTML and CSS
  if (!fs.existsSync(`${distDir}/popup`)) {
    fs.mkdirSync(`${distDir}/popup`, { recursive: true });
  }
  fs.copyFileSync('popup/popup.html', `${distDir}/popup/popup.html`);
  fs.copyFileSync('popup/popup.css', `${distDir}/popup/popup.css`);
  
  // Create icons directory and generate PNG icons
  if (!fs.existsSync(`${distDir}/icons`)) {
    fs.mkdirSync(`${distDir}/icons`, { recursive: true });
  }
  
  // Generate shield icon PNGs
  const sizes = [16, 32, 48, 128];
  sizes.forEach(size => {
    const png = generateShieldIconPNG(size);
    fs.writeFileSync(`${distDir}/icons/icon${size}.png`, png);
  });
  
  console.log('📁 Static files copied');
}

// ============================================================================
// Build Functions
// ============================================================================

async function build() {
  console.log('🔨 Building extension...\n');
  
  try {
    // Copy static files first
    copyStaticFiles();
    
    // Build each entry point
    for (const config of buildConfigs) {
      await esbuild.build({
        ...commonOptions,
        ...config,
      });
      console.log(`✅ Built: ${config.outfile}`);
    }
    
    console.log('\n✨ Build complete!');
    console.log(`📦 Output: ${path.resolve(distDir)}`);
    
    if (!isWatch) {
      console.log('\nTo load in Chrome:');
      console.log('  1. Go to chrome://extensions/');
      console.log('  2. Enable "Developer mode"');
      console.log('  3. Click "Load unpacked"');
      console.log(`  4. Select: ${path.resolve(distDir)}`);
      console.log('\nTo load in Firefox:');
      console.log('  1. Go to about:debugging#/runtime/this-firefox');
      console.log('  2. Click "Load Temporary Add-on..."');
      console.log(`  3. Select: ${path.resolve(distDir, 'manifest.json')}`);
    }
  } catch (error) {
    console.error('❌ Build failed:', error);
    process.exit(1);
  }
}

async function watch() {
  console.log('👀 Watching for changes...\n');
  
  // Initial build
  await build();
  
  // Set up watchers
  const contexts = await Promise.all(
    buildConfigs.map(config => 
      esbuild.context({
        ...commonOptions,
        ...config,
      })
    )
  );
  
  // Start watching
  await Promise.all(contexts.map(ctx => ctx.watch()));
  
  // Watch static files
  const staticFiles = ['manifest.json', 'popup/popup.html', 'popup/popup.css'];
  staticFiles.forEach(file => {
    fs.watchFile(file, () => {
      console.log(`📄 ${file} changed, copying...`);
      copyStaticFiles();
    });
  });
  
  console.log('\n⌛ Watching for changes... (Ctrl+C to stop)');
}

// Run
if (isWatch) {
  watch();
} else {
  build();
}
