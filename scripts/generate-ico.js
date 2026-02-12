/**
 * Generate .ico file from multiple PNG files
 * ICO format: header + directory entries + PNG data
 * No external dependencies needed.
 */
const fs = require('fs');
const path = require('path');

const icoDir = path.join(__dirname, '..', 'resources', '_ico_temp');
const sizes = [16, 32, 48, 256];
const pngBuffers = sizes.map(s => fs.readFileSync(path.join(icoDir, `${s}.png`)));

// ICO header: 6 bytes
// Directory entry: 16 bytes each
// Then PNG data concatenated

const headerSize = 6;
const dirEntrySize = 16;
const dirSize = dirEntrySize * pngBuffers.length;
let dataOffset = headerSize + dirSize;

// Build header
const header = Buffer.alloc(headerSize);
header.writeUInt16LE(0, 0);      // Reserved
header.writeUInt16LE(1, 2);      // Type: 1 = ICO
header.writeUInt16LE(pngBuffers.length, 4); // Number of images

// Build directory entries
const dirEntries = [];
for (let i = 0; i < pngBuffers.length; i++) {
	const png = pngBuffers[i];
	const size = sizes[i];
	const entry = Buffer.alloc(dirEntrySize);
	entry.writeUInt8(size >= 256 ? 0 : size, 0);  // Width (0 = 256)
	entry.writeUInt8(size >= 256 ? 0 : size, 1);  // Height (0 = 256)
	entry.writeUInt8(0, 2);       // Color palette
	entry.writeUInt8(0, 3);       // Reserved
	entry.writeUInt16LE(1, 4);    // Color planes
	entry.writeUInt16LE(32, 6);   // Bits per pixel
	entry.writeUInt32LE(png.length, 8);  // Size of PNG data
	entry.writeUInt32LE(dataOffset, 12); // Offset to PNG data
	dirEntries.push(entry);
	dataOffset += png.length;
}

const ico = Buffer.concat([header, ...dirEntries, ...pngBuffers]);

// Write to win32 and server
const outWin = path.join(__dirname, '..', 'resources', 'win32', 'code.ico');
const outFav = path.join(__dirname, '..', 'resources', 'server', 'favicon.ico');
fs.writeFileSync(outWin, ico);
fs.writeFileSync(outFav, ico);
console.log(`Created: ${outWin} (${ico.length} bytes)`);
console.log(`Created: ${outFav} (${ico.length} bytes)`);
console.log('Done! You can delete resources/_ico_temp/ now.');
