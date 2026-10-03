/**
 * Client-Side ZIP Optimizer
 * Strips non-code files (.git, datasets, binary weights, images, media)
 * before uploading to keep payloads well under serverless limits (4.5 MB on Vercel).
 */
import JSZip from 'jszip';

// Code and configuration files needed by the static analysis engine
const ALLOWED_EXTENSIONS = new Set([
  '.py', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.txt', '.md',
  '.dockerignore', '.gitignore', '.requirements'
]);

const IGNORED_DIRS = [
  '.git/', 'node_modules/', 'venv/', 'env/', '__pycache__/', '.pytest_cache/',
  'dist/', 'build/', '.idea/', '.vscode/', '.next/', '.cache/', 'data/', 'dataset/', 'datasets/'
];

const IGNORED_BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
  '.mp4', '.webm', '.mp3', '.wav', '.ogg',
  '.csv', '.tsv', '.parquet', '.feather', '.arrow',
  '.h5', '.hdf5', '.pth', '.pt', '.onnx', '.bin', '.pkl', '.pickle', '.model',
  '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx',
  '.exe', '.so', '.dylib', '.dll', '.pyc', '.wasm'
]);

export interface OptimizationResult {
  file: File;
  originalSize: number;
  optimizedSize: number;
  wasOptimized: boolean;
  fileCount: number;
}

export async function optimizeZipFile(file: File): Promise<OptimizationResult> {
  const originalSize = file.size;

  try {
    const zip = await JSZip.loadAsync(file);
    const newZip = new JSZip();
    let strippedCount = 0;
    let includedCount = 0;

    const entries = Object.keys(zip.files);
    for (const relativePath of entries) {
      const entry = zip.files[relativePath];
      if (entry.dir) continue;

      const pathLower = relativePath.toLowerCase();

      // Check if file is inside an ignored directory
      if (IGNORED_DIRS.some(dir => pathLower.includes(dir))) {
        strippedCount++;
        continue;
      }

      // Check file extension
      const lastDot = pathLower.lastIndexOf('.');
      const ext = lastDot !== -1 ? pathLower.slice(lastDot) : '';

      // Skip large binary/data extensions
      if (IGNORED_BINARY_EXTENSIONS.has(ext)) {
        strippedCount++;
        continue;
      }

      // Known configuration filenames without extensions
      const baseName = pathLower.split('/').pop() || '';
      const isKnownConfigFile = baseName === 'dockerfile' || baseName === 'procfile';

      if (ALLOWED_EXTENSIONS.has(ext) || isKnownConfigFile) {
        const content = await entry.async('uint8array');
        newZip.file(relativePath, content);
        includedCount++;
      } else {
        strippedCount++;
      }
    }

    if (strippedCount > 0 && includedCount > 0) {
      const compressedBlob = await newZip.generateAsync({
        type: 'blob',
        compression: 'DEFLATE',
        compressionOptions: { level: 6 },
      });

      const optimizedFile = new File([compressedBlob], file.name, {
        type: 'application/zip',
        lastModified: Date.now(),
      });

      return {
        file: optimizedFile,
        originalSize,
        optimizedSize: optimizedFile.size,
        wasOptimized: true,
        fileCount: includedCount,
      };
    }
  } catch (err) {
    console.warn('Client-side ZIP optimization bypassed:', err);
  }

  return {
    file,
    originalSize,
    optimizedSize: originalSize,
    wasOptimized: false,
    fileCount: 0,
  };
}
