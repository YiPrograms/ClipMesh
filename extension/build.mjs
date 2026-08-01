import { build } from 'esbuild';
import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';

await rm('dist', { recursive: true, force: true });
await mkdir('dist', { recursive: true });
await build({
  entryPoints: {
    background: 'src/background/index.ts',
    offscreen: 'src/offscreen/index.ts',
    popup: 'src/popup/index.ts',
    options: 'src/options/index.ts',
  },
  outdir: 'dist',
  bundle: true,
  format: 'esm',
  target: 'chrome116',
  sourcemap: true,
  minify: false,
});
await cp('public', 'dist', { recursive: true });
const manifest = JSON.parse(await readFile('manifest.json', 'utf8'));
manifest.version = JSON.parse(await readFile('package.json', 'utf8')).version;
await writeFile('dist/manifest.json', `${JSON.stringify(manifest, null, 2)}\n`);
