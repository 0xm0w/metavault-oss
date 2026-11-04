import {build} from 'esbuild';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const dir=path.dirname(fileURLToPath(import.meta.url));
await build({absWorkingDir:dir,entryPoints:['entry.jsx'],bundle:true,minify:true,outdir:path.join(dir,'../../site/assets/animations'),entryNames:'animations',loader:{'.ttf':'file'},assetNames:'fonts/[name]-[hash]',jsx:'transform',legalComments:'eof',banner:{js:'/* eslint-disable */'}});
