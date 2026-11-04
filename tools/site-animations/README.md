# Hackathon animations

The user's accepted React components, restyled in place. The component composition, scenarios, controls and six stages remain intact. Public wording corrections were individually approved on 2026-11-05.

Build committed static assets with `npm ci && npm run build` in this directory. The static site itself needs no build step. React and fonts are bundled locally, without a CDN dependency. The two same-origin iframe documents isolate the original utility CSS from the existing deck. `animation-embed.js` accepts resize events only from the correct same-origin frame.

The request animation is on the existing solution slide. The two-band comparison follows on its own new slide. Both `/` and `/hackathon/` use the same seven-slide sequence. On small screens, diagram geometry remains fixed and pans horizontally; controls and narration fit the viewport. Reduced motion prevents autoplay.
