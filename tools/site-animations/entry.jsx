import React from 'react';
import {createRoot} from 'react-dom/client';
import VaultExplainerVideo from './source/VaultExplainerVideo.jsx';
import Comparison from './source/Comparison.tsx';
createRoot(document.getElementById('root')).render(document.body.dataset.animation==='comparison'?<Comparison/>:<VaultExplainerVideo/>);
new ResizeObserver(()=>parent.postMessage({type:'metavault-animation-height',animation:document.body.dataset.animation,height:document.getElementById("root").offsetHeight},location.origin)).observe(document.body);
