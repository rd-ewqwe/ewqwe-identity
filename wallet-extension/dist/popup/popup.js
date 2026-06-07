"use strict";(()=>{var f={mdl:{docType:"org.iso.18013.5.1.mDL",namespace:"org.iso.18013.5.1",displayName:"Mobile Driver's License",description:"ISO 18013-5 compliant driving license",color:"#2563eb"},"national-id":{docType:"eu.europa.ec.eudi.pid.1",namespace:"eu.europa.ec.eudi.pid.1",displayName:"EU Person Identification Data",description:"EU Digital Identity Wallet PID",color:"#059669"},"proof-of-age":{docType:"eu.europa.ec.av.1",namespace:"eu.europa.ec.av.1",displayName:"Proof of Age",description:"EU Age Verification attestation",color:"#7c3aed"}};var d=typeof browser<"u"?browser.runtime:chrome.runtime,c=[],C="all",m=null,u=null;async function v(){x(),await p(),D(),o(),u&&h(u)}function x(){let t=new URLSearchParams(window.location.search).get("av");t&&(u=decodeURIComponent(t),console.log("[Wallet] Opened via av:// protocol:",u))}function h(e){try{let t=new URL(e.replace("web+av://","https://av.local/")),s=t.pathname.replace("/","")||t.hostname,a=t.searchParams.get("type"),n=t.searchParams.get("claims"),i=n?n.split(","):[],r=t.searchParams.get("return");console.log("[Wallet] AV Protocol Request:",{requestType:s,type:a,claims:i,returnUrl:r}),a&&T(a);let l=document.querySelector(".header h1");l&&(l.innerHTML='<span class="text-purple-400">\u{1F510}</span> Credential Request');let g=document.querySelector(".container");if(g){let y=document.createElement("div");y.className="bg-purple-900/50 border border-purple-500/30 rounded-lg p-3 mb-4 text-sm",y.innerHTML=`
        <div class="text-purple-200 font-medium mb-1">Age Verification Request</div>
        <div class="text-slate-300">
          ${a?`Type: <span class="text-purple-300">${a}</span>`:""}
          ${i.length?`<br>Claims: <span class="text-purple-300">${i.join(", ")}</span>`:""}
        </div>
      `,g.insertBefore(y,g.firstChild?.nextSibling||null)}}catch(t){console.error("[Wallet] Failed to parse av:// URI:",t)}}async function p(){let e=await d.sendMessage({type:"GET_CREDENTIALS"});c=e.credentials||[],L(e.counts)}function L(e){document.getElementById("count-mdl").textContent=String(e.mdl||0),document.getElementById("count-pid").textContent=String(e["national-id"]||0),document.getElementById("count-poa").textContent=String(e["proof-of-age"]||0)}function D(){document.querySelectorAll(".tab-btn").forEach(e=>{e.addEventListener("click",t=>{let s=t.target.dataset.tab;T(s)})}),document.getElementById("reset-btn")?.addEventListener("click",async()=>{confirm("Reset wallet to sample credentials?")&&(await d.sendMessage({type:"RESET_CREDENTIALS"}),await p(),o())}),document.getElementById("load-samples-btn")?.addEventListener("click",async()=>{await d.sendMessage({type:"RESET_CREDENTIALS"}),await p(),o()}),document.getElementById("modal-close")?.addEventListener("click",E),document.getElementById("credential-modal")?.addEventListener("click",e=>{e.target===e.currentTarget&&E()}),document.getElementById("modal-delete")?.addEventListener("click",async()=>{m&&confirm("Delete this credential?")&&(await d.sendMessage({type:"DELETE_CREDENTIAL",id:m.id}),E(),await p(),o())})}function T(e){C=e,document.querySelectorAll(".tab-btn").forEach(t=>{t.dataset.tab===e?t.classList.add("active"):t.classList.remove("active")}),o()}function o(){let e=document.getElementById("credentials-list"),t=document.getElementById("empty-state"),s=C==="all"?c:c.filter(a=>a.type===C);if(s.length===0){e.innerHTML="",t.classList.remove("hidden");return}t.classList.add("hidden"),e.innerHTML=s.map(b).join(""),e.querySelectorAll(".credential-card").forEach(a=>{a.addEventListener("click",n=>{let i=n.currentTarget.dataset.id,r=c.find(l=>l.id===i);r&&I(r)})})}function b(e){let t=f[e.type],s=new Date(e.expiresAt)<new Date,a=new Date(e.expiresAt).toLocaleDateString(),n={mdl:"bg-blue-500\\/20","national-id":"bg-green-500\\/20","proof-of-age":"bg-purple-500\\/20"}[e.type],i={mdl:"text-blue-400","national-id":"text-green-400","proof-of-age":"text-purple-400"}[e.type],r={mdl:'<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V8a2 2 0 00-2-2h-5m-4 0V5a2 2 0 114 0v1m-4 0a2 2 0 104 0m-5 8a2 2 0 100-4 2 2 0 000 4zm0 0c1.306 0 2.417.835 2.83 2M9 14a3.001 3.001 0 00-2.83 2M15 11h3m-3 4h2" />',"national-id":'<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />',"proof-of-age":'<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />'}[e.type];return`
    <div class="credential-card cursor-pointer p-3"
         data-id="${e.id}">
      <div class="flex items-start gap-3">
        <div class="w-10 h-10 rounded-lg ${n} flex items-center justify-center">
          <svg class="w-5 h-5 ${i}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            ${r}
          </svg>
        </div>
        <div class="flex-1 min-w-0">
          <div class="flex items-center gap-2">
            <h3 class="font-medium text-sm truncate text-white">${e.displayName}</h3>
            ${s?'<span class="px-1.5 py-0.5 text-xs bg-red-500\\/20 text-red-400 rounded">Expired</span>':""}
          </div>
          <p class="text-xs text-gray-400 truncate">${e.issuer}</p>
          <p class="text-xs text-gray-500 mt-1">Expires: ${a}</p>
        </div>
        <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
        </svg>
      </div>
    </div>
  `}function I(e){m=e;let t=f[e.type];document.getElementById("modal-title").textContent=e.displayName,document.getElementById("modal-issuer").textContent=e.issuer;let s=Object.entries(e.claims).filter(([a,n])=>n!=null).map(([a,n])=>{let i;return typeof n=="boolean"?i=n?"\u2713 Yes":"\u2717 No":Array.isArray(n)?i=n.map(r=>typeof r=="object"?JSON.stringify(r):String(r)).join(", "):typeof n=="object"?i=JSON.stringify(n):i=String(n),`
        <div class="claim-row">
          <span class="claim-label">${w(a)}</span>
          <span class="claim-value" title="${i}">
            ${i}
          </span>
        </div>
      `}).join("");document.getElementById("modal-content").innerHTML=`
    <div class="modal-info-box">
      <div class="modal-info-row">
        <span>Type</span>
        <span class="font-mono">${t.displayName}</span>
      </div>
      <div class="modal-info-row">
        <span>DocType</span>
        <span class="font-mono text-xs">${e.docType}</span>
      </div>
    </div>
    <h4 class="claims-heading">Claims</h4>
    ${s}
  `,document.getElementById("credential-modal").classList.remove("hidden")}function E(){m=null,document.getElementById("credential-modal").classList.add("hidden")}function w(e){return e.replace(/_/g," ").replace(/\b\w/g,t=>t.toUpperCase())}document.addEventListener("DOMContentLoaded",v);})();
