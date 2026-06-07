"use strict";(()=>{var f=typeof browser<"u"?browser.runtime:chrome.runtime;console.log("[EU AV Wallet] Content script loaded");function u(){if(!navigator.credentials?.get?.bind(navigator.credentials)){console.log("[EU AV Wallet] Credential Management API not available");return}typeof globalThis.DigitalCredential>"u"&&console.log("[EU AV Wallet] Digital Credentials API not natively supported - extension will handle")}function y(){console.log("[EU AV Wallet] Setting up protocol handler and message listener"),document.addEventListener("click",e=>{let n=e.target.closest("a");n?.href?.startsWith("av://")&&(e.preventDefault(),x(n.href))},!0),window.addEventListener("message",e=>{e.data?.type?.startsWith("EU_AV")&&console.log("[EU AV Wallet] Received message:",e.data.type,e.data),e.source===window&&e.data?.type==="EU_AV_WALLET_REQUEST"&&v(e.data.payload,e.data.requestId)})}async function x(e){console.log("[EU AV Wallet] Handling av:// protocol:",e);try{let t=new URL(e.replace("av://","https://av.local/")),n=t.searchParams.get("credential_offer"),o=t.searchParams.get("request_uri");if(n){console.log("[EU AV Wallet] Credential offer received (issuance not yet implemented)"),h("Credential issuance is not yet supported in this wallet version.");return}o&&await b(o)}catch(t){console.error("[EU AV Wallet] Failed to handle av:// protocol:",t)}}async function b(e){try{let t=await fetch(e),n=new URLSearchParams(await t.text()),o={response_type:n.get("response_type"),response_mode:n.get("response_mode"),client_id:n.get("client_id"),response_uri:n.get("response_uri"),nonce:n.get("nonce"),state:n.get("state"),dcql_query:n.get("dcql_query")?JSON.parse(n.get("dcql_query")):null},i=await f.sendMessage({type:"PRESENT_CREDENTIAL",request:o});console.log("[EU AV Wallet] Presentation result:",i)}catch(t){console.error("[EU AV Wallet] Failed to handle presentation request:",t)}}async function v(e,t){console.log("[EU AV Wallet] Wallet request received:",e,"requestId:",t);try{let n=await f.sendMessage({type:"DC_API_REQUEST",request:e});if(console.log("[EU AV Wallet] Background response:",n),n.error){d(t,{error:n.error});return}let o=n.matchingCredentials||[];if(o.length===0){h("No matching credentials found in your wallet"),d(t,{response:null});return}let i=await E(o,e);if(!i){d(t,{cancelled:!0});return}let l=w(i,e);d(t,{response:l})}catch(n){console.error("[EU AV Wallet] Error handling wallet request:",n),d(t,{error:String(n)})}}function d(e,t){window.postMessage({type:"EU_AV_WALLET_RESPONSE",requestId:e,payload:t},"*")}function w(e,t){let n=t?.data?.nonce||crypto.randomUUID(),o={docType:e.docType,namespace:e.namespace,claims:e.claims,issuer:e.issuer,issuedAt:e.issuedAt,expiresAt:e.expiresAt};return{vp_token:JSON.stringify(o),presentation_submission:{id:crypto.randomUUID(),definition_id:"credential_presentation",descriptor_map:[{id:e.type+"_credential",format:"mso_mdoc",path:"$"}]},state:t?.data?.state,nonce:n}}function E(e,t){return new Promise(n=>{let o=document.createElement("div");o.id="eu-av-wallet-overlay",o.style.cssText=`
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 999999;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;let i=document.createElement("div");i.style.cssText=`
      background: linear-gradient(135deg, #1e1b4b 0%, #581c87 50%, #1e1b4b 100%);
      border-radius: 16px;
      padding: 24px;
      max-width: 400px;
      width: 90%;
      max-height: 80vh;
      overflow-y: auto;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      border: 1px solid rgba(168, 85, 247, 0.3);
    `;let l=document.createElement("div");l.style.cssText=`
      display: flex;
      align-items: center;
      margin-bottom: 20px;
      padding-bottom: 16px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    `,l.innerHTML=`
      <div style="width: 40px; height: 40px; background: linear-gradient(135deg, #6366f1, #7c3aed); border-radius: 10px; display: flex; align-items: center; justify-content: center; margin-right: 12px;">
        <svg width="20" height="20" fill="none" stroke="white" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      </div>
      <div>
        <h2 style="margin: 0; font-size: 18px; font-weight: 600; color: white;">EU AV Wallet</h2>
        <p style="margin: 4px 0 0; font-size: 12px; color: rgba(255,255,255,0.6);">Select a credential to share</p>
      </div>
    `,i.appendChild(l);let c=document.createElement("div");c.style.cssText=`
      background: rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 16px;
      font-size: 13px;
      color: rgba(255, 255, 255, 0.8);
    `,c.innerHTML=`
      <div style="color: rgba(255,255,255,0.5); font-size: 11px; margin-bottom: 4px;">Requesting site:</div>
      <div style="font-weight: 500;">${window.location.origin}</div>
    `,i.appendChild(c);let p=document.createElement("div");p.style.cssText=`
      display: flex;
      flex-direction: column;
      gap: 10px;
      margin-bottom: 16px;
    `,e.forEach(s=>{let r=document.createElement("button");r.style.cssText=`
        background: rgba(255, 255, 255, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.2);
        border-radius: 12px;
        padding: 14px;
        cursor: pointer;
        text-align: left;
        transition: all 0.2s;
        display: flex;
        align-items: center;
        gap: 12px;
      `;let g={mdl:"#60a5fa","national-id":"#34d399","proof-of-age":"#a78bfa"}[s.type]||"#818cf8";r.innerHTML=`
        <div style="width: 40px; height: 40px; background: ${g}33; border-radius: 10px; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
          <svg width="20" height="20" fill="none" stroke="${g}" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <div style="flex: 1; min-width: 0;">
          <div style="font-weight: 500; color: white; font-size: 14px;">${s.displayName}</div>
          <div style="font-size: 12px; color: rgba(255,255,255,0.5); margin-top: 2px;">${s.issuer}</div>
        </div>
        <svg width="20" height="20" fill="none" stroke="rgba(255,255,255,0.4)" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
        </svg>
      `,r.addEventListener("mouseenter",()=>{r.style.background="rgba(255, 255, 255, 0.15)",r.style.borderColor="rgba(168, 85, 247, 0.5)"}),r.addEventListener("mouseleave",()=>{r.style.background="rgba(255, 255, 255, 0.1)",r.style.borderColor="rgba(255, 255, 255, 0.2)"}),r.addEventListener("click",()=>{o.remove(),n(s)}),p.appendChild(r)}),i.appendChild(p);let a=document.createElement("button");a.textContent="Cancel",a.style.cssText=`
      width: 100%;
      padding: 12px;
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.2);
      border-radius: 8px;
      color: white;
      font-size: 14px;
      cursor: pointer;
      transition: all 0.2s;
    `,a.addEventListener("mouseenter",()=>{a.style.background="rgba(255, 255, 255, 0.15)"}),a.addEventListener("mouseleave",()=>{a.style.background="rgba(255, 255, 255, 0.1)"}),a.addEventListener("click",()=>{o.remove(),n(null)}),i.appendChild(a),o.addEventListener("click",s=>{s.target===o&&(o.remove(),n(null))}),o.appendChild(i),document.body.appendChild(o)})}function h(e){let t=document.createElement("div");t.style.cssText=`
    position: fixed;
    bottom: 20px;
    right: 20px;
    padding: 12px 20px;
    background: #7c3aed;
    color: white;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    z-index: 999999;
    animation: slideIn 0.3s ease;
  `,t.textContent=e,document.body.appendChild(t),setTimeout(()=>{t.style.animation="slideOut 0.3s ease",setTimeout(()=>t.remove(),300)},3e3)}function m(){let e=document.createElement("style");e.textContent=`
    @keyframes slideIn {
      from { transform: translateX(100%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
      from { transform: translateX(0); opacity: 1; }
      to { transform: translateX(100%); opacity: 0; }
    }
  `,document.head?document.head.appendChild(e):document.addEventListener("DOMContentLoaded",()=>{document.head.appendChild(e)})}y();document.readyState==="loading"?document.addEventListener("DOMContentLoaded",()=>{m(),u()}):(m(),u());})();
