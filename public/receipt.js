(function(){
"use strict";

const API_BASE = "https://mpeb-license-api.onrender.com";

function getDeviceId(){
  let id = localStorage.getItem("mpeb_install_id");
  if(!id){
    id = (crypto.randomUUID ? crypto.randomUUID() :
      "mpeb-"+Date.now()+"-"+Math.random().toString(36).slice(2)+Math.random().toString(36).slice(2));
    localStorage.setItem("mpeb_install_id",id);
  }
  return id;
}

async function validate(){
  const token = localStorage.getItem("mpeb_license_token");
  if(!token) return false;

  const r = await fetch(API_BASE + "/api/validate", {
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({
      token:token,
      device_id:getDeviceId()
    })
  });

  if(!r.ok) return false;
  const d = await r.json();
  return !!d.success;
}

async function main(){
  try{
    if(!(await validate())){
      const key = prompt(
        "MPEB Receipt License Key required.\n\nEnter your license key:"
      );

      if(!key) return;

      const r = await fetch(API_BASE + "/api/activate",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({
          key:key,
          device_id:getDeviceId()
        })
      });

      const d = await r.json();

      if(!r.ok || !d.success){
        alert(d.error || "License activation failed.");
        return;
      }

      localStorage.setItem("mpeb_license_token",d.token);
    }

    printReceipt();
  }catch(e){
    console.error(e);
    alert("License server unavailable. Please try again.");
  }
}

function esc(v){
  return String(v ?? "N/A")
    .replace(/&/g,"&amp;")
    .replace(/</g,"&lt;")
    .replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;")
    .replace(/'/g,"&#039;");
}

function text(id){
  return document.getElementById(id)?.innerText?.trim() || "N/A";
}

function printReceipt(){
  const i=text("rcptConsumerId");
  const n=text("rcptConsumerName");
  const t=text("rcptTxnId");
  const tm=text("rcptTime");
  const m=text("rcptBillMonth");
  const a=text("rcptTotalPaid");

  let p="K20240805807035";

  document.querySelectorAll("strong").forEach(e=>{
    if(e.innerText && e.innerText.includes("K2024")){
      p=e.innerText.trim();
    }
  });

  const h=`
  <table style="width:100%;border-collapse:collapse;font-family:Arial;font-size:12px;">
    <tr><td style="border:1px solid #000;padding:2px 5px;font-weight:bold;">Channel Id.</td><td style="border:1px solid #000;padding:2px 5px;">${esc(p)}</td></tr>
    <tr><td style="border:1px solid #000;padding:2px 5px;font-weight:bold;width:40%;">Consumer IVRS</td><td style="border:1px solid #000;padding:2px 5px;">${esc(i)}</td></tr>
    <tr><td style="border:1px solid #000;padding:2px 5px;font-weight:bold;">Txn ID</td><td style="border:1px solid #000;padding:2px 5px;">${esc(t)}</td></tr>
    <tr><td style="border:1px solid #000;padding:2px 5px;font-weight:bold;">Name</td><td style="border:1px solid #000;padding:2px 5px;">${esc(n)}</td></tr>
    <tr><td style="border:1px solid #000;padding:2px 5px;font-weight:bold;">Month</td><td style="border:1px solid #000;padding:2px 5px;">${esc(m)}</td></tr>
    <tr><td style="border:1px solid #000;padding:2px 5px;font-weight:bold;">Amount</td><td style="border:1px solid #000;padding:2px 5px;">${esc(a)}</td></tr>
    <tr><td style="border:1px solid #000;padding:2px 5px;font-weight:bold;">Date</td><td style="border:1px solid #000;padding:2px 5px;">${esc(tm)}</td></tr>
    <tr><td style="border:1px solid #000;padding:2px 5px;font-weight:bold;">Status</td><td style="border:1px solid #000;padding:2px 5px;color:green;">Success</td></tr>
    <!--tr><td style="border:1px solid #000;padding:2px 5px;font-weight:bold;">KOSHTA COMPUTERS</td><td style="border:1px solid #000;padding:2px 5px;">Mo.6261728996</td></tr-->
  </table>`;

  const w=window.open("","_blank","width=800,height=600");
  if(!w){
    alert("Print window blocked. Please allow pop-ups for the MPEB website.");
    return;
  }

  w.document.write("<html><head><title>Print Receipt</title><style>@page{margin:5mm}body{margin:0;padding:5px;font-family:Arial}</style></head><body>"+h+"</body></html>");
  w.document.close();

  setTimeout(()=>{
    w.focus();
    w.print();
  },500);
}

main();
})();
