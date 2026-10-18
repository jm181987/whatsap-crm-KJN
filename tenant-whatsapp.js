import fs from "node:fs";
import path from "node:path";
import { makeWASocket, useMultiFileAuthState, fetchLatestBaileysVersion } from "@whiskeysockets/baileys";
import qrcode from "qrcode";

export function createTenantWhatsApp(db) {
  const instances = new Map();
  const base = path.resolve(process.env.SESSION_DIR || "session") + "-tenants";
  async function start(account) {
    const key = Number(account.id);
    if (instances.has(key)) return instances.get(key).status;
    const item = {status:"iniciando",qr:null,socket:null,retry:null,stopped:false};
    instances.set(key,item);
    async function connect() {
      if(item.stopped)return;
      try {
        const dir=path.join(base,String(account.tenant_id),String(key));
        fs.mkdirSync(dir,{recursive:true});
        const {state,saveCreds}=await useMultiFileAuthState(dir);
        const {version}=await fetchLatestBaileysVersion();
        const socket=makeWASocket({version,auth:state,printQRInTerminal:false,syncFullHistory:false});
        item.socket=socket;
        socket.ev.on("creds.update",saveCreds);
        socket.ev.on("connection.update",update=>{
          if(item.stopped||item.socket!==socket)return;
          if(update.qr){qrcode.toDataURL(update.qr).then(data=>{if(!item.stopped&&item.socket===socket){item.qr=data;item.status="qr"}}).catch(e=>console.error("Tenant QR:",e))}
          if(update.connection==="open"){item.qr=null;item.status="conectado";}
          if(update.connection==="close"){
            item.socket=null;item.qr=null;
            const loggedOut=update.lastDisconnect?.error?.output?.statusCode===401;
            item.status=loggedOut?"sesion_cerrada":"desconectado";
            if(!loggedOut&&!item.stopped)item.retry=setTimeout(connect,5000);
          }
        });
        socket.ev.on("messages.upsert",async event=>{
          for(const msg of event.messages||[]){
            if(!msg.message||msg.key.fromMe||msg.key.remoteJid==="status@broadcast")continue;
            const numero=msg.key.remoteJid;
            const texto=msg.message.conversation||msg.message.extendedTextMessage?.text||"";
            try{
              await db.query("INSERT INTO crm_tenant_contactos(tenant_id,cuenta_id,numero,nombre) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,cuenta_id,numero) DO UPDATE SET nombre=COALESCE(NULLIF(EXCLUDED.nombre,''),crm_tenant_contactos.nombre)",[account.tenant_id,key,numero,msg.pushName||""]);
              await db.query("INSERT INTO crm_tenant_mensajes(tenant_id,cuenta_id,numero,texto,direccion) VALUES($1,$2,$3,$4,$5)",[account.tenant_id,key,numero,texto,"recibido"]);
            }catch(e){console.error("Tenant message persistence:",e)}
          }
        });
      }catch(e){item.status="error";console.error("Tenant WhatsApp startup:",e);if(!item.stopped)item.retry=setTimeout(connect,10000)}
    }
    await connect();
    return item.status;
  }
  function status(id){const item=instances.get(Number(id));return {estado:item?.status||"no_iniciada",qr:item?.qr||null}}
  async function send(id,numero,texto){
    const item=instances.get(Number(id));
    if(item?.status!=="conectado"||!item.socket)throw new Error("WhatsApp no conectado");
    await item.socket.sendMessage(numero,{text:texto});
  }
  function stop(id){
    const item=instances.get(Number(id));if(!item)return;
    item.stopped=true;clearTimeout(item.retry);item.socket?.end?.(new Error("Detenido por administrador"));instances.delete(Number(id));
  }
  return {start,status,send,stop};
}
