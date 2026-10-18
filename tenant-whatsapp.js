import fs from "node:fs";
import path from "node:path";
import { makeWASocket, useMultiFileAuthState, fetchLatestBaileysVersion, downloadContentFromMessage } from "@whiskeysockets/baileys";
import qrcode from "qrcode";
import { randomUUID } from "node:crypto";

export function createTenantWhatsApp(db) {
  const instances = new Map();
  const base = path.join(path.resolve(process.env.SESSION_DIR || "session"), "tenants");
  function archiveInvalidSession(dir) {
    const archive=path.join(dir,"_invalidated_"+Date.now());
    fs.mkdirSync(archive,{recursive:true});
    for(const entry of fs.readdirSync(dir,{withFileTypes:true})){
      if(entry.isFile()&&entry.name.endsWith(".json"))fs.renameSync(path.join(dir,entry.name),path.join(archive,entry.name));
    }
  }
  async function start(account) {
    const key = Number(account.id);
    if (instances.has(key)) {
      const current=instances.get(key);
      if(current.status==="sesion_cerrada"||current.status==="error"){stop(key)}
      else return current.status;
    }
    const item = {status:"iniciando",qr:null,socket:null,retry:null,stopped:false};
    instances.set(key,item);
    async function connect() {
      if(item.stopped)return;
      clearTimeout(item.retry);item.retry=null;
      item.status="iniciando";
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
            if(loggedOut){
             try{archiveInvalidSession(dir);item.status="reconectando";if(!item.stopped)item.retry=setTimeout(connect,1500)}
             catch(err){item.status="sesion_cerrada";console.error("Tenant session archive failed:",err)}
           }
           if(!loggedOut&&!item.stopped)item.retry=setTimeout(connect,5000);
          }
        });
        socket.ev.on("messages.upsert",async event=>{
          console.log("📥 Tenant WhatsApp upsert:",key,event.type,"cantidad:",event.messages?.length||0);
          for(const msg of event.messages||[]){
            try{
            if(!msg.message||msg.key.fromMe||msg.key.remoteJid==="status@broadcast")continue;
            if(msg.message.protocolMessage||msg.message.senderKeyDistributionMessage||msg.message.reactionMessage)continue;
            const numero=msg.key.remoteJidAlt?.endsWith("@s.whatsapp.net")?msg.key.remoteJidAlt:msg.key.remoteJid;
            let content=msg.message;
            for(let depth=0;depth<5;depth++){
              const nested=content.ephemeralMessage?.message||content.viewOnceMessageV2?.message||content.viewOnceMessage?.message||content.documentWithCaptionMessage?.message||content.viewOnceMessageV2Extension?.message;
              if(!nested)break;
              content=nested;
            }
            const texto=content.conversation||content.extendedTextMessage?.text||content.imageMessage?.caption||content.videoMessage?.caption||content.buttonsResponseMessage?.selectedDisplayText||content.listResponseMessage?.title||content.templateButtonReplyMessage?.selectedDisplayText||(content.imageMessage?"🖼️ Imagen":content.audioMessage?"🎵 Audio":content.videoMessage?"🎥 Video":content.documentMessage?"📄 Documento":"");
            if(!texto){console.warn("Tenant unsupported or undecrypted message",key,msg.key?.id,Object.keys(content));continue;}
            let mediaPath=null,mediaMime=null,mediaNombre=null;
            const media=content.imageMessage||content.videoMessage||content.audioMessage||content.documentMessage;
            if(media){
              const kind=content.imageMessage?"image":content.videoMessage?"video":content.audioMessage?"audio":"document";
              mediaMime=String(media.mimetype||"application/octet-stream").split(";")[0];
              mediaNombre=String(media.fileName||kind).slice(0,150);
              try{
                const stream=await downloadContentFromMessage(media,kind);
                const chunks=[];let size=0;
                for await(const chunk of stream){
                  size+=chunk.length;
                  if(size>30*1024*1024)throw new Error("El archivo supera 30 MB");
                  chunks.push(chunk);
                }
                const buffer=Buffer.concat(chunks);
                if(buffer?.length&&buffer.length<=30*1024*1024){
                  const mediaDir=path.join(base,String(account.tenant_id),String(key),"media");
                  fs.mkdirSync(mediaDir,{recursive:true,mode:0o700});
                  mediaPath=randomUUID();
                  fs.writeFileSync(path.join(mediaDir,mediaPath),buffer,{mode:0o600});
                }else console.warn("Tenant media omitted: empty or exceeds 30MB",key);
              }catch(err){console.error("Tenant media download failed:",key,err)}
            }
            try{
              await db.query("INSERT INTO crm_tenant_contactos(tenant_id,cuenta_id,numero,nombre) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,cuenta_id,numero) DO UPDATE SET nombre=COALESCE(NULLIF(EXCLUDED.nombre,''),crm_tenant_contactos.nombre)",[account.tenant_id,key,numero,msg.pushName||""]);
              await db.query("INSERT INTO crm_tenant_mensajes(tenant_id,cuenta_id,numero,texto,direccion,media_path,media_mime,media_nombre) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",[account.tenant_id,key,numero,texto,"recibido",mediaPath,mediaPath?mediaMime:null,mediaPath?mediaNombre:null]);
              console.log("✅ Tenant mensaje persistido:",account.tenant_id,key,msg.key?.id,mediaPath?"multimedia":"texto");
            }catch(e){console.error("Tenant message persistence:",e)}
            }catch(e){console.error("Tenant incoming message error:",key,msg?.key?.id,e)}
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
  async function sendMedia(id,numero,{kind,data,mimeType,fileName,caption}){
    const item=instances.get(Number(id));
    if(item?.status!=="conectado"||!item.socket)throw new Error("WhatsApp no conectado");
    const buffer=Buffer.from(data,"base64");
    if(!buffer.length||buffer.length>8*1024*1024)throw new Error("Archivo vacío o superior a 8 MB");
    const payload=kind==="image"?{image:buffer,mimetype:mimeType,caption:caption||""}:
      kind==="video"?{video:buffer,mimetype:mimeType,caption:caption||""}:
      kind==="audio"?{audio:buffer,mimetype:mimeType,ptt:false}:
      {document:buffer,mimetype:mimeType,fileName:fileName||"archivo"};
    await item.socket.sendMessage(numero,payload);
  }
  function stop(id){
    const item=instances.get(Number(id));if(!item)return;
    item.stopped=true;clearTimeout(item.retry);item.socket?.end?.(new Error("Detenido por administrador"));instances.delete(Number(id));
  }
  return {start,status,send,sendMedia,stop};
}
