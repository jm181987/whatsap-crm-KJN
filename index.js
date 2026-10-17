import { execFile } from "node:child_process";
import { promisify } from "node:util";
import express from "express";
import cors from 'cors';

import {
  makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  downloadContentFromMessage
} from "@whiskeysockets/baileys";

import qrcode from "qrcode";
import fs from "fs";
import multer from "multer";
import { db, initDatabase } from "./postgres.js";
import http from "http";
import { timingSafeEqual } from "node:crypto";
import path from "path";
import { fileURLToPath } from "url";
import { Parser } from "json2csv";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const allowedOrigins = (process.env.CORS_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({ origin: allowedOrigins.length ? allowedOrigins : false }));
const server = http.createServer(app);

// Require an explicit access password before serving the CRM or its API.
const crmUser = process.env.CRM_USER;
const crmPassword = process.env.CRM_PASSWORD;
if (!crmUser || !crmPassword) throw new Error("Configure CRM_USER y CRM_PASSWORD en Coolify");
function secureEqual(a, b) {
  const aa = Buffer.from(a), bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
app.use((req, res, next) => {
  const header = req.headers.authorization || "";
  if (header.startsWith("Basic ")) {
    try {
      const decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
      const separator = decoded.indexOf(":");
      if (separator !== -1 && secureEqual(decoded.slice(0, separator), crmUser) && secureEqual(decoded.slice(separator + 1), crmPassword)) return next();
    } catch {}
  }
  res.setHeader("WWW-Authenticate", 'Basic realm="KNJ WhatsApp CRM"');
  res.setHeader("Cache-Control", "no-store");
  return res.status(401).send("Autenticación requerida");
});
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Crear directorios necesarios si no existen
const directories = ['public', 'public/audios', 'public/imagenes', 'public/archivos', 'public/videos', process.env.SESSION_DIR || 'session'];
directories.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

await initDatabase();

let sock;


/* ========================================================
   CONFIGURACIÓN MULTER PARA ARCHIVOS
======================================================== */
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let folder = 'public/archivos/';
    
    if (file.mimetype.startsWith('audio/')) {
      folder = 'public/audios/';
    } else if (file.mimetype.startsWith('image/')) {
      folder = 'public/imagenes/';
    } else if (file.mimetype.startsWith('video/')) {
      folder = 'public/videos/';
    }
    
    cb(null, folder);
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    const extension = path.extname(file.originalname);
    let prefix = 'archivo';
    
    if (file.mimetype.startsWith('audio/')) {
      prefix = 'audio';
    } else if (file.mimetype.startsWith('image/')) {
      prefix = 'imagen';
    } else if (file.mimetype.startsWith('video/')) {
      prefix = 'video';
    }
    
    const fileName = `${prefix}_${timestamp}${extension}`;
    cb(null, fileName);
  }
});

const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB limit
  }
});

/* ========================================================
   SUBIR CONTACTOS DESDE ARCHIVO
======================================================== */

app.post("/subir-contactos", upload.single('archivo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No se subió ningún archivo" });
    }

    const filePath = req.file.path;
    const fileContent = fs.readFileSync(filePath, 'utf8');
    
    // Limpiar archivo temporal
    fs.unlinkSync(filePath);

    // Procesar números del archivo
    const lineas = fileContent.split('\n');
    const numerosUnicos = new Set();
    
    lineas.forEach(linea => {
      const numerosEnLinea = linea.match(/\d+/g);
      if (numerosEnLinea) {
        numerosEnLinea.forEach(num => {
          if (num.length >= 10) {
            let numeroFormateado = num;
            if (num.length === 10) {
              numeroFormateado = '52' + num; // Asumir México
            }
            numerosUnicos.add(numeroFormateado + '@s.whatsapp.net');
          }
        });
      }
    });

    const numeros = Array.from(numerosUnicos);
    let nuevos = 0;
    let existentes = 0;
    let errores = 0;

    // Procesar cada número
    for (const numero of numeros) {
      try {
        // Verificar si ya existe
        db.get("SELECT * FROM clientes WHERE numero = ?", [numero], (err, row) => {
          if (err) {
            console.error(`Error verificando ${numero}:`, err);
            errores++;
            return;
          }

          if (!row) {
            // Crear nuevo contacto con etiqueta "nuevo"
            const nuevoCliente = {
              numero: numero,
              nombre: numero.replace('@s.whatsapp.net', ''),
              etiqueta: 'nuevo',
              nota: '',
              archivado: 0,
              ultima_interaccion: new Date().toISOString()
            };

            db.run(
              `INSERT INTO clientes (numero, nombre, etiqueta, nota, archivado, ultima_interaccion) 
               VALUES (?, ?, ?, ?, ?, ?)`,
              [nuevoCliente.numero, nuevoCliente.nombre, nuevoCliente.etiqueta, 
               nuevoCliente.nota, nuevoCliente.archivado, nuevoCliente.ultima_interaccion],
              function(insertErr) {
                if (insertErr) {
                  console.error(`Error creando ${numero}:`, insertErr);
                  errores++;
                } else {
                  nuevos++;
                  console.log(`✅ Nuevo contacto: ${numero}`);
                }
              }
            );
          } else {
            existentes++;
          }
        });

      } catch (error) {
        console.error(`Error procesando ${numero}:`, error);
        errores++;
      }
    }

    // Esperar a que se completen las operaciones de BD
    await new Promise(resolve => setTimeout(resolve, 3000));

    res.json({
      success: true,
      resumen: {
        total: numeros.length,
        nuevos: nuevos,
        existentes: existentes,
        errores: errores
      },
      mensaje: `Contactos procesados: ${nuevos} nuevos, ${existentes} existentes, ${errores} errores`
    });

  } catch (error) {
    console.error('Error subiendo contactos:', error);
    res.status(500).json({
      success: false,
      error: 'Error procesando archivo: ' + error.message
    });
  }
});

/* ========================================================
   ENVÍO A LISTA ESPECÍFICA DE CONTACTOS
======================================================== */

app.post("/enviar-lista-contactos", async (req, res) => {
  try {
    const { numeros, mensaje } = req.body;

    if (!sock) {
      return res.status(500).json({ error: "WhatsApp no conectado" });
    }

    if (!numeros || !Array.isArray(numeros) || numeros.length === 0) {
      return res.status(400).json({ error: "Lista de números requerida" });
    }

    if (!mensaje) {
      return res.status(400).json({ error: "Mensaje requerido" });
    }

    let exitosos = 0;
    let errores = 0;
    const detalles = [];

    for (const numero of numeros) {
      try {
        console.log(`📋 Procesando número: ${numero}`);

        // 1. VERIFICAR SI EL CONTACTO EXISTE
        db.get("SELECT * FROM clientes WHERE numero = ?", [numero], async (err, row) => {
          if (err) {
            console.error(`❌ Error verificando contacto ${numero}:`, err);
            errores++;
            detalles.push({ numero, estado: "error", error: "Error en BD" });
            return;
          }

          // 2. SI NO EXISTE, CREARLO CON ETIQUETA "nuevo"
          if (!row) {
            console.log(`🆕 Creando nuevo contacto: ${numero}`);
            
            const nuevoCliente = {
              numero: numero,
              nombre: numero.replace('@s.whatsapp.net', ''),
              etiqueta: 'nuevo', // ← ESTA ES LA CLAVE
              nota: '',
              archivado: 0,
              ultima_interaccion: new Date().toISOString()
            };

            db.run(
              `INSERT INTO clientes (numero, nombre, etiqueta, nota, archivado, ultima_interaccion) 
               VALUES (?, ?, ?, ?, ?, ?)`,
              [nuevoCliente.numero, nuevoCliente.nombre, nuevoCliente.etiqueta, 
               nuevoCliente.nota, nuevoCliente.archivado, nuevoCliente.ultima_interaccion],
              function(insertErr) {
                if (insertErr) {
                  console.error(`❌ Error creando contacto ${numero}:`, insertErr);
                  errores++;
                  detalles.push({ numero, estado: "error", error: "Error creando contacto" });
                } else {
                  console.log(`✅ Contacto creado: ${numero}`);
                  // Continuar con el envío del mensaje
                  enviarMensajeYRegistrar(numero, mensaje);
                }
              }
            );
          } else {
            // 3. SI YA EXISTE, SOLO ENVIAR MENSAJE
            console.log(`✅ Contacto existente: ${numero} (etiqueta: ${row.etiqueta})`);
            enviarMensajeYRegistrar(numero, mensaje);
          }
        });

        // Función auxiliar para enviar mensaje y registrar
        const enviarMensajeYRegistrar = async (numero, mensaje) => {
          try {
            await sock.sendMessage(numero, { text: mensaje });
            exitosos++;

            // Guardar mensaje en base de datos
            const fecha = new Date().toISOString();
            guardarMensajeEnDB(numero, mensaje, 'enviado', fecha, null, null, 0);

            detalles.push({ numero, estado: "enviado" });
            console.log(`✅ Mensaje enviado a: ${numero}`);

          } catch (e) {
            console.error(`❌ Error enviando a ${numero}:`, e.message);
            errores++;
            detalles.push({ numero, estado: "error", error: e.message });
          }
        };

        // Pequeña pausa para evitar bloqueos
        await new Promise(resolve => setTimeout(resolve, 500));

      } catch (e) {
        console.error(`❌ Error general con ${numero}:`, e.message);
        errores++;
        detalles.push({ numero, estado: "error", error: e.message });
      }
    }

    // Esperar un poco para que se completen las operaciones de BD
    await new Promise(resolve => setTimeout(resolve, 2000));

    res.json({
      success: true,
      resumen: {
        total: numeros.length,
        exitosos: exitosos,
        errores: errores
      },
      detalles: detalles,
      mensaje: `Procesados ${numeros.length} números: ${exitosos} exitosos, ${errores} errores`
    });

  } catch (error) {
    console.error('❌ Error en envío a lista de contactos:', error);
    res.status(500).json({
      success: false,
      error: 'Error interno del servidor: ' + error.message
    });
  }
});

// ... (tus otros endpoints existentes continúan aquí)

/* ========================================================
   INICIAR WHATSAPP
======================================================== */
async function iniciarWhatsApp() {
  try {
    const { state, saveCreds } = await useMultiFileAuthState(process.env.SESSION_DIR || "session");
    const { version } = await fetchLatestBaileysVersion();

    sock = makeWASocket({
      version,
      auth: state,
      printQRInTerminal: true,
      browser: ["Chrome", "Windows", "10.0"],
      syncFullHistory: false,
      markOnlineOnConnect: true,
      defaultQueryTimeoutMs: 60000
    });

    sock.ev.on("creds.update", saveCreds);

    sock.ev.on("connection.update", async (update) => {
      const { connection, qr, lastDisconnect } = update;

      if (qr) {
        try {
          const qrData = await qrcode.toDataURL(qr);
          fs.writeFileSync("public/qr.json", JSON.stringify({ qr: qrData }));
          console.log("📱 Escanea el QR para conectar WhatsApp.");
        } catch (error) {
          console.error("Error generando QR:", error);
        }
      }

      if (connection === "open") {
        try {
          if (fs.existsSync("public/qr.json")) fs.unlinkSync("public/qr.json");
          console.log("✅ Conectado a WhatsApp");
          await sincronizarChats();
        } catch (error) {
          console.error("Error eliminando QR:", error);
        }
      }

      if (connection === "close") {
        const reason = lastDisconnect?.error?.output?.statusCode;
        console.log("⚠️ Conexión cerrada:", reason);
        if (reason !== 401) {
          setTimeout(iniciarWhatsApp, 5000);
        } else {
          console.log("❌ Sesión inválida, borra la carpeta /session y reconecta.");
        }
      }
    });

    // Configurar manejo de mensajes
    configurarManejoMensajes();

  } catch (error) {
    console.error("Error iniciando WhatsApp:", error);
    setTimeout(iniciarWhatsApp, 10000);
  }
}

/* ========================================================
   MANEJO DE MENSAJES
======================================================== */

function phoneKey(jid) {
  const value = String(jid || '');
  if (!value.endsWith('@s.whatsapp.net') && !value.endsWith('@c.us')) return null;
  return value.split('@')[0].split(':')[0].replace(/\\D/g, '');
}

async function resolveConversationJid(jid, alternativeJid) {
  const candidates = [jid, alternativeJid].filter(Boolean);
  for (const candidate of candidates) {
    const existing = await db.query('SELECT numero FROM clientes WHERE numero = $1 LIMIT 1', [candidate]);
    if (existing.length) return existing[0].numero;
  }
  const phones = candidates.map(phoneKey).filter(Boolean);
  if (phones.length) {
    const existing = await db.query("SELECT numero FROM clientes WHERE numero LIKE '%@s.whatsapp.net' OR numero LIKE '%@c.us'");
    const match = existing.find(row => phones.includes(phoneKey(row.numero)));
    if (match) return match.numero;
  }
  return alternativeJid && phoneKey(alternativeJid) ? alternativeJid : jid;
}

function configurarManejoMensajes() {
  
  sock.ev.on("messages.upsert", async (m) => {
    try {
      if (!m.messages || m.messages.length === 0) return;

      for (const msg of m.messages) {
      
      // Ignorar mensajes propios y estados
      if (msg.key.fromMe || !msg.message || msg.key.remoteJid === "status@broadcast") continue;

      // WhatsApp may wrap incoming media in ephemeral/view-once containers.
      const wrapped = msg.message.ephemeralMessage?.message
        || msg.message.viewOnceMessageV2?.message
        || msg.message.viewOnceMessage?.message
        || msg.message.documentWithCaptionMessage?.message;
      if (wrapped) msg.message = wrapped;
      const numero = await resolveConversationJid(msg.key.remoteJid, msg.key.remoteJidAlt);
      const contacto = msg.pushName || "Desconocido";
      const fecha = new Date().toISOString();

      console.log("📨 Mensaje recibido de:", contacto, "Tipo:", Object.keys(msg.message)[0]);

      // Manejar mensajes de audio
      if (msg.message.audioMessage) {
        await procesarMensajeAudio(msg, numero, contacto, fecha);
        continue;
      }

      // Manejar mensajes de imagen
      if (msg.message.imageMessage) {
        await procesarMensajeImagen(msg, numero, contacto, fecha);
        continue;
      }

      // Manejar mensajes de video
      if (msg.message.videoMessage) {
        await procesarMensajeVideo(msg, numero, contacto, fecha);
        continue;
      }

      // Manejar mensajes de documento
      if (msg.message.documentMessage) {
        await procesarMensajeDocumento(msg, numero, contacto, fecha);
        continue;
      }

      // Manejar mensajes de texto
      await procesarMensajeTexto(msg, numero, contacto, fecha);
      }

    } catch (error) {
      console.error("Error procesando mensaje:", error);
    }
  });
}

/* ========================================================
   FUNCIONES PARA PROCESAR MENSAJES
======================================================== */

async function procesarMensajeAudio(msg, numero, contacto, fecha) {
  try {
    console.log("🎵 Procesando audio recibido...");
    
    const audioMessage = msg.message.audioMessage;
    
    // Descargar el audio
    const stream = await downloadContentFromMessage(audioMessage, "audio");
    let buffer = Buffer.from([]);
    for await (const chunk of stream) {
      buffer = Buffer.concat([buffer, chunk]);
    }

    // Guardar archivo
    const fileName = `audio_${Date.now()}.ogg`;
    const filePath = `public/audios/${fileName}`;
    fs.writeFileSync(filePath, buffer);

    console.log("✅ Audio guardado:", fileName);

    // Guardar en base de datos
    const mensajeTexto = audioMessage.caption || "🎵 Audio";
    await guardarMensajeEnDB(numero, mensajeTexto, 'recibido', fecha, `/audios/${fileName}`, 'audio/ogg', 1);
    
    actualizarCliente(numero, contacto, fecha);
    crearNotificacion(numero, contacto, "🎵 Audio", fecha);

  } catch (error) {
    console.error("❌ Error procesando audio:", error);
    try {
      await guardarMensajeEnDB(numero, "🎵 Audio (archivo no disponible)", 'recibido', fecha, null, 'audio/ogg', 1);
      actualizarCliente(numero, contacto, fecha);
      crearNotificacion(numero, contacto, "🎵 Audio (archivo no disponible)", fecha);
    } catch (dbError) { console.error("Error registrando multimedia sin archivo:", dbError); }
  }
}

async function procesarMensajeImagen(msg, numero, contacto, fecha) {
  try {
    console.log("🖼️ Procesando imagen recibida...");
    
    const imageMessage = msg.message.imageMessage;
    
    // Descargar la imagen
    const stream = await downloadContentFromMessage(imageMessage, "image");
    let buffer = Buffer.from([]);
    for await (const chunk of stream) {
      buffer = Buffer.concat([buffer, chunk]);
    }

    // Guardar archivo
    const extension = (imageMessage.mimetype || 'image/jpeg').split('/')[1] || 'jpg';
    const fileName = `imagen_${Date.now()}.${extension}`;
    const filePath = `public/imagenes/${fileName}`;
    fs.writeFileSync(filePath, buffer);

    console.log("✅ Imagen guardada:", fileName);

    // Guardar en base de datos
    const mensajeTexto = imageMessage.caption || "🖼️ Imagen";
    guardarMensajeEnDB(numero, mensajeTexto, 'recibido', fecha, `/imagenes/${fileName}`, imageMessage.mimetype, 1);
    
    actualizarCliente(numero, contacto, fecha);
    crearNotificacion(numero, contacto, "🖼️ Imagen", fecha);

  } catch (error) {
    console.error("❌ Error procesando imagen:", error);
  }
}

async function procesarMensajeVideo(msg, numero, contacto, fecha) {
  try {
    console.log("🎥 Procesando video recibido...");
    
    const videoMessage = msg.message.videoMessage;
    
    // Descargar el video
    const stream = await downloadContentFromMessage(videoMessage, "video");
    let buffer = Buffer.from([]);
    for await (const chunk of stream) {
      buffer = Buffer.concat([buffer, chunk]);
    }

    // Guardar archivo
    const extension = (videoMessage.mimetype || 'video/mp4').split('/')[1] || 'mp4';
    const fileName = `video_${Date.now()}.${extension}`;
    const filePath = `public/videos/${fileName}`;
    fs.writeFileSync(filePath, buffer);

    console.log("✅ Video guardado:", fileName);

    // Guardar en base de datos
    const mensajeTexto = videoMessage.caption || "🎥 Video";
    await guardarMensajeEnDB(numero, mensajeTexto, 'recibido', fecha, `/videos/${fileName}`, videoMessage.mimetype, 1);
    
    actualizarCliente(numero, contacto, fecha);
    crearNotificacion(numero, contacto, "🎥 Video", fecha);

  } catch (error) {
    console.error("❌ Error procesando video:", error);
    try {
      await guardarMensajeEnDB(numero, "🎥 Video (archivo no disponible)", 'recibido', fecha, null, 'video/mp4', 1);
      actualizarCliente(numero, contacto, fecha);
      crearNotificacion(numero, contacto, "🎥 Video (archivo no disponible)", fecha);
    } catch (dbError) { console.error("Error registrando multimedia sin archivo:", dbError); }
  }
}

async function procesarMensajeDocumento(msg, numero, contacto, fecha) {
  try {
    console.log("📄 Procesando documento recibido...");
    
    const documentMessage = msg.message.documentMessage;
    
    // Descargar el documento
    const stream = await downloadContentFromMessage(documentMessage, "document");
    let buffer = Buffer.from([]);
    for await (const chunk of stream) {
      buffer = Buffer.concat([buffer, chunk]);
    }

    // Guardar archivo
    const fileName = documentMessage.fileName || `documento_${Date.now()}`;
    const filePath = `public/archivos/${fileName}`;
    fs.writeFileSync(filePath, buffer);

    console.log("✅ Documento guardado:", fileName);

    // Guardar en base de datos
    const mensajeTexto = documentMessage.caption || `📄 ${fileName}`;
    guardarMensajeEnDB(numero, mensajeTexto, 'recibido', fecha, `/archivos/${fileName}`, documentMessage.mimetype, 1);
    
    actualizarCliente(numero, contacto, fecha);
    crearNotificacion(numero, contacto, `📄 ${fileName}`, fecha);

  } catch (error) {
    console.error("❌ Error procesando documento:", error);
  }
}

async function procesarMensajeTexto(msg, numero, contacto, fecha) {
  const texto =
    msg.message.conversation ||
    msg.message.extendedTextMessage?.text ||
    "(mensaje sin texto)";

  console.log("📝 Texto recibido:", texto.substring(0, 50) + "...");

  // Guardar mensaje en base de datos
  guardarMensajeEnDB(numero, texto, 'recibido', fecha, null, null, 0);
  
  actualizarCliente(numero, contacto, fecha);
  crearNotificacion(numero, contacto, texto, fecha);
}

// Función para guardar mensajes en la base de datos
async function guardarMensajeEnDB(numero, mensaje, tipo, fecha, archivo, mime_type, es_multimedia) {
  await db.query(
    "INSERT INTO mensajes (numero, mensaje, tipo, fecha, archivo, mime_type, es_multimedia) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    [numero, mensaje, tipo, fecha, archivo, mime_type, es_multimedia]
  );
  console.log("✅ Mensaje guardado en DB:", String(mensaje).substring(0, 30));
}

function actualizarCliente(numero, contacto, fecha) {
  db.get("SELECT * FROM clientes WHERE numero=?", [numero], (err, row) => {
    if (err) {
      console.error("Error buscando cliente:", err);
      return;
    }

    if (!row) {
      const etiqueta = numero.endsWith("@g.us") ? "grupos" : "nuevo";
      db.run(
        `INSERT INTO clientes (numero, nombre, etiqueta, ultima_interaccion, archivado, nota)
         VALUES (?, ?, ?, ?, 0, '')`,
        [numero, contacto, etiqueta, fecha],
        function(err) {
          if (err) {
            console.error("Error insertando cliente:", err);
          } else {
            console.log("✅ Nuevo cliente agregado:", contacto);
          }
        }
      );
    } else {
      db.run(
        `UPDATE clientes SET ultima_interaccion=?, nombre=? WHERE numero=?`,
        [fecha, contacto, numero],
        function(err) {
          if (err) {
            console.error("Error actualizando cliente:", err);
          }
        }
      );
    }
  });
}

function crearNotificacion(numero, contacto, mensaje, fecha) {
  const notifyData = {
    numero,
    nombre: contacto,
    mensaje: mensaje.substring(0, 100),
    fecha
  };

  try {
    fs.writeFileSync("public/notify.json", JSON.stringify(notifyData));
    console.log("🔔 Notificación creada para:", contacto);
  } catch (error) {
    console.error("Error creando notificación:", error);
  }
}

/* ========================================================
   SINCRONIZAR CHATS
======================================================== */

async function sincronizarChats() {
  try {
    if (!sock.store?.chats) {
      console.log("⚠ Store no disponible para sincronizar chats");
      return;
    }

    const chats = await sock.store.chats.all();
    let nuevos = 0;

    for (const c of chats) {
      const numero = c.id;
      const nombre = c.name || c.subject || "Sin nombre";
      const isGroup = numero.endsWith("@g.us");
      const etiqueta = isGroup ? "grupos" : "nuevo";
      const fecha = new Date().toISOString();

      db.get("SELECT * FROM clientes WHERE numero=?", [numero], (err, row) => {
        if (err) {
          console.error("Error buscando chat:", err);
          return;
        }

        if (!row) {
          db.run(
            `INSERT INTO clientes (numero, nombre, etiqueta, ultima_interaccion, archivado, nota)
             VALUES (?, ?, ?, ?, 0, '')`,
            [numero, nombre, etiqueta, fecha],
            function(err) {
              if (err) {
                if (!err.message.includes("UNIQUE constraint")) {
                  console.error("Error insertando chat:", err);
                }
              } else {
                nuevos++;
              }
            }
          );
        }
      });
    }

    console.log(`🔄 Chats sincronizados. Nuevos: ${nuevos}`);
  } catch (e) {
    console.log("⚠ Error al sincronizar chats:", e.message);
  }
}

/* ========================================================
   ENDPOINTS PARA ARCHIVOS MULTIMEDIA
======================================================== */

// ENVÍO DE AUDIO DESDE CRM
const execFileAsync = promisify(execFile);
// Convert browser-recorded WebM/MP4 into WhatsApp-compatible Ogg/Opus voice notes.
app.post("/enviar-audio", upload.single("audio"), async (req, res) => {
  const numero = req.body?.numero;
  if (!sock?.user) return res.status(503).json({ error: "WhatsApp no está conectado" });
  if (!numero || !req.file) return res.status(400).json({ error: "Contacto y audio requeridos" });
  const source = req.file.path;
  const isRecording = /^nota_voz_/i.test(req.file.originalname || "");
  let filePath = source;
  let mime = req.file.mimetype || "audio/ogg";
  try {
    if (!fs.statSync(source).size) throw new Error("La grabación está vacía");
    if (isRecording) {
      const convertedName = "voz_" + Date.now() + "_" + Math.random().toString(36).slice(2,8) + ".ogg";
      const convertedPath = path.join(__dirname, "public", "audios", convertedName);
      await execFileAsync("ffmpeg", [
        "-hide_banner", "-loglevel", "error", "-y", "-i", source,
        "-vn", "-ac", "1", "-ar", "48000", "-c:a", "libopus",
        "-b:a", "32k", "-application", "voip", convertedPath
      ], { timeout: 120000 });
      filePath = convertedPath;
      mime = "audio/ogg; codecs=opus";
    }
    const buffer = fs.readFileSync(filePath);
    if (!buffer.length) throw new Error("El archivo de audio convertido está vacío");
    await sock.sendMessage(numero, {
      audio: buffer,
      mimetype: mime,
      ...(isRecording ? { ptt: true } : {})
    });
    const archivo = "/audios/" + path.basename(filePath);
    await guardarMensajeEnDB(numero, "🎵 Audio", "enviado", new Date().toISOString(), archivo, mime, 1);
    console.log("✅ Audio enviado y guardado:", archivo, numero);
    res.json({ ok: true, archivo });
  } catch (e) {
    console.error("❌ Error enviando audio:", e);
    res.status(500).json({ error: "No se pudo enviar la nota de voz: " + e.message });
  } finally {
    if (filePath !== source) {
      try { fs.unlinkSync(source); } catch {}
    }
  }
});

// ENVÍO DE IMAGEN DESDE CRM
app.post("/enviar-imagen", upload.single("imagen"), async (req, res) => {
  try {
    console.log("🖼️ Iniciando envío de imagen...");
    
    if (!sock) {
      return res.status(500).json({ error: "WhatsApp no conectado" });
    }

    const { numero, caption } = req.body;
    if (!numero) {
      return res.status(400).json({ error: "Número requerido" });
    }

    if (!req.file) {
      return res.status(400).json({ error: "Archivo de imagen requerido" });
    }

    const filePath = req.file.path;
    const fileName = req.file.filename;

    console.log("📁 Imagen a enviar:", fileName, "a:", numero);

    // Leer archivo como buffer
    const buffer = fs.readFileSync(filePath);
    console.log("📊 Tamaño de la imagen:", buffer.length, "bytes");

    await sock.sendMessage(numero, {
      image: buffer,
      caption: caption || "",
      mimetype: req.file.mimetype,
    });

    console.log("✅ Imagen enviada a WhatsApp");

    // Guardar mensaje en DB
    const fecha = new Date().toISOString();
    guardarMensajeEnDB(numero, caption || "🖼️ Imagen", 'enviado', fecha, `/imagenes/${fileName}`, req.file.mimetype, 1);

    res.json({ ok: true, archivo: fileName });

  } catch (e) {
    console.log("❌ Error enviando imagen:", e);
    res.status(500).json({ error: e.message });
  }
});

// ENVÍO DE VIDEO DESDE CRM
app.post("/enviar-video", upload.single("video"), async (req, res) => {
  if (!sock) return res.status(503).json({ error: "WhatsApp no conectado" });
  if (!req.body.numero || !req.file) return res.status(400).json({ error: "Contacto y video requeridos" });
  if (!req.file.mimetype?.startsWith("video/")) return res.status(400).json({ error: "El archivo no es un video" });
  try {
    const buffer = fs.readFileSync(req.file.path);
    await sock.sendMessage(req.body.numero, {
      video: buffer, mimetype: req.file.mimetype, caption: req.body.caption || ""
    });
    await guardarMensajeEnDB(req.body.numero, req.body.caption || "🎥 Video", "enviado",
      new Date().toISOString(), "/videos/" + req.file.filename, req.file.mimetype, 1);
    res.json({ ok: true });
  } catch (err) {
    console.error("Error enviando video:", err);
    res.status(500).json({ error: err.message });
  }
});

// ENVÍO DE DOCUMENTO/ARCHIVO DESDE CRM
app.post("/enviar-documento", upload.single("documento"), async (req, res) => {
  try {
    console.log("📄 Iniciando envío de documento...");
    
    if (!sock) {
      return res.status(500).json({ error: "WhatsApp no conectado" });
    }

    const { numero, caption } = req.body;
    if (!numero) {
      return res.status(400).json({ error: "Número requerido" });
    }

    if (!req.file) {
      return res.status(400).json({ error: "Archivo requerido" });
    }

    const filePath = req.file.path;
    const fileName = req.file.filename;
    const originalName = req.file.originalname;

    console.log("📁 Documento a enviar:", originalName, "a:", numero);

    // Leer archivo como buffer
    const buffer = fs.readFileSync(filePath);
    console.log("📊 Tamaño del documento:", buffer.length, "bytes");

    await sock.sendMessage(numero, {
      document: buffer,
      fileName: originalName,
      caption: caption || "",
      mimetype: req.file.mimetype,
    });

    console.log("✅ Documento enviado a WhatsApp");

    // Guardar mensaje en DB
    const fecha = new Date().toISOString();
    guardarMensajeEnDB(numero, caption || `📄 ${originalName}`, 'enviado', fecha, `/archivos/${fileName}`, req.file.mimetype, 1);

    res.json({ ok: true, archivo: fileName });

  } catch (e) {
    console.log("❌ Error enviando documento:", e);
    res.status(500).json({ error: e.message });
  }
});

/* ========================================================
   SISTEMA DE RECORDATORIOS PARA CALLBACK
======================================================== */

// Obtener recordatorios de un contacto
app.get("/recordatorios/:numero", (req, res) => {
  const numero = decodeURIComponent(req.params.numero);
  
  db.all(
    "SELECT * FROM recordatorios WHERE numero = ? ORDER BY fecha_recordatorio ASC",
    [numero],
    (err, rows) => {
      if (err) {
        console.error("Error obteniendo recordatorios:", err);
        res.status(500).json({ error: "Error interno" });
      } else {
        res.json(rows);
      }
    }
  );
});

// Crear nuevo recordatorio
app.post("/recordatorios", (req, res) => {
  const { numero, fecha_recordatorio, mensaje } = req.body;
  
  if (!numero || !fecha_recordatorio) {
    return res.status(400).json({ error: "Número y fecha requeridos" });
  }

  db.run(
    "INSERT INTO recordatorios (numero, fecha_recordatorio, mensaje) VALUES (?, ?, ?)",
    [numero, fecha_recordatorio, mensaje || "Recordatorio de callback"],
    function(err) {
      if (err) {
        console.error("Error creando recordatorio:", err);
        res.status(500).json({ error: "Error interno" });
      } else {
        res.json({ 
          id: this.lastID, 
          numero, 
          fecha_recordatorio, 
          mensaje: mensaje || "Recordatorio de callback" 
        });
      }
    }
  );
});

// Actualizar recordatorio
app.put("/recordatorios/:id", (req, res) => {
  const { fecha_recordatorio, mensaje } = req.body;
  const id = req.params.id;

  db.run(
    "UPDATE recordatorios SET fecha_recordatorio = ?, mensaje = ? WHERE id = ?",
    [fecha_recordatorio, mensaje, id],
    function(err) {
      if (err) {
        console.error("Error actualizando recordatorio:", err);
        res.status(500).json({ error: "Error interno" });
      } else {
        res.json({ ok: true });
      }
    }
  );
});

// Eliminar recordatorio
app.delete("/recordatorios/:id", (req, res) => {
  const id = req.params.id;

  db.run("DELETE FROM recordatorios WHERE id = ?", [id], function(err) {
    if (err) {
      console.error("Error eliminando recordatorio:", err);
      res.status(500).json({ error: "Error interno" });
    } else {
      res.json({ ok: true });
    }
  });
});

// Obtener recordatorios próximos (para notificaciones)
app.get("/recordatorios-proximos", (req, res) => {
  const ahora = new Date().toISOString();
  const unaHoraDespues = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  
  db.all(
    `SELECT r.*, c.nombre 
     FROM recordatorios r 
     JOIN clientes c ON r.numero = c.numero 
     WHERE r.fecha_recordatorio BETWEEN ? AND ? 
     AND r.activo = 1 
     ORDER BY r.fecha_recordatorio ASC`,
    [ahora, unaHoraDespues],
    (err, rows) => {
      if (err) {
        console.error("Error obteniendo recordatorios próximos:", err);
        res.status(500).json({ error: "Error interno" });
      } else {
        res.json(rows);
      }
    }
  );
});

// Marcar recordatorio como inactivo
app.put("/recordatorios/:id/marcar-completado", (req, res) => {
  const id = req.params.id;

  db.run(
    "UPDATE recordatorios SET activo = 0 WHERE id = ?",
    [id],
    function(err) {
      if (err) {
        console.error("Error marcando recordatorio:", err);
        res.status(500).json({ error: "Error interno" });
      } else {
        res.json({ ok: true });
      }
    }
  );
});

/* ========================================================
   GESTIÓN DE CONTACTOS MASIVOS DESDE ARCHIVOS
======================================================== */

// Endpoint para subir archivos de contactos
app.post("/subir-contactos", upload.single("archivo"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Archivo requerido" });
    }

    const filePath = req.file.path;
    const extension = path.extname(filePath).toLowerCase();
    
    let numeros = [];
    let resultados = {
      total: 0,
      nuevos: 0,
      existentes: 0,
      errores: 0,
      detalles: []
    };

    console.log("📁 Procesando archivo:", req.file.originalname);

    // Leer archivo según extensión
    if (extension === '.txt') {
      const contenido = fs.readFileSync(filePath, 'utf8');
      numeros = contenido.split('\n')
        .map(linea => linea.trim())
        .filter(linea => linea.length > 0);
      
      console.log(`📄 ${numeros.length} números encontrados en TXT`);
      
    } else if (extension === '.csv') {
      const contenido = fs.readFileSync(filePath, 'utf8');
      const lineas = contenido.split('\n');
      
      for (let i = 0; i < lineas.length; i++) {
        const linea = lineas[i].trim();
        if (!linea) continue;
        
        // Buscar números en la línea (pueden estar en cualquier columna)
        const numerosEnLinea = linea.match(/\b\d{10,15}\b/g) || [];
        numeros.push(...numerosEnLinea);
      }
      
      console.log(`📊 ${numeros.length} números encontrados en CSV`);
    } else {
      // Eliminar archivo no soportado
      fs.unlinkSync(filePath);
      return res.status(400).json({ error: "Formato no soportado. Use .txt o .csv" });
    }

    resultados.total = numeros.length;

    // Procesar cada número
    for (const numero of numeros) {
      try {
        // Formatear número al formato WhatsApp
        let numeroFormateado = numero.replace(/\D/g, ''); // Solo números
        
        console.log(`🔢 Procesando: ${numero} -> ${numeroFormateado}`);
        
        // Validar que tenga al menos 10 dígitos
        if (numeroFormateado.length < 10) {
          resultados.errores++;
          resultados.detalles.push({ numero, estado: "error", error: "Número muy corto" });
          continue;
        }
        
        // Si no tiene código de país, asumir México (+52)
        if (numeroFormateado.length === 10) {
          numeroFormateado = '52' + numeroFormateado;
          console.log(`🇲🇽 Asumiendo México: ${numeroFormateado}`);
        }
        
        numeroFormateado += '@s.whatsapp.net';

        // Verificar si ya existe
        const existe = await new Promise((resolve) => {
          db.get("SELECT numero FROM clientes WHERE numero = ?", [numeroFormateado], (err, row) => {
            if (err) {
              console.error("Error buscando cliente:", err);
              resolve(false);
            } else {
              resolve(!!row);
            }
          });
        });

        if (existe) {
          resultados.existentes++;
          resultados.detalles.push({ numero: numeroFormateado, estado: "existente" });
          console.log(`📋 Ya existe: ${numeroFormateado}`);
        } else {
          // Insertar nuevo cliente
          await new Promise((resolve, reject) => {
            const fecha = new Date().toISOString();
            db.run(
              `INSERT INTO clientes (numero, nombre, etiqueta, ultima_interaccion, archivado, nota) 
               VALUES (?, ?, ?, ?, 0, '')`,
              [numeroFormateado, `Contacto ${numero}`, 'nuevo', fecha],
              function(err) {
                if (err) {
                  if (err.message.includes("UNIQUE constraint")) {
                    resultados.existentes++;
                    resultados.detalles.push({ numero: numeroFormateado, estado: "existente" });
                  } else {
                    resultados.errores++;
                    resultados.detalles.push({ numero: numeroFormateado, estado: "error", error: err.message });
                  }
                } else {
                  resultados.nuevos++;
                  resultados.detalles.push({ numero: numeroFormateado, estado: "nuevo" });
                  console.log(`✅ Nuevo: ${numeroFormateado}`);
                }
                resolve();
              }
            );
          });
        }
      } catch (error) {
        resultados.errores++;
        resultados.detalles.push({ numero, estado: "error", error: error.message });
        console.error(`❌ Error con ${numero}:`, error);
      }
    }

    // Eliminar archivo temporal
    fs.unlinkSync(filePath);

    console.log(`🎯 Resultado final: ${resultados.nuevos} nuevos, ${resultados.existentes} existentes, ${resultados.errores} errores`);

    res.json({
      ok: true,
      resumen: resultados,
      mensaje: `✅ ${resultados.nuevos} nuevos contactos, ${resultados.existentes} existentes, ${resultados.errores} errores`
    });

  } catch (error) {
    console.error("Error procesando archivo:", error);
    res.status(500).json({ error: "Error procesando archivo: " + error.message });
  }
});

// Endpoint para enviar mensaje a lista de números específica
app.post("/enviar-lista-contactos", async (req, res) => {
  try {
    const { numeros, mensaje } = req.body;

    if (!sock) {
      return res.status(500).json({ error: "WhatsApp no conectado" });
    }

    if (!numeros || !Array.isArray(numeros) || numeros.length === 0) {
      return res.status(400).json({ error: "Lista de números requerida" });
    }

    if (!mensaje || mensaje.trim() === '') {
      return res.status(400).json({ error: "Mensaje requerido" });
    }

    console.log(`📤 Enviando mensaje a ${numeros.length} números`);

    let exitosos = 0;
    let errores = 0;
    const detalles = [];

    for (const numero of numeros) {
      try {
        await sock.sendMessage(numero, { text: mensaje });
        exitosos++;
        
        // Guardar en base de datos
        const fecha = new Date().toISOString();
        guardarMensajeEnDB(numero, mensaje, 'enviado', fecha, null, null, 0);
        
        detalles.push({ numero, estado: "enviado" });
        console.log(`✅ Enviado a: ${numero}`);

        // Pausa para evitar bloqueos
        await new Promise(resolve => setTimeout(resolve, 200));
        
      } catch (e) {
        errores++;
        detalles.push({ numero, estado: "error", error: e.message });
        console.error(`❌ Error enviando a ${numero}:`, e.message);
      }
    }

    console.log(`🎯 Envío completado: ${exitosos} exitosos, ${errores} errores`);

    res.json({
      ok: true,
      resumen: {
        total: numeros.length,
        exitosos: exitosos,
        errores: errores
      },
      detalles: detalles
    });

  } catch (error) {
    console.error("Error en envío por lista:", error);
    res.status(500).json({ error: error.message });
  }
});

/* ========================================================
   ENDPOINTS EXISTENTES
======================================================== */

// Endpoint QR
app.get("/qr.json", (req, res) => {
  try {
    if (fs.existsSync("public/qr.json")) {
      const qrData = fs.readFileSync("public/qr.json", "utf8");
      res.json(JSON.parse(qrData));
    } else {
      res.json({ qr: null });
    }
  } catch (error) {
    res.json({ qr: null });
  }
});

// Endpoint notificaciones
app.get("/notify.json", (req, res) => {
  try {
    if (fs.existsSync("public/notify.json")) {
      const notifyData = fs.readFileSync("public/notify.json", "utf8");
      res.json(JSON.parse(notifyData));
    } else {
      res.json({});
    }
  } catch (error) {
    res.json({});
  }
});

// Eliminar notificación
app.delete("/notify.json", (req, res) => {
  try {
    if (fs.existsSync("public/notify.json")) {
      fs.unlinkSync("public/notify.json");
    }
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Respuestas rápidas
app.get("/respuestas", (req, res) => {
  db.all("SELECT * FROM respuestas ORDER BY id", (err, rows) => {
    if (err) {
      console.error("Error obteniendo respuestas:", err);
      res.status(500).json({ error: "Error interno" });
    } else {
      res.json(rows);
    }
  });
});

app.post("/respuestas", (req, res) => {
  const { texto } = req.body;
  if (!texto) {
    return res.status(400).json({ error: "Texto requerido" });
  }

  db.run("INSERT INTO respuestas (texto) VALUES (?)", [texto], function(err) {
    if (err) {
      console.error("Error insertando respuesta:", err);
      res.status(500).json({ error: "Error interno" });
    } else {
      res.json({ id: this.lastID, texto });
    }
  });
});

app.put("/respuestas/:id", (req, res) => {
  const { texto } = req.body;
  const id = req.params.id;

  if (!texto) {
    return res.status(400).json({ error: "Texto requerido" });
  }

  db.run("UPDATE respuestas SET texto=? WHERE id=?", [texto, id], function(err) {
    if (err) {
      console.error("Error actualizando respuesta:", err);
      res.status(500).json({ error: "Error interno" });
    } else {
      res.json({ ok: true });
    }
  });
});

app.delete("/respuestas/:id", (req, res) => {
  const id = req.params.id;

  db.run("DELETE FROM respuestas WHERE id=?", [id], function(err) {
    if (err) {
      console.error("Error eliminando respuesta:", err);
      res.status(500).json({ error: "Error interno" });
    } else {
      res.json({ ok: true });
    }
  });
});

// Agenda manual de contactos (sin requerir un mensaje entrante).
app.post("/contactos", async (req,res) => {
  const nombre=String(req.body?.nombre||"").trim();
  const digits=String(req.body?.telefono||"").replace(/\D/g,"");
  if(!nombre || digits.length<8 || digits.length>15)
    return res.status(400).json({error:"Ingresá un nombre y un teléfono internacional válido (8-15 dígitos)."});
  const numero=digits+"@s.whatsapp.net";
  try {
    const existing=await db.query("SELECT numero FROM clientes WHERE numero=$1",[numero]);
    if(existing.rows.length)return res.status(409).json({error:"El contacto ya está agendado"});
    await db.query("INSERT INTO clientes (numero,nombre,etiqueta,nota,archivado,ultima_interaccion) VALUES ($1,$2,$3,$4,$5,$6)",
      [numero,nombre,"nuevo","",0,new Date().toISOString()]);
    res.status(201).json({ok:true,numero,nombre});
  }catch(e){console.error("Error agendando contacto:",e);res.status(500).json({error:"No se pudo guardar el contacto"})}
});

// Obtener clientes
app.get("/clientes", (req, res) => {
  db.all("SELECT * FROM clientes ORDER BY ultima_interaccion DESC", (err, rows) => {
    if (err) {
      console.error("Error obteniendo clientes:", err);
      res.status(500).json({ error: "Error interno" });
    } else {
      res.json(rows);
    }
  });
});

// Cambiar estado
app.put("/clientes/:numero/estado", (req, res) => {
  const { etiqueta, archivado } = req.body;
  const numero = decodeURIComponent(req.params.numero);
  
  db.run(
    "UPDATE clientes SET etiqueta=?, archivado=? WHERE numero=?",
    [etiqueta, archivado, numero],
    function(err) {
      if (err) {
        console.error("Error actualizando estado:", err);
        res.status(500).json({ error: "Error interno" });
      } else {
        res.json({ ok: true });
      }
    }
  );
});

// Notas
app.get("/clientes/:numero/nota", (req, res) => {
  const numero = decodeURIComponent(req.params.numero);
  
  db.get("SELECT nota FROM clientes WHERE numero=?", [numero], (err, row) => {
    if (err) {
      console.error("Error obteniendo nota:", err);
      res.status(500).json({ error: "Error interno" });
    } else {
      res.json({ nota: row?.nota || "" });
    }
  });
});

app.put("/clientes/:numero/nota", (req, res) => {
  const numero = decodeURIComponent(req.params.numero);
  
  db.run(
    "UPDATE clientes SET nota=? WHERE numero=?",
    [req.body.nota, numero],
    function(err) {
      if (err) {
        console.error("Error actualizando nota:", err);
        res.status(500).json({ error: "Error interno" });
      } else {
        res.json({ ok: true });
      }
    }
  );
});
/* ========================================================
   ACTUALIZAR NOMBRE DE CONTACTO
======================================================== */

app.put("/clientes/:numero/nombre", (req, res) => {
  const { nombre } = req.body;
  const numero = decodeURIComponent(req.params.numero);
  
  console.log(`✏️ Actualizando nombre para ${numero}: "${nombre}"`);
  
  db.run(
    "UPDATE clientes SET nombre=? WHERE numero=?",
    [nombre, numero],
    function(err) {
      if (err) {
        console.error("❌ Error actualizando nombre:", err);
        res.status(500).json({ error: "Error interno" });
      } else {
        console.log(`✅ Nombre actualizado para ${numero}: "${nombre}"`);
        res.json({ 
          ok: true, 
          mensaje: "Nombre actualizado correctamente",
          cambios: this.changes 
        });
      }
    }
  );
});


/* Daily activity and unanswered conversation monitoring. */
app.get("/api/informes/conversaciones", async (req, res) => {
  try {
    const days = Math.min(90, Math.max(1, Number.parseInt(req.query.dias, 10) || 14));
    // fecha is TEXT in the legacy schema. Aggregate by its ISO date prefix.
    const daily = await db.query(`
      SELECT LEFT(fecha, 10) AS dia, COUNT(*) AS mensajes,
             COUNT(DISTINCT numero) AS conversaciones,
             SUM(CASE WHEN tipo = 'recibido' THEN 1 ELSE 0 END)::int AS recibidos,
             SUM(CASE WHEN tipo = 'enviado' THEN 1 ELSE 0 END)::int AS enviados
      FROM mensajes
      WHERE LEFT(fecha, 10) >= TO_CHAR(CURRENT_DATE - ($1::int - 1), 'YYYY-MM-DD')
      GROUP BY LEFT(fecha, 10) ORDER BY dia DESC`, [days]);
    // Match the latest stored message by id; avoid casting old text dates to timestamps.
    const pending = await db.query(`
      SELECT m.numero, COALESCE(NULLIF(c.nombre, ''), m.numero) AS nombre,
             m.fecha AS ultima_fecha, m.mensaje AS ultimo_mensaje,
             CASE WHEN m.fecha ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T'
               THEN GREATEST(0, EXTRACT(EPOCH FROM (NOW() - NULLIF(m.fecha, '')::timestamptz))::int)
               ELSE NULL END AS espera_segundos
      FROM mensajes m
      LEFT JOIN clientes c ON c.numero = m.numero
      WHERE m.tipo = 'recibido'
        AND m.id = (SELECT ultimo.id FROM mensajes ultimo
                    WHERE ultimo.numero = m.numero ORDER BY ultimo.id DESC LIMIT 1)
      ORDER BY m.id DESC LIMIT 200`);
    res.setHeader('Cache-Control', 'no-store');
    res.json({ daily, pending, llamadas: { duracion_segundos: null, disponible: false,
      motivo: 'La integración actual no registra duración de llamadas.' } });
  } catch (error) {
    console.error('Error informe conversaciones:', error);
    res.status(500).json({ error: 'No se pudo generar el informe', code: error.code || 'report_query_failed', detail: error.message });
  }
});

// Obtener TODOS los mensajes (para analytics)
app.get("/mensajes", (req, res) => {
  console.log("📊 Solicitando todos los mensajes para analytics");
  
  db.all(
    "SELECT * FROM mensajes ORDER BY fecha DESC LIMIT 1000",
    (err, rows) => {
      if (err) {
        console.error("Error obteniendo mensajes:", err);
        res.status(500).json({ error: "Error al obtener mensajes" });
      } else {
        console.log(`✅ Enviando ${rows.length} mensajes`);
        res.json(rows);
      }
    }
  );
});
// Mensajes del chat
app.get("/mensajes/:numero", (req, res) => {
  const numero = decodeURIComponent(req.params.numero);
  
  console.log(`📨 Solicitando mensajes para: ${numero}`);
  
  db.all(
    "SELECT * FROM mensajes WHERE numero=? ORDER BY fecha ASC",
    [numero],
    (err, rows) => {
      if (err) {
        console.error("Error obteniendo mensajes:", err);
        res.status(500).json({ error: "Error interno" });
      } else {
        console.log(`✅ Enviando ${rows.length} mensajes para ${numero}`);
        // Forzar no-cache
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.json(rows);
      }
    }
  );
});

// Eliminar cliente
app.delete("/clientes/:numero", (req, res) => {
  const numero = decodeURIComponent(req.params.numero);
  
  db.run("DELETE FROM clientes WHERE numero=?", [numero], function(err) {
    if (err) {
      console.error("Error eliminando cliente:", err);
      res.status(500).json({ error: "Error interno" });
      return;
    }
    
    db.run("DELETE FROM mensajes WHERE numero=?", [numero], function(err) {
      if (err) {
        console.error("Error eliminando mensajes:", err);
        res.status(500).json({ error: "Error interno" });
      } else {
        res.json({ ok: true });
      }
    });
  });
});

// Enviar texto
app.post("/enviar", async (req, res) => {
  const { numero, mensaje } = req.body;
  
  if (!sock) {
    return res.status(500).json({ error: "WhatsApp no conectado" });
  }

  try {
    await sock.sendMessage(numero, { text: mensaje });

    const fecha = new Date().toISOString();
    guardarMensajeEnDB(numero, mensaje, 'enviado', fecha, null, null, 0);

    res.json({ ok: true });
  } catch (e) {
    console.error("Error enviando mensaje:", e);
    res.status(500).json({ error: e.message });
  }
});

// Envío masivo a TODOS los clientes
app.post("/enviar-masivo", async (req, res) => {
  const { mensaje } = req.body;

  if (!sock) {
    return res.status(500).json({ error: "WhatsApp no conectado" });
  }

  db.all("SELECT numero FROM clientes WHERE archivado=0", async (err, rows) => {
    if (err) {
      console.error("Error obteniendo clientes para envío masivo:", err);
      return res.status(500).json({ error: "Error interno" });
    }

    try {
      let exitosos = 0;
      let errores = 0;
      
      for (const c of rows) {
        try {
          await sock.sendMessage(c.numero, { text: mensaje });
          exitosos++;
          
          // Guardar en base de datos
          const fecha = new Date().toISOString();
          guardarMensajeEnDB(c.numero, mensaje, 'enviado', fecha, null, null, 0);
          
          // Pequeña pausa para evitar bloqueos
          await new Promise(resolve => setTimeout(resolve, 100));
        } catch (e) {
          console.error(`Error enviando a ${c.numero}:`, e.message);
          errores++;
        }
      }

      res.json({ 
        ok: true, 
        resumen: {
          total: rows.length,
          exitosos: exitosos,
          errores: errores
        }
      });
    } catch (e) {
      console.error("Error en envío masivo:", e);
      res.status(500).json({ error: e.message });
    }
  });
});

// Envío masivo por estado
app.post("/enviar-masivo-estado", async (req, res) => {
  const { mensaje, estados } = req.body;

  if (!sock) {
    return res.status(500).json({ error: "WhatsApp no conectado" });
  }

  if (!estados || !Array.isArray(estados) || estados.length === 0) {
    return res.status(400).json({ error: "Selecciona al menos un estado" });
  }

  // Construir la consulta SQL según los estados seleccionados
  let query = "SELECT numero FROM clientes WHERE archivado=0 AND (";
  const params = [];
  
  estados.forEach((estado, index) => {
    if (index > 0) query += " OR ";
    query += "etiqueta=?";
    params.push(estado);
  });
  
  query += ")";

  db.all(query, params, async (err, rows) => {
    if (err) {
      console.error("Error obteniendo clientes por estado:", err);
      return res.status(500).json({ error: "Error interno" });
    }

    if (rows.length === 0) {
      return res.status(400).json({ error: "No hay clientes en los estados seleccionados" });
    }

    try {
      let exitosos = 0;
      let errores = 0;
      
      for (const c of rows) {
        try {
          await sock.sendMessage(c.numero, { text: mensaje });
          exitosos++;
          
          // Guardar en base de datos
          const fecha = new Date().toISOString();
          guardarMensajeEnDB(c.numero, mensaje, 'enviado', fecha, null, null, 0);
          
          // Pequeña pausa para evitar bloqueos
          await new Promise(resolve => setTimeout(resolve, 100));
        } catch (e) {
          console.error(`Error enviando a ${c.numero}:`, e.message);
          errores++;
        }
      }

      res.json({ 
        ok: true, 
        resumen: {
          total: rows.length,
          exitosos: exitosos,
          errores: errores
        }
      });
    } catch (e) {
      console.error("Error en envío masivo por estado:", e);
      res.status(500).json({ error: e.message });
    }
  });
});

// Exportar CSV
app.get("/exportar", (req, res) => {
  db.all("SELECT * FROM clientes ORDER BY ultima_interaccion DESC", (err, rows) => {
    if (err) {
      console.error("Error exportando CSV:", err);
      return res.status(500).json({ error: "Error interno" });
    }

    try {
      const parser = new Parser({
        fields: ["numero", "nombre", "etiqueta", "ultima_interaccion", "nota", "archivado"],
      });

      const csv = parser.parse(rows);

      res.setHeader("Content-disposition", "attachment; filename=crm_clientes.csv");
      res.set("Content-Type", "text/csv");
      res.status(200).send(csv);
    } catch (error) {
      console.error("Error generando CSV:", error);
      res.status(500).json({ error: "Error generando CSV" });
    }
  });
});

// Ruta por defecto
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});



/* ========================================================
   DASHBOARD - MÉTRICAS EN TIEMPO REAL
======================================================== */

// Métricas principales del dashboard
app.get("/dashboard/metricas", (req, res) => {
  const metricas = {};

  // 1. Total clientes activos
  db.get("SELECT COUNT(*) as count FROM clientes WHERE archivado=0", (err, row) => {
    if (err) {
      console.error("Error métrica clientes:", err);
      return res.status(500).json({ error: "Error interno" });
    }
    metricas.totalClientes = row.count;

    // 2. Mensajes de hoy
    db.get(`SELECT COUNT(*) as count FROM mensajes 
            WHERE DATE(fecha) = DATE('now')`, (err, row) => {
      if (err) {
        console.error("Error métrica mensajes:", err);
        return res.status(500).json({ error: "Error interno" });
      }
      metricas.mensajesHoy = row.count;

      // 3. Nuevos clientes hoy
      db.get(`SELECT COUNT(*) as count FROM clientes 
              WHERE DATE(ultima_interaccion) = DATE('now') 
              AND etiqueta='nuevo'`, (err, row) => {
        if (err) {
          console.error("Error métrica nuevos:", err);
          return res.status(500).json({ error: "Error interno" });
        }
        metricas.nuevosHoy = row.count;

        // 4. Tasa de conversión (nuevo -> callback/analista)
        db.get(`SELECT COUNT(*) as convertidos FROM clientes 
                WHERE etiqueta IN ('callback', 'analista')`, (err, row) => {
          if (err) {
            console.error("Error métrica conversión:", err);
            return res.status(500).json({ error: "Error interno" });
          }
          
          const totalNoArchivados = metricas.totalClientes;
          metricas.tasaConversion = totalNoArchivados > 0 
            ? Math.round((row.convertidos / totalNoArchivados) * 100)
            : 0;

          // 5. Tiempo promedio de respuesta (últimas 24h)
          db.get(`SELECT AVG(
            (julianday(m2.fecha) - julianday(m1.fecha)) * 24 * 60
          ) as avg_minutes FROM mensajes m1
          JOIN mensajes m2 ON m1.numero = m2.numero 
          AND m2.id = (SELECT MIN(id) FROM mensajes 
                      WHERE numero = m1.numero AND id > m1.id)
          WHERE m1.tipo = 'recibido' 
          AND m1.fecha > datetime('now', '-1 day')
          AND (julianday(m2.fecha) - julianday(m1.fecha)) * 24 * 60 < 120`, 
          (err, row) => {
            if (err) {
              console.error("Error métrica respuesta:", err);
              // No fallar por esta métrica
              metricas.tiempoRespuesta = 0;
            } else {
              metricas.tiempoRespuesta = Math.round(row.avg_minutes || 0);
            }

            res.json(metricas);
          });
        });
      });
    });
  });
});

// Datos para gráfico de clientes por estado
app.get("/dashboard/estados-clientes", (req, res) => {
  db.all(`SELECT etiqueta, COUNT(*) as count 
          FROM clientes 
          WHERE archivado=0 
          GROUP BY etiqueta`, (err, rows) => {
    if (err) {
      console.error("Error gráfico estados:", err);
      res.status(500).json({ error: "Error interno" });
    } else {
      res.json(rows);
    }
  });
});

// Actividad reciente (últimos mensajes)
app.get("/dashboard/actividad-reciente", (req, res) => {
  db.all(`SELECT c.nombre, c.numero, m.mensaje, m.fecha, m.tipo, m.es_multimedia,
          CASE 
            WHEN m.es_multimedia = 1 THEN 
              CASE 
                WHEN m.mime_type LIKE 'audio/%' THEN '🎵 Audio'
                WHEN m.mime_type LIKE 'image/%' THEN '🖼️ Imagen' 
                WHEN m.mime_type LIKE 'video/%' THEN '🎥 Video'
                ELSE '📄 Archivo'
              END
            ELSE m.mensaje
          END as contenido,
          datetime(m.fecha) as fecha_legible
          FROM mensajes m 
          JOIN clientes c ON m.numero = c.numero 
          ORDER BY m.fecha DESC 
          LIMIT 10`, (err, rows) => {
    if (err) {
      console.error("Error actividad reciente:", err);
      res.status(500).json({ error: "Error interno" });
    } else {
      res.json(rows);
    }
  });
});

// Actividad últimos 7 días (para gráfico)
app.get("/dashboard/actividad-7dias", (req, res) => {
  db.all(`SELECT 
          DATE(fecha) as dia,
          COUNT(*) as mensajes,
          COUNT(DISTINCT numero) as conversaciones
          FROM mensajes 
          WHERE fecha >= date('now', '-6 days')
          GROUP BY DATE(fecha)
          ORDER BY dia ASC`, (err, rows) => {
    if (err) {
      console.error("Error actividad 7 días:", err);
      res.status(500).json({ error: "Error interno" });
    } else {
      res.json(rows);
    }
  });
});

/* ========================================================
   ENVÍO A LISTA ESPECÍFICA DE CONTACTOS
======================================================== */

app.post("/enviar-lista-contactos", async (req, res) => {
  try {
    const { numeros, mensaje } = req.body;

    if (!sock) {
      return res.status(500).json({ error: "WhatsApp no conectado" });
    }

    if (!numeros || !Array.isArray(numeros) || numeros.length === 0) {
      return res.status(400).json({ error: "Lista de números requerida" });
    }

    if (!mensaje) {
      return res.status(400).json({ error: "Mensaje requerido" });
    }

    let exitosos = 0;
    let errores = 0;
    const detalles = [];

    for (const numero of numeros) {
      try {
        console.log(`📋 Procesando número: ${numero}`);

        // 1. VERIFICAR SI EL CONTACTO EXISTE
        db.get("SELECT * FROM clientes WHERE numero = ?", [numero], async (err, row) => {
          if (err) {
            console.error(`❌ Error verificando contacto ${numero}:`, err);
            errores++;
            detalles.push({ numero, estado: "error", error: "Error en BD" });
            return;
          }

          // 2. SI NO EXISTE, CREARLO CON ETIQUETA "nuevo"
          if (!row) {
            console.log(`🆕 Creando nuevo contacto: ${numero}`);
            
            const nuevoCliente = {
              numero: numero,
              nombre: numero.replace('@s.whatsapp.net', ''),
              etiqueta: 'nuevo', // ← ESTA ES LA CLAVE
              nota: '',
              archivado: 0,
              ultima_interaccion: new Date().toISOString()
            };

            db.run(
              `INSERT INTO clientes (numero, nombre, etiqueta, nota, archivado, ultima_interaccion) 
               VALUES (?, ?, ?, ?, ?, ?)`,
              [nuevoCliente.numero, nuevoCliente.nombre, nuevoCliente.etiqueta, 
               nuevoCliente.nota, nuevoCliente.archivado, nuevoCliente.ultima_interaccion],
              function(insertErr) {
                if (insertErr) {
                  console.error(`❌ Error creando contacto ${numero}:`, insertErr);
                  errores++;
                  detalles.push({ numero, estado: "error", error: "Error creando contacto" });
                } else {
                  console.log(`✅ Contacto creado: ${numero}`);
                  // Continuar con el envío del mensaje
                  enviarMensajeYRegistrar(numero, mensaje);
                }
              }
            );
          } else {
            // 3. SI YA EXISTE, SOLO ENVIAR MENSAJE
            console.log(`✅ Contacto existente: ${numero} (etiqueta: ${row.etiqueta})`);
            enviarMensajeYRegistrar(numero, mensaje);
          }
        });

        // Función auxiliar para enviar mensaje y registrar
        const enviarMensajeYRegistrar = async (numero, mensaje) => {
          try {
            await sock.sendMessage(numero, { text: mensaje });
            exitosos++;

            // Guardar mensaje en base de datos
            const fecha = new Date().toISOString();
            guardarMensajeEnDB(numero, mensaje, 'enviado', fecha, null, null, 0);

            detalles.push({ numero, estado: "enviado" });
            console.log(`✅ Mensaje enviado a: ${numero}`);

          } catch (e) {
            console.error(`❌ Error enviando a ${numero}:`, e.message);
            errores++;
            detalles.push({ numero, estado: "error", error: e.message });
          }
        };

        // Pequeña pausa para evitar bloqueos
        await new Promise(resolve => setTimeout(resolve, 500));

      } catch (e) {
        console.error(`❌ Error general con ${numero}:`, e.message);
        errores++;
        detalles.push({ numero, estado: "error", error: e.message });
      }
    }

    // Esperar un poco para que se completen las operaciones de BD
    await new Promise(resolve => setTimeout(resolve, 2000));

    res.json({
      success: true,
      resumen: {
        total: numeros.length,
        exitosos: exitosos,
        errores: errores
      },
      detalles: detalles,
      mensaje: `Procesados ${numeros.length} números: ${exitosos} exitosos, ${errores} errores`
    });

  } catch (error) {
    console.error('❌ Error en envío a lista de contactos:', error);
    res.status(500).json({
      success: false,
      error: 'Error interno del servidor: ' + error.message
    });
  }
});


/* ========================================================
   SISTEMA DE ENVÍO MASIVO MULTI-IDIOMA CON CAMPAÑAS
======================================================== */

// Base de datos de campañas predefinidas
const campañasPredefinidas = {
  "es": {
    "🔥 Oferta Exclusiva Monety Trade": [
      "¡Oferta exclusiva Monety Trade! Deposite hoy y gane 50% de bono sobre el capital invertido para potenciar sus resultados desde el primer día. 💼 Monety Trade — invirtiendo a su lado.",
      "¡ÚLTIMA OPORTUNIDAD! Hoy DUPLICA tu capital en Monety Trade. Deposite ahora y reciba 100% de bono inmediato. Quien deja para después… pierde dinero. Monety Trade — acción ahora, resultado después. ⚡",
      "¡Atención! Oportunidad REAL y LIMITADA. ¿Activó hoy? Monety Trade coloca 100% más en su inversión. Es literalmente doblar su poder financiero en segundos. No existe motivo para esperar. 🔥",
      "Monety Trade está haciendo historia: Usted coloca 500, se convierte en 1000. Usted coloca 1000, se convierte en 2000. 100% DE BONO GARANTIZADO HOY. Si quiere aprovechar, es ahora. Mañana ya era. 💰"
    ],
    "🚀 Activación de Cuenta - Primer Inversión": [
      "¡Es hora de comenzar! Dé su primer paso en Monety Trade y active su cuenta con la inversión inicial. Las oportunidades no esperan — comience a invertir ahora. 🚀",
      "Su futuro financiero comienza hoy. Haga su primera inversión en Monety Trade y entre de lleno en el mercado con soporte profesional. Haga clic y avance al siguiente nivel. ⚡",
      "Monety Trade le llamó — ahora es usted quien decide. Haga la primera inversión y libere todos los beneficios de la plataforma. Quien actúa primero, gana primero. 🔥",
      "Active su inversión inicial ahora y comience a construir resultados en Monety Trade. El mejor momento es este. 💼",
      "¿Listo para comenzar? Su acceso ya está liberado — solo debe hacer la primera inversión en Monety Trade y activar todos los beneficios de su cuenta. 👉 Avance ahora.",
      "Atención: su perfil está aprobado, pero aún falta la primera inversión para liberar las operaciones. Entre ahora y finalice — esto garantiza su activación hoy mismo. ⚠️",
      "Comience hoy: Active su primera inversión y ya entre con ventaja en Monety Trade. 👉 Vamos a liberar su cuenta ahora?",
      "¿Ya imaginó dónde puede estar dentro de 6 meses si comienza hoy? Su primera inversión en Monety Trade es más que dinero — es elección, es cambio, es futuro. 💭",
      "Sé que tomar decisiones financieras no es fácil. Pero no está solo(a): después de su primera inversión, tendrá acompañamiento y dirección en Monety Trade. 🤝"
    ]
  },
  "pt": {
    "🔥 Oferta Exclusiva Monety Trade": [
      "Oferta exclusiva Monety Trade! Deposite hoje e ganhe 50% de bônus sobre o capital investido para potencializar seus resultados desde o primeiro dia. 💼 Monety Trade — investindo ao seu lado.",
      "ÚLTIMA CHAMADA! Hoje você DUPLICA o seu capital na Monety Trade. Deposite agora e receba 100% de bônus imediato. Quem deixa para depois… perde dinheiro. Monety Trade — ação agora, resultado depois. ⚡",
      "Atenção! Oportunidade REAL e LIMITADA. Ativou hoje? A Monety Trade coloca 100% a mais no seu investimento. É literalmente dobrar seu poder financeiro em segundos. Não existe motivo pra esperar. 🔥",
      "Monety Trade está fazendo história: Você coloca 500, vira 1000. Você coloca 1000, vira 2000. 100% DE BÔNUS GARANTIDO HOJE. Se quiser aproveitar, é agora. Amanhã já era. 💰"
    ],
    "🚀 Ativação de Conta - Primeiro Investimento": [
      "É hora de começar! Dê seu primeiro passo na Monety Trade e ative sua conta com o investimento inicial. Oportunidades não esperam — comece a investir agora. 🚀",
      "Seu futuro financeiro começa hoje. Faça seu primeiro investimento na Monety Trade e entre de vez no mercado com suporte profissional. Clique e avance para o próximo nível. ⚡",
      "Monety Trade te chamou — agora é você quem decide. Faça o primeiro investimento e libere todos os benefícios da plataforma. Quem age primeiro, lucra primeiro. 🔥",
      "Ative seu investimento inicial agora e comece a construir resultados na Monety Trade. O melhor momento é este. 💼",
      "Pronto para começar? Seu acesso já está liberado — basta fazer o primeiro investimento na Monety Trade e ativar todos os benefícios da sua conta. 👉 Avance agora.",
      "Atenção: seu perfil está aprovado, mas ainda falta o primeiro investimento para liberar as operações. Entre agora e finalize — isso garante sua ativação hoje mesmo. ⚠️",
      "Comece hoje: Ative seu primeiro investimento e já entre com vantagem na Monety Trade. 👉 Vamos liberar sua conta agora?",
      "Você já imaginou onde pode estar daqui a 6 meses se começar hoje? Seu primeiro investimento na Monety Trade é mais do que dinheiro — é escolha, é mudança, é futuro. 💭",
      "Eu sei que tomar decisão financeira não é fácil. Mas você não está sozinho(a): depois do seu primeiro investimento, você terá acompanhamento e direção na Monety Trade. 🤝"
    ]
  }
};

// Endpoint para obtener campañas por idioma
app.get("/campañas/:idioma", (req, res) => {
  const idioma = req.params.idioma;
  const campañas = campañasPredefinidas[idioma] || campañasPredefinidas["es"];
  res.json(campañas);
});

// Endpoint para envío masivo con variantes
app.post("/enviar-masivo-variantes", async (req, res) => {
  try {
    const { numeros, nombreCampaña, idioma, nombreAgente } = req.body;

    if (!sock) {
      return res.status(500).json({ error: "WhatsApp no conectado" });
    }

    if (!numeros || !Array.isArray(numeros) || numeros.length === 0) {
      return res.status(400).json({ error: "Lista de números requerida" });
    }

    // Obtener las variantes de la campaña seleccionada
    const campañas = campañasPredefinidas[idioma] || campañasPredefinidas["es"];
    const variantes = campañas[nombreCampaña];

    if (!variantes || variantes.length === 0) {
      return res.status(400).json({ error: "Campaña no encontrada" });
    }

    let exitosos = 0;
    let errores = 0;
    const detalles = [];

    for (let i = 0; i < numeros.length; i++) {
      try {
        // Seleccionar variante aleatoria
        const varianteAleatoria = variantes[Math.floor(Math.random() * variantes.length)];
        
        // Reemplazar {agente} si existe en el texto y si el contexto lo permite
        let mensajeFinal = varianteAleatoria;
        if (nombreAgente && mensajeFinal.includes('{agente}')) {
          mensajeFinal = mensajeFinal.replace(/{agente}/g, nombreAgente);
        }

        await sock.sendMessage(numeros[i], { text: mensajeFinal });
        exitosos++;

        // Guardar en base de datos
        const fecha = new Date().toISOString();
        guardarMensajeEnDB(numeros[i], mensajeFinal, 'enviado', fecha, null, null, 0);

        detalles.push({ 
          numero: numeros[i], 
          estado: "enviado",
          variante: mensajeFinal.substring(0, 50) + '...'
        });

        // Pausa aleatoria entre 1 y 60 segundos
        const pausaAleatoria = Math.floor(Math.random() * 60000) + 1000;
        await new Promise(resolve => setTimeout(resolve, pausaAleatoria));

      } catch (e) {
        errores++;
        detalles.push({ numero: numeros[i], estado: "error", error: e.message });
        console.error(`Error enviando a ${numeros[i]}:`, e.message);
      }
    }

    res.json({
      ok: true,
      resumen: {
        total: numeros.length,
        exitosos: exitosos,
        errores: errores
      },
      detalles: detalles
    });

  } catch (error) {
    console.error("Error en envío masivo con variantes:", error);
    res.status(500).json({ error: error.message });
  }
});
/* ========================================================
   INICIAR SERVIDOR
======================================================== */

server.listen(Number(process.env.PORT || 3000), () => {
  console.log("🟢 CRM activo en http://localhost:3000");
  console.log("🗄️ Base de datos inicializada");
  console.log("📱 Sistema listo para conectar WhatsApp");
  console.log("⏰ Sistema de recordatorios activo");
  console.log("📊 Dashboard en tiempo real activo"); // 👈 NUEVA LÍNEA
  iniciarWhatsApp();

});







