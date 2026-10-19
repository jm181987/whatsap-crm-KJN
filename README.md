# KNJ WhatsApp CRM

**Gestión de conversaciones de WhatsApp, contactos y seguimiento comercial, con administración de empresas y cuentas independientes.**

[![Node.js](https://img.shields.io/badge/Node.js-ESM-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![WhatsApp](https://img.shields.io/badge/WhatsApp-Baileys-25D366?logo=whatsapp&logoColor=white)](https://github.com/WhiskeySockets/Baileys)
[![Deploy](https://img.shields.io/badge/Deploy-Coolify-6366F1)](https://coolify.io/)

> **Estado del proyecto:** desarrollo activo. Las funciones nuevas por empresa utilizan rutas y tablas separadas; la bandeja y algunas funciones heredadas todavía no se han migrado completamente. No debe considerarse un CRM multiempresa totalmente aislado hasta completar esa migración y sus pruebas.

## Qué permite hacer

- Conectar WhatsApp mediante **Baileys** y código QR.
- Consultar y enviar mensajes de texto en las bandejas implementadas.
- Administrar empresas, miembros, asignaciones y varias cuentas de WhatsApp.
- Acceder a una **bandeja por empresa** y cambiar entre cuentas autorizadas.
- Gestionar contactos, estados, notas, archivado, recordatorios y seguimientos por empresa.
- Consultar indicadores por cuenta y conteos de contactos por estado.
- Gestionar respuestas rápidas por cuenta, exportaciones CSV e informes de conversaciones.
- Enviar y consultar adjuntos de imagen, video, audio y documentos en la bandeja de empresa, sujetos a los formatos y límites admitidos.
- Ejecutar envíos de texto a un máximo de 20 contactos por operación, con confirmación de consentimiento y permisos de administrador de empresa.
- Previsualizar e importar registros heredados a una cuenta elegida por el administrador global; los registros antiguos no incluyen una empresa de origen verificable.
- Administrar operadores y revisar funciones de administración.

### Estado funcional

| Área | Situación |
| --- | --- |
| Sesiones de WhatsApp por cuenta de empresa | Implementadas, requieren volumen persistente y validación operativa |
| Bandeja de texto por empresa | Implementada |
| Contactos, notas, estados y archivado por cuenta | Implementados |
| Recordatorios y seguimientos por cuenta | Implementados |
| Indicadores y conteos de Kanban por cuenta | Implementados |
| Bandeja principal y módulos históricos | **Siguen siendo heredados y no están completamente migrados** |
| Kanban por empresa | Estados y conteos implementados; tablero visual integral pendiente |
| Multimedia entrante/saliente por empresa | Rutas y almacenamiento implementados; requiere pruebas reales de cifrado, recepción y reproducción |
| Envío masivo de texto por empresa | Implementado con límite de 20 destinatarios y confirmación de consentimiento; pendiente de validar | 
| Respuestas rápidas, CSV e informes por cuenta | Rutas implementadas; pendiente de validar funcionalidad integral |
| Automatizaciones y reportes avanzados | Pendientes de completar |
| Importación de datos heredados a empresas | Vista previa e importación manual implementadas; verificar titularidad y respaldar antes |

**Importante:** las rutas heredadas están restringidas para determinados usuarios de empresas para evitar exponer datos de la conexión principal. No deben desbloquearse sin controles de acceso por empresa y cuenta.

## Arquitectura

| Archivo | Responsabilidad |
| --- | --- |
| `index.js` | Servidor Express, autenticación, endpoints, integración principal de WhatsApp |
| `tenant-whatsapp.js` | Gestión de conexiones Baileys por cuenta de empresa |
| `postgres.js` | Conexión a PostgreSQL e inicialización de esquema |
| `public/index.html` | Interfaz del CRM y bandejas |
| `package.json` | Dependencias y comando de inicio |

**Tecnologías:** Node.js (módulos ES), Express, PostgreSQL (`pg`), Baileys y JavaScript en el navegador. La integración utiliza **Baileys**, no Evolution API.

## Requisitos

- Node.js y npm compatibles con las dependencias del proyecto.
- PostgreSQL accesible desde el contenedor o servidor.
- Un directorio **persistente y escribible** para las credenciales de WhatsApp.
- HTTPS y configuración de red apropiada para la instancia de producción.

## Instalación

```bash
git clone https://github.com/jm181987/whatsap-crm-KJN.git
cd whatsap-crm-KJN
npm install
```

Configurá las variables de entorno en el servicio (no las subas al repositorio):

```dotenv
DATABASE_URL=postgresql://USUARIO:CONTRASENA@HOST:5432/BASE
CRM_USER=administrador
CRM_PASSWORD=CAMBIAR_POR_UNA_CONTRASENA_SEGURA
SESSION_DIR=/app/session
PORT=3000
```

`DATABASE_URL` es obligatoria. `CRM_USER` y `CRM_PASSWORD` corresponden a la cuenta principal de acceso según la configuración actual de la aplicación. Definí valores fuertes y únicos.

Iniciá el servidor:

```bash
npm start
```

La aplicación escucha en el puerto indicado por `PORT` (3000 de forma predeterminada). Existe una ruta de comprobación `GET /health`.

## Despliegue en Coolify

1. Creá o seleccioná un servicio conectado al repositorio.
2. Configurá el comando de inicio **`npm start`** y el puerto **3000**, salvo que lo hayas cambiado.
3. Agregá `DATABASE_URL`, `CRM_USER`, `CRM_PASSWORD`, `SESSION_DIR` y, si corresponde, `PORT` como variables privadas.
4. Montá un **volumen persistente en `/app/session`** y usá `SESSION_DIR=/app/session`. El proceso debe tener permisos de lectura y escritura.
5. Configurá el dominio y HTTPS, desplegá y revisá los logs de arranque.
6. Comprobá `/health` y probá cada conexión de WhatsApp antes de habilitar usuarios.

### Dónde se guardan las sesiones

Con `SESSION_DIR=/app/session`:

```text
/app/session/
├── creds.json              # Sesión principal, si está vinculada
├── ...                     # Claves de la sesión principal
└── tenants/
    └── <empresa_id>/
        └── <cuenta_id>/
            ├── creds.json
            └── ...         # Claves de esa cuenta
```

No borres `/app/session` completo para resolver un problema de una sola empresa. Tampoco borres las credenciales mientras el proceso las esté usando. Si venís de una instalación anterior, verificá la ubicación de las sesiones antes de cambiar el volumen.

> **Respaldo:** hacé copias de PostgreSQL y del volumen de sesiones antes de actualizar o realizar operaciones destructivas. Protegé los respaldos: contienen información sensible.

## Uso multiempresa

1. Ingresá con un usuario autorizado.
2. Desde **Administración**, creá la empresa y agregá su cuenta de WhatsApp.
3. Configurá los miembros y las asignaciones según corresponda.
4. Conectá la cuenta y escaneá el QR con el teléfono correspondiente.
5. Abrí **Bandejas de empresas** (🏢), seleccioná empresa y cuenta, y consultá sus conversaciones.

La empresa y la cuenta seleccionadas determinan el alcance de los endpoints nuevos. El administrador principal puede acceder a las empresas desde la interfaz de administración; los miembros tienen controles de pertenencia y asignación.

**Atención:** las funcionalidades antiguas que siguen usando tablas globales no adquieren aislamiento multiempresa por el simple hecho de elegir una empresa en la interfaz.

### Archivos, medios y mensajes cifrados

Los archivos multimedia recibidos se asocian a la cuenta y se guardan bajo su directorio de sesión, en `tenants/<empresa_id>/<cuenta_id>/media/`. Su descarga pasa por una ruta que valida permisos. El envío multimedia admite un conjunto limitado de formatos y archivos de hasta **8 MB** mediante la API actual. **La presencia de código no garantiza que Baileys pueda descifrar todos los mensajes**: comprobá recepción de texto, imagen, video, audio y documentos con cada cuenta real, incluida una reconexión y un reinicio de Coolify. Reconectar no recupera necesariamente mensajes cifrados antiguos.

### Importación del CRM heredado

La importación de contactos y mensajes históricos requiere autorización del administrador global y confirmación `IMPORTAR`. **No detecta automáticamente a qué empresa pertenecen los datos antiguos.** Antes de ejecutarla, verificá la cuenta destino, hacé una copia de seguridad y revisá la vista previa. No importes los mismos datos indiscriminadamente a varias empresas.

### Eliminación de empresas

La interfaz requiere escribir **`ELIMINAR`** para confirmar. La operación elimina los datos asociados a esa empresa de las tablas multiempresa implementadas y procura cerrar sus conexiones y borrar los archivos de sesión correspondientes. **Es irreversible**; realizá un respaldo previamente. No elimina mensajes almacenados en los teléfonos de los participantes.

## Diagnóstico de incidencias

| Síntoma | Qué revisar |
| --- | --- |
| `no available server` / 502 | Logs de arranque de Node, errores de sintaxis, conexión PostgreSQL, puerto y salud del contenedor |
| `DATABASE_URL es obligatoria` | Variable `DATABASE_URL` y acceso a PostgreSQL |
| Se solicita QR nuevamente tras desplegar | Persistencia y permisos de `SESSION_DIR`; cambios de ruta o pérdida de credenciales |
| Conexión WhatsApp abierta pero sin mensajes | Eventos de Baileys, procesamiento de mensajes, credenciales, permisos y errores de persistencia |
| «Esperando este mensaje» o errores de cifrado | Estado de las claves de extremo a extremo; reconectar **no garantiza** recuperar mensajes que no pudieron descifrarse |
| No aparecen fotos, audios o videos en una bandeja de empresa | Revisá eventos `messages.upsert`, descifrado, descarga del adjunto, permisos de archivos y errores en logs; las rutas multimedia existen, pero requieren validación con dispositivos reales |
| Una función devuelve 403 | Verificá permisos y si la ruta pertenece al CRM heredado, que puede estar restringido |

**No compartas** archivos `creds.json`, claves de sesión, contraseñas, tokens ni cadenas de conexión en incidencias públicas.

### Comprobación después de cada despliegue

Antes de habilitar nuevas empresas, verificá estos escenarios en un entorno de prueba:

1. `GET /health` responde correctamente y PostgreSQL inicializa sin errores.
2. La sesión principal y dos cuentas de **empresas distintas** conectan, conservan sus credenciales tras reiniciar Coolify y no comparten directorios.
3. Cada cuenta recibe y envía **texto**, y recibe **imagen, video, audio y documento**; comprobá que el archivo se pueda abrir desde la bandeja autorizada.
4. Dos operadores de empresas distintas no pueden acceder a conversaciones, contactos, adjuntos, reportes ni operaciones de la otra empresa, incluso llamando a la API directamente.
5. Los contactos, estados, notas, recordatorios y seguimientos permanecen separados al cambiar de empresa.
6. Probá una reconexión de una sola cuenta sin borrar el directorio completo de sesiones.
7. Comprobá la exportación y, antes de importar datos heredados, revisá la vista previa y el destino.

Si WhatsApp indica **conectado** pero no llegan mensajes, no asumas que el QR o la conexión de red son suficientes: revisá el evento entrante, la disponibilidad de claves de cifrado y la persistencia en PostgreSQL. El aviso de Baileys sobre `printQRInTerminal` obsoleto no demuestra por sí solo una falla de conexión.

### Alcance y criterios para dar por finalizada la migración

La plataforma debe ofrecer la misma lógica funcional para cada empresa creada. Para considerarla completa todavía falta validar y, donde corresponda, terminar la adaptación de la **bandeja principal heredada, Kanban visual, automatizaciones, envíos avanzados, reportes y sesión original** al contexto de empresa/cuenta. Las rutas heredadas restringidas deben permanecer protegidas hasta que exista aislamiento comprobado. No se debe declarar terminada la migración basándose únicamente en la existencia de endpoints o controles visuales.

## Seguridad y consideraciones operativas

- Usá HTTPS, contraseñas robustas y acceso restringido a PostgreSQL.
- Resguardá los archivos de sesión y los respaldos; no los subas a Git.
- No compartas una misma carpeta de credenciales entre dos cuentas.
- Verificá permisos y aislamiento de datos antes de incorporar más empresas.
- Baileys es una integración no oficial de WhatsApp. Su funcionamiento puede cambiar y debe evaluarse frente a las condiciones aplicables del servicio.
- No realices envíos masivos sin consentimiento ni sin cumplir las políticas pertinentes.
- Validá migraciones, flujos de medios, reconexiones y restauración de respaldos en un entorno de prueba.

## Limitaciones conocidas y validación

- La bandeja original y algunas funciones antiguas siguen usando datos globales. Las nuevas rutas por empresa no las convierten automáticamente en multiempresa.
- El aislamiento de contactos, mensajes y permisos de las nuevas rutas debe validarse con **dos empresas y dos usuarios distintos**, intentando acceso cruzado.
- Las automatizaciones antiguas, el Kanban visual integral y la integración total de la sesión principal aún requieren trabajo.
- Los medios y las claves de Baileys deben conservarse en un volumen persistente; las reconexiones y la recepción deben probarse después de cada despliegue.
- Los cambios del repositorio no equivalen a pruebas completadas en Coolify.

## Contribuciones y mantenimiento

Para reportar un fallo, indicá qué empresa y módulo están afectados **sin publicar datos personales**, la acción realizada, el resultado esperado, el resultado obtenido y los mensajes relevantes del log con secretos ocultos.

Este README documenta el estado conocido del código; **no sustituye pruebas de integración ni certifica que todos los módulos estén listos para producción**.

---

### Desarrollado por KNJ

**KNJ · Soluciones digitales y automatización**

[Conocé KNJ](https://www.marketingknj.site/) · [Repositorio en GitHub](https://github.com/jm181987/whatsap-crm-KJN)

Documentación y mantenimiento: **KNJ**. Se conservan las atribuciones y licencias de las dependencias y proyectos de terceros.
