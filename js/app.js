// =====================================================
// E3 - Prototipo de algoritmos criptográficos
// AES-256-GCM + RSA (OAEP para cifrar, PKCS#1 v1.5 para firmar)
// Se usa la Web Crypto API del navegador (crypto.subtle)
// =====================================================

const subtle = window.crypto.subtle;
const codificador = new TextEncoder();
const decodificador = new TextDecoder();

// Algoritmos que se van a usar
const RSA_CIFRADO = { name: "RSA-OAEP", hash: "SHA-256" };
const RSA_FIRMA = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };

// Aquí se guardan las claves de B, C y T
let claves = {};
let certificadoB = null; // firma de T sobre la clave pública de B
let ultimoPaquete = null; // último mensaje cifrado de A para B
let ultimaFirma = null;

// ---------------- Funciones de ayuda ----------------

// Convierte bytes a hexadecimal
function aHex(buffer) {
  let bytes = new Uint8Array(buffer);
  let texto = "";
  for (let i = 0; i < bytes.length; i++) {
    texto += bytes[i].toString(16).padStart(2, "0");
  }
  return texto;
}

// Convierte bytes a Base64
function aBase64(buffer) {
  let bytes = new Uint8Array(buffer);
  let texto = "";
  for (let i = 0; i < bytes.length; i++) {
    texto += String.fromCharCode(bytes[i]);
  }
  return btoa(texto);
}

// Convierte Base64url (como viene en JWK) a BigInt
function base64urlABigInt(b64url) {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  let binario = atob(b64);
  let hex = "";
  for (let i = 0; i < binario.length; i++) {
    hex += binario.charCodeAt(i).toString(16).padStart(2, "0");
  }
  return BigInt("0x" + hex);
}

// Exponenciación modular (base^exp mod m), se usa para "descifrar" la firma
function potenciaModular(base, exp, mod) {
  let resultado = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) resultado = (resultado * base) % mod;
    exp = exp / 2n;
    base = (base * base) % mod;
  }
  return resultado;
}

// Formato PEM para mostrar las claves
function aPEM(buffer, tipo) {
  let b64 = aBase64(buffer);
  let lineas = b64.match(/.{1,64}/g).join("\n");
  return "-----BEGIN " + tipo + "-----\n" + lineas + "\n-----END " + tipo + "-----";
}

// Huella digital de una clave pública (primeros 16 bytes del SHA-256)
async function huella(spki) {
  let hash = await subtle.digest("SHA-256", spki);
  let hex = aHex(hash).substring(0, 32).toUpperCase();
  return hex.match(/../g).join(":");
}

function escapar(texto) {
  return String(texto).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function tiempo(ms) {
  return ms.toFixed(2) + " ms";
}

function tamano(bytes) {
  if (bytes < 1024) return bytes + " bytes";
  return (bytes / 1024).toFixed(1) + " KB";
}

// Agrega una línea a la bitácora
function bitacora(texto) {
  let li = document.createElement("li");
  let hora = new Date().toLocaleTimeString();
  li.textContent = "[" + hora + "] " + texto;
  document.getElementById("bitacora").prepend(li);
}

// Agrega un paso a la sección de resultados
// tipo puede ser: "", "bien", "mal" o "aviso"
function agregarPaso(contenedor, titulo, contenido, tipo) {
  let div = document.createElement("div");
  div.className = "paso " + (tipo || "");
  div.innerHTML = "<h3>" + titulo + "</h3>" + contenido;
  document.getElementById(contenedor).appendChild(div);
}

// Muestra un dato con su etiqueta
function dato(etiqueta, valor) {
  return '<span class="etiqueta">' + etiqueta + '</span><div class="dato">' + escapar(valor) + "</div>";
}

function limpiar(id) {
  document.getElementById(id).innerHTML = "";
}

// ---------------- Generación de claves ----------------

// Genera un par RSA y lo prepara para cifrar y para firmar.
// Es el mismo par de claves, solo se importa dos veces porque
// la Web Crypto API pide indicar el algoritmo.
async function generarParticipante(nombre, bits) {
  let par = await subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: bits,
      publicExponent: new Uint8Array([1, 0, 1]), // e = 65537
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  let spki = await subtle.exportKey("spki", par.publicKey);
  let pkcs8 = await subtle.exportKey("pkcs8", par.privateKey);
  let jwk = await subtle.exportKey("jwk", par.publicKey);

  let clavePrivadaFirma = await subtle.importKey("pkcs8", pkcs8, RSA_FIRMA, false, ["sign"]);
  let clavePublicaFirma = await subtle.importKey("spki", spki, RSA_FIRMA, false, ["verify"]);

  return {
    nombre: nombre,
    bits: bits,
    publica: par.publicKey,
    privada: par.privateKey,
    privadaFirma: clavePrivadaFirma,
    publicaFirma: clavePublicaFirma,
    spki: spki,
    pkcs8: pkcs8,
    n: base64urlABigInt(jwk.n),
    e: base64urlABigInt(jwk.e),
    huella: await huella(spki),
  };
}

function mostrarClaves() {
  let roles = { B: "Receptor", C: "Intruso", T: "Amigo en común" };
  let html = '<div class="tabla-scroll"><table><tr><th>Participante</th><th>Huella de la clave pública</th><th>Claves</th></tr>';
  for (let id of ["B", "C", "T"]) {
    let p = claves[id];
    html += "<tr><td><b>" + id + "</b> - " + roles[id] + "<br><small>RSA " + p.bits + " bits</small></td>";
    html += '<td class="mono">' + p.huella + "</td>";
    html += "<td><details><summary>Ver clave pública</summary><div class='dato'>" + escapar(aPEM(p.spki, "PUBLIC KEY")) + "</div></details>";
    html += "<details><summary>Ver clave privada</summary><div class='dato'>" + escapar(aPEM(p.pkcs8, "PRIVATE KEY")) + "</div></details></td></tr>";
  }
  html += "</table></div>";
  html += '<p class="nota">A no necesita un par de claves para mandar mensajes cifrados, solo usa la clave pública de B.</p>';
  document.getElementById("tablaClaves").innerHTML = html;
}

function activarBotones(activo) {
  let ids = ["btnGenerar", "btnCifrar", "btnFirmar", "btnVerificar", "btnMitm", "btnRend"];
  for (let id of ids) document.getElementById(id).disabled = !activo;
}

async function generarClaves() {
  let bits = parseInt(document.getElementById("tamClave").value);
  let estado = document.getElementById("estadoClaves");
  activarBotones(false);
  estado.textContent = "Generando claves de " + bits + " bits, espera un momento...";

  let inicio = performance.now();
  claves.B = await generarParticipante("B", bits);
  claves.C = await generarParticipante("C", bits);
  claves.T = await generarParticipante("T", bits);

  // T firma la clave pública de B (esto sería como un certificado)
  certificadoB = await subtle.sign(RSA_FIRMA, claves.T.privadaFirma, claves.B.spki);
  let fin = performance.now();

  estado.textContent = "Claves generadas en " + tiempo(fin - inicio) + ". T ya firmó la clave pública de B.";
  bitacora("Se generaron las claves RSA de " + bits + " bits para B, C y T");
  mostrarClaves();
  activarBotones(true);
}

// ---------------- Cifrado híbrido (AES + RSA) ----------------

async function cifrarHibrido(mensaje, clavePublicaRSA) {
  let t0 = performance.now();
  // 1. Clave de sesión AES de 256 bits
  let claveAES = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  // 2. Vector de inicialización de 12 bytes
  let iv = crypto.getRandomValues(new Uint8Array(12));
  // 3. Se cifra el mensaje con AES
  // el mensaje puede venir como texto o como bytes
  let bytesMensaje = typeof mensaje === "string" ? codificador.encode(mensaje) : mensaje;
  let criptograma = await subtle.encrypt({ name: "AES-GCM", iv: iv }, claveAES, bytesMensaje);
  let t1 = performance.now();
  // 4. Se cifra la clave de sesión con RSA
  let claveCruda = await subtle.exportKey("raw", claveAES);
  let claveCifrada = await subtle.encrypt(RSA_CIFRADO, clavePublicaRSA, claveCruda);
  let t2 = performance.now();

  return { claveCruda, iv, criptograma, claveCifrada, tiempoAES: t1 - t0, tiempoRSA: t2 - t1 };
}

async function descifrarHibrido(paquete, clavePrivadaRSA) {
  let t0 = performance.now();
  // 1. Se recupera la clave de sesión con la clave privada RSA
  let claveCruda = await subtle.decrypt(RSA_CIFRADO, clavePrivadaRSA, paquete.claveCifrada);
  let t1 = performance.now();
  // 2. Se descifra el mensaje con AES
  let claveAES = await subtle.importKey("raw", claveCruda, "AES-GCM", false, ["decrypt"]);
  let textoPlano = await subtle.decrypt({ name: "AES-GCM", iv: paquete.iv }, claveAES, paquete.criptograma);
  let t2 = performance.now();

  return { claveCruda, mensaje: decodificador.decode(textoPlano), tiempoRSA: t1 - t0, tiempoAES: t2 - t1 };
}

function paqueteJSON(p) {
  return JSON.stringify(
    {
      claveSesionCifrada: aBase64(p.claveCifrada),
      iv: aBase64(p.iv),
      mensajeCifrado: aBase64(p.criptograma),
    },
    null,
    2
  );
}

// ---------------- 1. Confidencialidad ----------------

async function confidencialidad() {
  limpiar("resConf");
  let mensaje = document.getElementById("txtMensaje").value;
  let B = claves.B;

  agregarPaso("resConf", "Paso 1: B le envía a A su clave pública",
    dato("Huella de la clave pública de B", B.huella));

  let paquete = await cifrarHibrido(mensaje, B.publica);

  agregarPaso("resConf", "Paso 2: A cifra el mensaje con AES-256",
    dato("Clave de sesión AES (hex)", aHex(paquete.claveCruda)) +
    dato("IV (hex)", aHex(paquete.iv)) +
    dato("Mensaje cifrado (" + tamano(paquete.criptograma.byteLength) + ")", aBase64(paquete.criptograma)) +
    "<p>Tiempo AES: " + tiempo(paquete.tiempoAES) + "</p>");

  agregarPaso("resConf", "Paso 3: A cifra la clave de sesión con la clave pública de B (RSA)",
    dato("Clave de sesión cifrada (" + tamano(paquete.claveCifrada.byteLength) + ")", aBase64(paquete.claveCifrada)) +
    "<p>Tiempo RSA: " + tiempo(paquete.tiempoRSA) + "</p>");

  agregarPaso("resConf", "Paso 4: A le manda el paquete a B", dato("Paquete", paqueteJSON(paquete)));

  let resultado = await descifrarHibrido(paquete, B.privada);
  let coincide = resultado.mensaje === mensaje;

  agregarPaso("resConf", "Paso 5: B descifra con su clave privada",
    dato("Clave de sesión recuperada", aHex(resultado.claveCruda)) +
    dato("Mensaje recuperado", resultado.mensaje) +
    "<p>Tiempo RSA: " + tiempo(resultado.tiempoRSA) + " | Tiempo AES: " + tiempo(resultado.tiempoAES) + "</p>" +
    (coincide ? '<p class="ok">✔ El mensaje es igual al original</p>' : '<p class="error">✘ El mensaje no coincide</p>'),
    "bien");

  ultimoPaquete = paquete;
  document.getElementById("btnAlterar").disabled = false;
  document.getElementById("btnIntrusoDescifra").disabled = false;
  bitacora("A cifró un mensaje para B y B lo descifró correctamente");
}

async function alterarMensaje() {
  // Se cambia un bit del mensaje cifrado
  let copia = new Uint8Array(ultimoPaquete.criptograma.slice(0));
  copia[0] = copia[0] ^ 1;
  let paqueteAlterado = { ...ultimoPaquete, criptograma: copia.buffer };

  try {
    await descifrarHibrido(paqueteAlterado, claves.B.privada);
    agregarPaso("resConf", "Prueba: mensaje alterado", '<p class="error">B no detectó el cambio</p>', "mal");
  } catch (e) {
    agregarPaso("resConf", "Prueba: alguien cambió un bit del mensaje cifrado",
      '<p class="ok">✔ B rechaza el mensaje.</p><p>AES-GCM tiene una etiqueta de autenticación, si el criptograma cambia el descifrado falla.</p>',
      "bien");
    bitacora("Se alteró el criptograma y AES-GCM lo detectó");
  }
}

async function intrusoDescifra() {
  try {
    await descifrarHibrido(ultimoPaquete, claves.C.privada);
    agregarPaso("resConf", "Prueba: C intenta descifrar", '<p class="error">C pudo descifrar</p>', "mal");
  } catch (e) {
    agregarPaso("resConf", "Prueba: C intenta descifrar con su clave privada",
      '<p class="ok">✔ C no puede recuperar la clave de sesión.</p><p>Solo la clave privada de B sirve para descifrar lo que se cifró con la clave pública de B.</p>',
      "bien");
    bitacora("C intentó descifrar el mensaje y no pudo");
  }
}

// ---------------- 2. Autenticación (firma digital) ----------------

async function firmar() {
  let mensaje = document.getElementById("txtFirma").value;
  let resumen = await subtle.digest("SHA-256", codificador.encode(mensaje));
  ultimaFirma = await subtle.sign(RSA_FIRMA, claves.B.privadaFirma, codificador.encode(mensaje));

  document.getElementById("txtRecibido").value = mensaje;
  limpiar("resFirma");
  agregarPaso("resFirma", "B firma el mensaje",
    dato("r(m) = SHA-256 del mensaje", aHex(resumen)) +
    dato("Firma = r(m) cifrado con la clave privada de B (Base64)", aBase64(ultimaFirma)));
  bitacora("B firmó un mensaje");
}

async function verificar() {
  if (!ultimaFirma) return;
  let B = claves.B;
  let recibido = document.getElementById("txtRecibido").value;

  // A "descifra" la firma con la clave pública de B: firma^e mod n
  let firmaNumero = BigInt("0x" + aHex(ultimaFirma));
  let bloque = potenciaModular(firmaNumero, B.e, B.n).toString(16).padStart(B.bits / 4, "0");
  // Los últimos 32 bytes (64 caracteres hex) del bloque son el hash r(m)
  let rm = bloque.substring(bloque.length - 64);

  // A calcula su propio resumen r'(m)
  let rPrima = aHex(await subtle.digest("SHA-256", codificador.encode(recibido)));

  // También se verifica con la función de la API
  let valida = await subtle.verify(RSA_FIRMA, B.publicaFirma, ultimaFirma, codificador.encode(recibido));

  let iguales = rm === rPrima;
  agregarPaso("resFirma", "A verifica la firma con la clave pública de B",
    dato("Bloque obtenido al descifrar la firma", bloque.substring(0, 24) + " ... " + rm) +
    dato("r(m) sacado de la firma", rm) +
    dato("r'(m) calculado por A", rPrima) +
    "<p>verify() de la API: " + valida + "</p>" +
    (iguales && valida
      ? '<p class="ok">✔ r(m) = r\'(m), el mensaje es auténtico y viene de B</p>'
      : '<p class="error">✘ r(m) ≠ r\'(m), el mensaje fue modificado</p>'),
    iguales && valida ? "bien" : "mal");
  bitacora(iguales ? "A verificó la firma: auténtico" : "A verificó la firma: mensaje alterado");
}

// ---------------- 3. Ataque de intermediario ----------------

async function ataqueIntermediario() {
  limpiar("resMitm");
  let intercepta = document.getElementById("chkIntercepta").checked;
  let revisaCert = document.getElementById("chkCertificado").checked;
  let mensaje = document.getElementById("txtMitm").value;
  let B = claves.B, C = claves.C, T = claves.T;

  agregarPaso("resMitm", "T (amigo en común) firma la clave pública de B",
    dato("Certificado de B (firma de T)", aBase64(certificadoB)));

  // La clave que le llega a A depende de si C intercepta o no
  let claveRecibida = intercepta ? C : B;

  if (intercepta) {
    agregarPaso("resMitm", "A pide la clave de B pero C la intercepta y manda la suya",
      dato("Huella que recibe A", claveRecibida.huella) +
      dato("Huella real de B", B.huella) +
      "<p>C reenvía el certificado de B porque no puede falsificar la firma de T.</p>", "aviso");
  } else {
    agregarPaso("resMitm", "A pide la clave de B y le llega bien",
      dato("Huella que recibe A", claveRecibida.huella), "bien");
  }

  if (revisaCert) {
    let certValido = await subtle.verify(RSA_FIRMA, T.publicaFirma, certificadoB, claveRecibida.spki);
    if (!certValido) {
      agregarPaso("resMitm", "A revisa el certificado de T",
        '<p class="ok">✔ La firma de T no corresponde a la clave recibida. A descarta la clave y no manda nada.</p>', "bien");
      agregarPaso("resMitm", "Resultado", "<p><b>Ataque detenido.</b> Gracias a la firma del amigo en común A detectó que la clave era falsa.</p>", "bien");
      bitacora("A detectó la clave falsa de C con el certificado de T");
      return;
    }
    agregarPaso("resMitm", "A revisa el certificado de T", '<p class="ok">✔ La clave sí es de B</p>', "bien");
  } else {
    agregarPaso("resMitm", "A acepta la clave sin revisarla", "<p>A confía en que la clave es de B.</p>", intercepta ? "mal" : "aviso");
  }

  // A cifra con la clave que recibió
  let publicaRecibida = await subtle.importKey("spki", claveRecibida.spki, RSA_CIFRADO, false, ["encrypt"]);
  let paquete = await cifrarHibrido(mensaje, publicaRecibida);
  agregarPaso("resMitm", "A cifra el mensaje con la clave que cree que es de B", dato("Paquete", paqueteJSON(paquete)));

  let paqueteParaB = paquete;
  if (intercepta) {
    let leido = await descifrarHibrido(paquete, C.privada);
    agregarPaso("resMitm", "C intercepta el paquete y lo descifra con su clave privada",
      dato("Lo que lee C", leido.mensaje), "mal");
    paqueteParaB = await cifrarHibrido(leido.mensaje, B.publica);
    agregarPaso("resMitm", "C lo vuelve a cifrar con la clave real de B y se lo manda", "<p>Así B no se da cuenta.</p>", "aviso");
  }

  let deB = await descifrarHibrido(paqueteParaB, B.privada);
  agregarPaso("resMitm", "B descifra el mensaje", dato("Mensaje que recibe B", deB.mensaje), "bien");

  if (intercepta) {
    // C se hace pasar por B firmando un documento falso
    let falso = "Cambio de planes, la entrega se movió al viernes y yo subo el archivo final. - B";
    let firmaFalsa = await subtle.sign(RSA_FIRMA, C.privadaFirma, codificador.encode(falso));
    let publicaFirmaRecibida = await subtle.importKey("spki", claveRecibida.spki, RSA_FIRMA, false, ["verify"]);
    let aceptada = await subtle.verify(RSA_FIRMA, publicaFirmaRecibida, firmaFalsa, codificador.encode(falso));
    agregarPaso("resMitm", "C firma un documento falso y A lo verifica",
      dato("Documento", falso) + "<p>Resultado en A: <b>" + (aceptada ? "firma válida, A cree que es de B" : "firma inválida") + "</b></p>", "mal");
    agregarPaso("resMitm", "Resultado",
      "<p><b>El ataque funcionó.</b> C leyó el mensaje y se hizo pasar por B sin que ninguno se diera cuenta. Activa la opción del certificado de T y vuelve a ejecutar.</p>", "mal");
    bitacora("Ataque de intermediario: C leyó el mensaje y suplantó a B");
  } else {
    agregarPaso("resMitm", "Resultado", "<p>Sin intermediario solo B puede leer el mensaje.</p>", "bien");
    bitacora("Comunicación normal entre A y B");
  }
}

// ---------------- 4. Rendimiento ----------------

function datosAleatorios(tam) {
  let datos = new Uint8Array(tam);
  // getRandomValues solo acepta 65536 bytes por llamada
  for (let i = 0; i < tam; i += 65536) {
    crypto.getRandomValues(datos.subarray(i, Math.min(tam, i + 65536)));
  }
  return datos;
}

async function rendimiento() {
  let kb = parseInt(document.getElementById("tamDatos").value);
  let tam = kb * 1024;
  let B = claves.B;
  let datos = datosAleatorios(tam);
  document.getElementById("resRend").innerHTML = "<p class='nota'>Midiendo...</p>";
  document.getElementById("btnRend").disabled = true;

  let filas = [];

  // AES
  let claveAES = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  let iv = crypto.getRandomValues(new Uint8Array(12));
  let t0 = performance.now();
  let cAES = await subtle.encrypt({ name: "AES-GCM", iv: iv }, claveAES, datos);
  let t1 = performance.now();
  await subtle.decrypt({ name: "AES-GCM", iv: iv }, claveAES, cAES);
  let t2 = performance.now();
  filas.push({ nombre: "Solo AES-256", cifrar: t1 - t0, descifrar: t2 - t1, tam: cAES.byteLength });

  // RSA por bloques. Con OAEP-SHA256 cada bloque puede tener k - 66 bytes
  let k = B.bits / 8;
  let bloque = k - 66;
  let bloquesCifrados = [];
  t0 = performance.now();
  for (let i = 0; i < tam; i += bloque) {
    bloquesCifrados.push(await subtle.encrypt(RSA_CIFRADO, B.publica, datos.subarray(i, Math.min(tam, i + bloque))));
  }
  t1 = performance.now();
  for (let b of bloquesCifrados) {
    await subtle.decrypt(RSA_CIFRADO, B.privada, b);
  }
  t2 = performance.now();
  filas.push({ nombre: "Solo RSA (" + bloquesCifrados.length + " bloques)", cifrar: t1 - t0, descifrar: t2 - t1, tam: bloquesCifrados.length * k });

  // Híbrido
  t0 = performance.now();
  let paquete = await cifrarHibrido(datos, B.publica);
  t1 = performance.now();
  await descifrarHibrido(paquete, B.privada);
  t2 = performance.now();
  filas.push({ nombre: "Híbrido (AES + RSA)", cifrar: t1 - t0, descifrar: t2 - t1, tam: paquete.criptograma.byteLength + paquete.claveCifrada.byteLength });

  // Tabla
  let maximo = Math.max(...filas.map(f => f.cifrar + f.descifrar));
  let html = '<div class="tabla-scroll"><table><tr><th>Método</th><th>Cifrar</th><th>Descifrar</th><th>Total</th><th>Tamaño cifrado</th></tr>';
  for (let f of filas) {
    let total = f.cifrar + f.descifrar;
    let ancho = Math.max(1, (total / maximo) * 100);
    html += "<tr><td>" + f.nombre + "</td><td>" + tiempo(f.cifrar) + "</td><td>" + tiempo(f.descifrar) + "</td>";
    html += '<td style="min-width:130px"><div class="barra" style="width:' + ancho + '%"></div>' + tiempo(total) + "</td>";
    html += "<td>" + tamano(f.tam) + "</td></tr>";
  }
  html += "</table></div>";

  let veces = (filas[1].cifrar + filas[1].descifrar) / (filas[0].cifrar + filas[0].descifrar);
  html += "<p>Con " + kb + " KB y RSA de " + B.bits + " bits, RSA solo fue aproximadamente <b>" + veces.toFixed(0) +
    " veces más lento</b> que AES, y el cifrado ocupó " + tamano(filas[1].tam) + " contra " + tamano(filas[0].tam) +
    " de AES. Por eso se usa el esquema híbrido: AES para los datos y RSA solo para la clave de sesión.</p>";

  document.getElementById("resRend").innerHTML = html;
  document.getElementById("btnRend").disabled = false;
  bitacora("Prueba de rendimiento con " + kb + " KB: RSA fue " + veces.toFixed(0) + " veces más lento que AES");
}

// ---------------- Pestañas ----------------

function cambiarSeccion(evento) {
  let botones = document.querySelectorAll(".pestana");
  let secciones = document.querySelectorAll(".seccion");
  botones.forEach(b => b.classList.remove("activa"));
  secciones.forEach(s => s.classList.add("oculto"));
  evento.target.classList.add("activa");
  document.getElementById(evento.target.dataset.seccion).classList.remove("oculto");
}

// ---------------- Eventos ----------------

document.querySelectorAll(".pestana").forEach(b => b.addEventListener("click", cambiarSeccion));
document.getElementById("btnGenerar").addEventListener("click", generarClaves);
document.getElementById("btnCifrar").addEventListener("click", confidencialidad);
document.getElementById("btnAlterar").addEventListener("click", alterarMensaje);
document.getElementById("btnIntrusoDescifra").addEventListener("click", intrusoDescifra);
document.getElementById("btnFirmar").addEventListener("click", firmar);
document.getElementById("btnVerificar").addEventListener("click", verificar);
document.getElementById("btnMitm").addEventListener("click", ataqueIntermediario);
document.getElementById("btnRend").addEventListener("click", rendimiento);

if (!window.crypto || !window.crypto.subtle) {
  document.getElementById("estadoClaves").textContent =
    "Este navegador no soporta la Web Crypto API. Abre la página con https o en un navegador actualizado.";
  document.getElementById("btnGenerar").disabled = true;
}
