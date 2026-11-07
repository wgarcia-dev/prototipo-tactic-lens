# Diseño de los correos de TacticLens

Las notificaciones usan ahora una plantilla común con el lenguaje visual del panel: cabecera azul noche `#0b1423`, marca TacticLens y acento turquesa `#43d7d4`. El cuerpo claro mejora la lectura dentro del cliente de correo; títulos, etiquetas y avisos separan la acción principal de la información secundaria.

## Variantes

- Verificación: código de seis dígitos destacado y fácil de copiar, vigencia y diferencia explícita frente a Google Authenticator.
- Registro recibido y recuperación recibida: confirmación informativa, sin botones o enlaces inventados.
- Registro autorizado: botón **Crear mi contraseña**.
- Recuperación aprobada: botón **Restablecer contraseña**, vigencia original y enlace de respaldo para copiar.
- Contraseña actualizada: confirmación del cambio y texto original sobre sesiones/MFA.
- Suspensión, bloqueo y rechazo: etiquetas con tonos de advertencia o restricción; no indican que la recuperación pueda levantar un bloqueo.
- Reactivación y avisos de MFA: identidad común y contenido específico del evento.
- Asuntos nuevos no reconocidos: plantilla general que conserva asunto y contenido sin ocultarlos.

El asunto controlado por el backend selecciona la presentación. No se modificó el contrato `deliver(settings, recipient, subject, content)` ni el contenido original de la alternativa de texto. Los códigos y enlaces se extraen únicamente de líneas completas del contenido existente para destacarlos; la plantilla no los genera ni cambia su validez.

## Seguridad y compatibilidad

El correo es multipart: texto simple y HTML. El HTML utiliza tablas de presentación, estilos en línea, ancho fluido de hasta 600 px y ajustes móviles. Incluye un ancho alternativo mediante comentarios condicionales para Outlook. No necesita JavaScript, fuentes remotas, imágenes descargadas ni píxeles de seguimiento.

Los asuntos y contenidos se escapan. Solo se convierten en enlaces direcciones HTTP/HTTPS válidas, sin credenciales incrustadas ni caracteres de control. El preencabezado oculto es descriptivo y no incluye códigos ni tokens. Los enlaces personales aparecen únicamente donde corresponde al mensaje y mantienen exactamente su valor original.

La [documentación de Gmail](https://developers.google.com/workspace/gmail/design/css) describe el soporte de estilos y media queries; algunos clientes pueden ignorar detalles decorativos. La lectura y las acciones conservan sus alternativas simples. No se afirma una validación en Gmail/Outlook reales: no se enviaron correos durante esta tarea.

## Vistas previas locales

Desde la raíz:

```powershell
.\.venv\Scripts\python.exe -B -m scripts.preview_emails
```

Se generan once ejemplos y una galería en `.local/email-previews/index.html`. El generador no carga `.env`, no consulta usuarios y no llama a SMTP. Los códigos y enlaces de ejemplo son ficticios. La carpeta está ignorada por Git.

Para abrirlos mediante un servidor local dedicado:

```powershell
.\.venv\Scripts\python.exe -m http.server 5174 --bind 127.0.0.1 --directory .local/email-previews
```

Abrir `http://127.0.0.1:5174/`. Este servidor sirve únicamente la carpeta de ejemplos, no los mensajes reales del buzón `.local/mail` ni archivos de configuración.

## Archivos y verificación

- `backend/auth/email_templates.py`: paleta, perfiles, extracción segura y HTML reutilizable.
- `backend/auth/mailer.py`: integra la nueva plantilla conservando SMTP, SSL/STARTTLS, buzón local y texto simple.
- `scripts/preview_emails.py`: galería ficticia sin envío.
- `tests/test_email_templates.py`: once pruebas de contenido, seguridad, MIME, enlaces, código y transporte SMTP simulado.

Pasaron **103 pruebas backend**, incluidas las once nuevas, sin conexiones SMTP reales. Se revisaron en navegador verificación, recuperación y bloqueo, y la recuperación a 390 px: sin desbordamiento horizontal y con botón adaptado al ancho disponible. La integración de SMTP con Resend no cambia y no requiere migraciones ni variables nuevas.

Para aplicar la plantilla a futuros envíos, reiniciar el backend. Los mensajes ya recibidos no se modifican. La comprobación de entrega real queda pendiente de la autorización del titular.
