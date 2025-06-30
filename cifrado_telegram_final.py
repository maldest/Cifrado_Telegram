from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Función de cifrado AES
def cifrar_aes(mensaje: str, clave: bytes) -> tuple:
    try:
        if len(clave) not in [16, 24, 32]:
            raise ValueError("La clave debe tener una longitud válida: 16, 24 o 32 bytes.")
        
        iv = os.urandom(16)  # Vector de inicialización
        cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(mensaje.encode()) + padder.finalize()

        cifrado = encryptor.update(padded_data) + encryptor.finalize()
        return (base64.b64encode(cifrado).decode('utf-8'), 
                base64.b64encode(iv).decode('utf-8'))
    except Exception as e:
        raise ValueError(f"Error al cifrar: {str(e)}")

# Función de descifrado AES
def descifrar_aes(mensaje_cifrado: str, clave: bytes, iv: str) -> str:
    try:
        mensaje_cifrado_bytes = base64.b64decode(mensaje_cifrado)
        iv_bytes = base64.b64decode(iv)

        cipher = Cipher(algorithms.AES(clave), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()

        mensaje_padded = decryptor.update(mensaje_cifrado_bytes) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        mensaje = unpadder.update(mensaje_padded) + unpadder.finalize()

        return mensaje.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Error al descifrar: {str(e)}")

# Comando /start
async def say_hello(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "¡Hola! Soy tu bot de cifrado. Aquí están los comandos disponibles:\n\n"
        "/start - Inicia la conversación\n"
        "/cifrar - Envía un mensaje para cifrar\n"
        "/descifrar - Envía un mensaje cifrado para descifrar\n"
        "/terminar - Termina la sesión del bot"
    )

# Comando /cifrar
async def cifrar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    clave = os.urandom(16)  # Generar clave segura de 16 bytes
    context.user_data['clave'] = clave
    context.user_data['action'] = 'cifrar'
    await update.message.reply_text("Se ha generado una clave de cifrado segura. Por favor, envíame el mensaje que deseas cifrar.")

# Comando /descifrar
async def descifrar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if 'clave' not in context.user_data:
        await update.message.reply_text("Primero debes cifrar un mensaje para que se genere una clave.")
        return
    context.user_data['action'] = 'descifrar'
    await update.message.reply_text("Por favor, envíame el mensaje cifrado y el IV (separados por espacio).")

# Comando /terminar
async def terminar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.clear()
    await update.message.reply_text("Sesión finalizada. Puedes comenzar de nuevo con /start.")

# Procesar mensajes
async def process_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    action = context.user_data.get('action')

    if action == 'cifrar':
        mensaje = update.message.text
        clave = context.user_data.get('clave')

        if not clave or len(clave) not in [16, 24, 32]:
            await update.message.reply_text("La clave no es válida. Intenta nuevamente con /cifrar.")
            return

        try:
            mensaje_cifrado, iv = cifrar_aes(mensaje, clave)
            await update.message.reply_text("Mensaje cifrado:")
            await update.message.reply_text(f"{mensaje_cifrado}\n{iv}")
        except Exception as e:
            await update.message.reply_text(str(e))

    elif action == 'descifrar':
        try:
            mensaje_cifrado, iv = update.message.text.split()
            clave = context.user_data.get('clave')

            if not clave:
                await update.message.reply_text("No hay clave activa. Usa /cifrar primero.")
                return

            mensaje_descifrado = descifrar_aes(mensaje_cifrado, clave, iv)
            await update.message.reply_text(f"Mensaje descifrado: {mensaje_descifrado}")
        except Exception as e:
            await update.message.reply_text(f"Error al descifrar: {str(e)}")

# Crear aplicación
application = ApplicationBuilder().token("7806840133:AAEG5hAaNdDFELgoTQsfI_0vSsbCrzW3h4o").build()

# Handlers
application.add_handler(CommandHandler("start", say_hello))
application.add_handler(CommandHandler("cifrar", cifrar))
application.add_handler(CommandHandler("descifrar", descifrar))
application.add_handler(CommandHandler("terminar", terminar))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, process_message))

# Ejecutar bot
application.run_polling(allowed_updates=Update.ALL_TYPES)
