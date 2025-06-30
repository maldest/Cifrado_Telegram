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
        # Verificar longitud de la clave (debe ser 16, 24 o 32 bytes)
        if len(clave) not in [16, 24, 32]:
            raise ValueError("La clave debe tener una longitud válida: 16, 24 o 32 bytes.")
        
        iv = os.urandom(16)  # Vector de inicialización
        cipher = Cipher(algorithms.AES(clave), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Añadir padding al mensaje
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(mensaje.encode()) + padder.finalize()
        
        # Cifrar
        cifrado = encryptor.update(padded_data) + encryptor.finalize()
        return (base64.b64encode(cifrado).decode('utf-8'), 
                base64.b64encode(iv).decode('utf-8'))
    except Exception as e:
        raise ValueError(f"Error al cifrar: {str(e)}")

# Función de descifrado AES
def descifrar_aes(mensaje_cifrado: str, clave: bytes, iv: str) -> str:
    try:
        # Decodificar los datos
        mensaje_cifrado_bytes = base64.b64decode(mensaje_cifrado)
        iv_bytes = base64.b64decode(iv)
        
        cipher = Cipher(algorithms.AES(clave), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Descifrar
        mensaje_padded = decryptor.update(mensaje_cifrado_bytes) + decryptor.finalize()
        
        # Eliminar el padding
        unpadder = padding.PKCS7(128).unpadder()
        mensaje = unpadder.update(mensaje_padded) + unpadder.finalize()
        
        return mensaje.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Error al descifrar: {str(e)}")

# Función para manejar el comando /start
async def say_hello(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "¡Hola! Soy tu bot de cifrado. Aquí están los comandos disponibles:\n\n"
        "/start - Inicia la conversación\n"
        "/cifrar - Envia un mensaje para cifrar\n"
        "/descifrar - Envia un mensaje cifrado para descifrar\n"
        "/terminar - Termina la sesión del bot"
    )

# Función para manejar el comando /cifrar
async def cifrar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Por favor, envíame el mensaje que deseas cifrar.")
    context.user_data['action'] = 'cifrar'

# Función para manejar el comando /descifrar
async def descifrar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Por favor, envíame el mensaje cifrado y el IV (separados por espacio).")
    context.user_data['action'] = 'descifrar'

# Función para manejar el comando /terminar
async def terminar(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Terminando la sesión del bot.")
    context.user_data['action'] = None

# Función para procesar el mensaje del usuario
async def process_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    action = context.user_data.get('action')

    if action == 'cifrar':
        mensaje = update.message.text
        clave = b"miclavesecreta12"  # Clave de 16 bytes, longitud válida para AES

        # Verificación de longitud de clave
        while len(clave) not in [16, 24, 32]:
            await update.message.reply_text("La clave no tiene la longitud válida. La clave debe tener 16, 24 o 32 bytes. Por favor, ingresa el mensaje nuevamente.")
            return
        
        # Llamada al cifrado AES
        mensaje_cifrado, iv = cifrar_aes(mensaje, clave)
        
        # Enviar primer mensaje con solo el mensaje cifrado
        await update.message.reply_text(f"Mensaje cifrado: ")
        
        # Enviar segundo mensaje con el mensaje cifrado y el IV
        await update.message.reply_text(f"{mensaje_cifrado}\n {iv}")

    elif action == 'descifrar':
        try:
            # Obtener mensaje cifrado y IV del usuario
            mensaje_cifrado, iv = update.message.text.split()
            clave = b"miclavesecreta12"  # Clave de 16 bytes, longitud válida para AES

            # Llamada al descifrado AES
            mensaje_descifrado = descifrar_aes(mensaje_cifrado, clave, iv)
            
            # Responder con el mensaje descifrado
            await update.message.reply_text(f"Mensaje descifrado: {mensaje_descifrado}")
        except ValueError:
            await update.message.reply_text("Por favor, asegúrate de enviar correctamente el mensaje cifrado y el IV.")

# Crear y configurar la aplicación
application = ApplicationBuilder().token("7806840133:AAEG5hAaNdDFELgoTQsfI_0vSsbCrzW3h4o").build()

# Manejadores de comandos
application.add_handler(CommandHandler("start", say_hello))
application.add_handler(CommandHandler("cifrar", cifrar))
application.add_handler(CommandHandler("descifrar", descifrar))
application.add_handler(CommandHandler("terminar", terminar))

# Manejador de mensajes para capturar texto que no sean comandos
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, process_message))

# Iniciar el bot y esperar mensajes
application.run_polling(allowed_updates=Update.ALL_TYPES)
