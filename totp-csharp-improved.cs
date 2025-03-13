using System;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;

/// <summary>
/// Implementación de TOTP (Time-based One-Time Password) para autenticación de doble factor
/// Basado en el RFC 6238: https://tools.ietf.org/html/rfc6238
/// Esta versión incluye opciones adicionales como algoritmos hash diferentes y tolerancia de tiempo
/// </summary>
public class TOTPGeneratorAdvanced
{
    /// <summary>
    /// Diferentes algoritmos de hash disponibles para TOTP
    /// </summary>
    public enum HashAlgorithm
    {
        SHA1,
        SHA256,
        SHA512
    }
    
    /// <summary>
    /// Genera un código TOTP basado en un timestamp específico
    /// </summary>
    /// <param name="secret">La clave secreta compartida entre el servidor y el cliente</param>
    /// <param name="digits">Número de dígitos para el código (6 u 8)</param>
    /// <param name="timeStep">Intervalo de tiempo en segundos (típicamente 30)</param>
    /// <param name="timestamp">Timestamp en formato UNIX (segundos desde 1970)</param>
    /// <param name="algorithm">Algoritmo de hash a utilizar</param>
    /// <returns>Código TOTP generado</returns>
    public static string GenerateTOTP(string secret, int digits = 6, int timeStep = 30, 
                                     long? timestamp = null, HashAlgorithm algorithm = HashAlgorithm.SHA1)
    {
        // Si no se proporciona timestamp, usar el tiempo actual
        long timeCounter = timestamp.HasValue 
            ? timestamp.Value / timeStep 
            : DateTimeOffset.UtcNow.ToUnixTimeSeconds() / timeStep;
        
        // Convertir el contador a bytes (8 bytes, big-endian)
        byte[] timeBytes = new byte[8];
        for (int i = 7; i >= 0; i--)
        {
            timeBytes[i] = (byte)(timeCounter & 0xFF);
            timeCounter >>= 8;
        }
        
        // Convertir la clave secreta a bytes
        byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
        
        // Calcular HMAC usando el algoritmo seleccionado
        byte[] hash;
        switch (algorithm)
        {
            case HashAlgorithm.SHA256:
                using (HMACSHA256 hmac = new HMACSHA256(secretBytes))
                {
                    hash = hmac.ComputeHash(timeBytes);
                }
                break;
            case HashAlgorithm.SHA512:
                using (HMACSHA512 hmac = new HMACSHA512(secretBytes))
                {
                    hash = hmac.ComputeHash(timeBytes);
                }
                break;
            default: // SHA1
                using (HMACSHA1 hmac = new HMACSHA1(secretBytes))
                {
                    hash = hmac.ComputeHash(timeBytes);
                }
                break;
        }
        
        // Obtener el offset según el último nibble (4 bits) del hash
        int offset = hash[hash.Length - 1] & 0x0F;
        
        // Extraer 4 bytes a partir del offset y obtener un entero de 31 bits
        int binary = ((hash[offset] & 0x7F) << 24) | 
                     ((hash[offset + 1] & 0xFF) << 16) | 
                     ((hash[offset + 2] & 0xFF) << 8) | 
                     (hash[offset + 3] & 0xFF);
        
        // Obtener los últimos 'digits' dígitos
        int otp = binary % (int)Math.Pow(10, digits);
        
        // Formatear como una cadena con ceros a la izquierda si es necesario
        return otp.ToString().PadLeft(digits, '0');
    }
    
    /// <summary>
    /// Genera un código TOTP a partir de una fecha en formato personalizado
    /// </summary>
    /// <param name="dateString">Fecha en formato "YYYYMMDDHHMM" (ejemplo: 202503131728)</param>
    /// <param name="secret">Clave secreta compartida</param>
    /// <param name="digits">Número de dígitos del código (6 u 8)</param>
    /// <param name="algorithm">Algoritmo de hash a utilizar</param>
    /// <returns>Código TOTP generado</returns>
    public static string GenerateTOTPFromDateString(string dateString, string secret, 
                                                 int digits = 6, HashAlgorithm algorithm = HashAlgorithm.SHA1)
    {
        // Extraer componentes de la fecha
        int year = int.Parse(dateString.Substring(0, 4));
        int month = int.Parse(dateString.Substring(4, 2));
        int day = int.Parse(dateString.Substring(6, 2));
        int hour = int.Parse(dateString.Substring(8, 2));
        int minute = int.Parse(dateString.Substring(10, 2));
        
        // Crear objeto DateTime y obtener timestamp
        DateTime date = new DateTime(year, month, day, hour, minute, 0, DateTimeKind.Utc);
        long timestamp = new DateTimeOffset(date).ToUnixTimeSeconds();
        
        // Generar TOTP
        return GenerateTOTP(secret, digits, 30, timestamp, algorithm);
    }
    
    /// <summary>
    /// Verifica un código TOTP con una ventana de tolerancia
    /// </summary>
    /// <param name="userCode">Código proporcionado por el usuario</param>
    /// <param name="secret">Clave secreta compartida</param>
    /// <param name="digits">Número de dígitos del código</param>
    /// <param name="timeStep">Intervalo de tiempo en segundos</param>
    /// <param name="windowSize">Tamaño de la ventana de tolerancia (número de intervalos)</param>
    /// <param name="algorithm">Algoritmo de hash a utilizar</param>
    /// <returns>True si el código es válido, False en caso contrario</returns>
    public static bool VerifyTOTP(string userCode, string secret, int digits = 6, int timeStep = 30,
                               int windowSize = 1, HashAlgorithm algorithm = HashAlgorithm.SHA1)
    {
        // Obtener el timestamp actual
        long currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        
        // Verificar códigos en la ventana de tiempo
        for (int i = -windowSize; i <= windowSize; i++)
        {
            long timestampToCheck = currentTimestamp + (i * timeStep);
            string codeToCheck = GenerateTOTP(secret, digits, timeStep, timestampToCheck, algorithm);
            
            if (userCode.Equals(codeToCheck))
            {
                return true;
            }
        }
        
        return false;
    }
    
    /// <summary>
    /// Genera un conjunto de códigos TOTP válidos dentro de una ventana de tiempo
    /// Útil para depuración o para sistemas que requieren múltiples códigos válidos
    /// </summary>
    /// <param name="secret">Clave secreta compartida</param>
    /// <param name="digits">Número de dígitos del código</param>
    /// <param name="timeStep">Intervalo de tiempo en segundos</param>
    /// <param name="windowSize">Tamaño de la ventana de tolerancia (número de intervalos)</param>
    /// <param name="algorithm">Algoritmo de hash a utilizar</param>
    /// <returns>Diccionario con offset y código correspondiente</returns>
    public static Dictionary<int, string> GetValidTOTPCodes(string secret, int digits = 6, int timeStep = 30,
                                                         int windowSize = 1, HashAlgorithm algorithm = HashAlgorithm.SHA1)
    {
        Dictionary<int, string> validCodes = new Dictionary<int, string>();
        long currentTimestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        
        for (int i = -windowSize; i <= windowSize; i++)
        {
            long timestampToCheck = currentTimestamp + (i * timeStep);
            string code = GenerateTOTP(secret, digits, timeStep, timestampToCheck, algorithm);
            validCodes.Add(i, code);
        }
        
        return validCodes;
    }
}

/// <summary>
/// Clase de ejemplo para probar la generación y verificación de códigos TOTP
/// 