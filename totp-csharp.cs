using System;
using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Implementación de TOTP (Time-based One-Time Password) para autenticación de doble factor
/// Basado en el RFC 6238: https://tools.ietf.org/html/rfc6238
/// </summary>
public class TOTPGenerator
{
    /// <summary>
    /// Genera un código TOTP basado en un timestamp específico
    /// </summary>
    /// <param name="secret">La clave secreta compartida entre el servidor y el cliente</param>
    /// <param name="digits">Número de dígitos para el código (6 u 8)</param>
    /// <param name="timeStep">Intervalo de tiempo en segundos (típicamente 30)</param>
    /// <param name="timestamp">Timestamp en formato UNIX (segundos desde 1970)</param>
    /// <returns>Código TOTP generado</returns>
    public static string GenerateTOTP(string secret, int digits = 6, int timeStep = 30, long? timestamp = null)
    {
        // Si no se proporciona timestamp, usar el tiempo actual
        long timeCounter = timestamp.HasValue 
            ? timestamp.Value / timeStep 
            : DateTimeOffset.UtcNow.ToUnixTimeSeconds() / timeStep;
        
        // Convertir el contador a bytes (8 bytes, big-endian)
        byte[] timeBytes = BitConverter.GetBytes(timeCounter);
        // Invertir si la arquitectura es little-endian
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(timeBytes);
        }
        
        // Asegurar que timeBytes tenga 8 bytes (rellenar con ceros a la izquierda si es necesario)
        byte[] paddedTimeBytes = new byte[8];
        // Copiamos los bytes significativos al final del array
        Array.Copy(timeBytes, 0, paddedTimeBytes, 8 - timeBytes.Length, timeBytes.Length);
        
        // Convertir la clave secreta a bytes
        byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
        
        // Calcular HMAC-SHA1
        byte[] hash;
        using (HMACSHA1 hmac = new HMACSHA1(secretBytes))
        {
            hash = hmac.ComputeHash(paddedTimeBytes);
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
    /// <returns>Código TOTP generado</returns>
    public static string GenerateTOTPFromDateString(string dateString, string secret, int digits = 6)
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
        return GenerateTOTP(secret, digits, 30, timestamp);
    }
}

/// <summary>
/// Clase de ejemplo para probar la generación de códigos TOTP
/// </summary>
class Program
{
    static void Main(string[] args)
    {
        string dateString = "202503131728"; // 2025/03/13 17:28
        string secret = "MICLAVESECRATACOMPARTIDACONELSERVIDOR"; // Debe ser la misma en el servidor
        
        string code6 = TOTPGenerator.GenerateTOTPFromDateString(dateString, secret, 6);
        string code8 = TOTPGenerator.GenerateTOTPFromDateString(dateString, secret, 8);
        
        Console.WriteLine($"Código de 6 dígitos para {dateString}: {code6}");
        Console.WriteLine($"Código de 8 dígitos para {dateString}: {code8}");
        
        // También puedes generar un código basado en la hora actual
        string currentCode6 = TOTPGenerator.GenerateTOTP(secret, 6);
        Console.WriteLine($"Código actual de 6 dígitos: {currentCode6}");
    }
}
