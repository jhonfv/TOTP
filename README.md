# Implementación de TOTP para Autenticación de Doble Factor

> **DESCARGO DE RESPONSABILIDAD**: Este es un algoritmo OTP básico generado con la ayuda de la IA de Claude (Anthropic). El código se proporciona con fines educativos y puede requerir modificaciones adicionales para entornos de producción. Se recomienda realizar pruebas exhaustivas y considerar bibliotecas establecidas para implementaciones en sistemas críticos.

## Introducción

La autenticación de doble factor (2FA) es una capa adicional de seguridad que requiere no solo una contraseña, sino también un segundo factor de autenticación. Uno de los métodos más comunes es el TOTP (Time-based One-Time Password), utilizado por aplicaciones como Google Authenticator, Microsoft Authenticator y Authy.

Este documento explica la implementación de un algoritmo TOTP en C# que genera códigos de autenticación basados en el tiempo, compatible con el estándar RFC 6238.

## Fundamentos del TOTP

### ¿Qué es TOTP?

TOTP es un algoritmo que genera contraseñas de un solo uso basadas en:
1. Una clave secreta compartida
2. La hora actual
3. Un intervalo de tiempo predefinido (típicamente 30 segundos)

La magia del TOTP reside en que tanto el servidor como el cliente pueden generar el mismo código de forma independiente si comparten la misma clave secreta y sus relojes están sincronizados.

### Principios de funcionamiento

El proceso de generación de un código TOTP se puede dividir en varias etapas:

1. **Obtener un contador basado en el tiempo**: Se divide el timestamp actual (en segundos desde la época Unix) por el intervalo de tiempo (típicamente 30 segundos).

2. **Aplicar una función HMAC**: Se utiliza la clave secreta y el contador para generar un hash mediante HMAC (Hash-based Message Authentication Code).

3. **Truncar el resultado**: Se extraen bits específicos del hash resultante mediante un algoritmo de truncamiento dinámico.

4. **Generar un código numérico**: Se convierte el valor truncado a un número de 6 u 8 dígitos.

## Implementación en C#

### La clase TOTPGenerator

La clase principal `TOTPGenerator` proporciona dos métodos principales:

1. `GenerateTOTP`: Genera un código TOTP basado en un timestamp específico.
2. `GenerateTOTPFromDateString`: Genera un código TOTP a partir de una fecha en formato específico (YYYYMMDDHHMM).

### Generación del código

El proceso detallado de generación de un código TOTP en nuestra implementación es:

```csharp
public static string GenerateTOTP(string secret, int digits = 6, int timeStep = 30, long? timestamp = null)
{
    // Calcular el contador de tiempo
    long timeCounter = timestamp.HasValue 
        ? timestamp.Value / timeStep 
        : DateTimeOffset.UtcNow.ToUnixTimeSeconds() / timeStep;
    
    // Convertir el contador a bytes (formato big-endian)
    byte[] timeBytes = new byte[8];
    for (int i = 7; i >= 0; i--)
    {
        timeBytes[i] = (byte)(timeCounter & 0xFF);
        timeCounter >>= 8;
    }
    
    // Calcular el HMAC-SHA1
    byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
    byte[] hash;
    using (HMACSHA1 hmac = new HMACSHA1(secretBytes))
    {
        hash = hmac.ComputeHash(timeBytes);
    }
    
    // Obtener el offset para la truncación dinámica
    int offset = hash[hash.Length - 1] & 0x0F;
    
    // Extraer 4 bytes a partir del offset y obtener un entero de 31 bits
    int binary = ((hash[offset] & 0x7F) << 24) | 
                 ((hash[offset + 1] & 0xFF) << 16) | 
                 ((hash[offset + 2] & 0xFF) << 8) | 
                 (hash[offset + 3] & 0xFF);
    
    // Obtener los últimos 'digits' dígitos
    int otp = binary % (int)Math.Pow(10, digits);
    
    // Formatear con ceros a la izquierda si es necesario
    return otp.ToString().PadLeft(digits, '0');
}
```

### Aspectos clave de la implementación

1. **Conversión big-endian**: El algoritmo requiere que el contador de tiempo se represente en formato big-endian (los bytes más significativos primero).

2. **Truncamiento dinámico**: El último nibble (4 bits) del hash determina el offset donde comenzará la extracción de los 4 bytes que se utilizarán para generar el código.

3. **Máscara 0x7F**: Se aplica una máscara AND con 0x7F al primer byte para garantizar que el valor resultante sea un entero de 31 bits positivo.

4. **Módulo 10^n**: Para obtener un código de 'n' dígitos, se toma el módulo del valor binario por 10^n.

## Versión avanzada: TOTPGeneratorAdvanced

La versión avanzada incluye características adicionales:

1. **Múltiples algoritmos HMAC**: Soporte para SHA1, SHA256 y SHA512.

2. **Verificación con ventana de tolerancia**: Permite verificar códigos con una ventana de tiempo para compensar pequeñas desincronizaciones entre relojes.

3. **Generación de múltiples códigos válidos**: Útil para depuración o sistemas que requieren una ventana de validez más amplia.

### Verificación de códigos TOTP

```csharp
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
```

Esta función permite verificar si un código proporcionado por el usuario es válido dentro de una ventana de tiempo determinada, lo que es crucial para sistemas en producción.

## Casos de uso

### Autenticación de doble factor

El caso de uso principal es la implementación de autenticación de doble factor en:

- Aplicaciones web
- Aplicaciones móviles
- VPNs y acceso remoto
- Sistemas críticos que requieren seguridad adicional

### Sincronización con servidores NTP

Para un funcionamiento óptimo, es recomendable que tanto el servidor como el cliente mantengan sus relojes sincronizados con servidores NTP (Network Time Protocol).

## Mejores prácticas de seguridad

1. **Almacenamiento seguro de la clave secreta**: La clave secreta debe almacenarse de forma segura, preferiblemente cifrada.

2. **Protección contra ataques de fuerza bruta**: Implementar limitación de intentos para prevenir ataques.

3. **Códigos de recuperación**: Proporcionar códigos de recuperación para casos en que el usuario pierda acceso a su dispositivo de autenticación.

4. **Ventana de tolerancia reducida**: Utilizar una ventana de tolerancia pequeña (1 o 2 intervalos) para minimizar el riesgo de ataques.

## Ejemplos de integración

### Proceso de registro

1. Generar una clave secreta única para el usuario
2. Almacenar la clave secreta de forma segura
3. Proporcionar la clave al usuario (mediante QR o manualmente)
4. Verificar que el usuario puede generar códigos correctamente

### Proceso de autenticación

1. El usuario introduce su nombre de usuario y contraseña
2. El sistema solicita un código TOTP
3. El usuario introduce el código generado en su dispositivo
4. El sistema verifica el código y concede acceso si es válido

## Conclusión

La implementación de TOTP proporcionada en este repositorio ofrece una solución flexible y segura para añadir autenticación de doble factor a cualquier sistema. Aunque es un algoritmo relativamente simple, proporciona una capa de seguridad significativa contra muchos tipos de ataques.

Para sistemas en producción, considere utilizar bibliotecas establecidas como `Otp.NET` o integrar con proveedores de autenticación existentes como Auth0, Okta o Azure AD.

## Referencias

- [RFC 6238 - TOTP: Time-Based One-Time Password Algorithm](https://tools.ietf.org/html/rfc6238)
- [RFC 4226 - HOTP: An HMAC-Based One-Time Password Algorithm](https://tools.ietf.org/html/rfc4226)
