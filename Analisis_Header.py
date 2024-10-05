import pandas as pd
import subprocess
import requests

# Leer el archivo Excel
file_path = r"C:\Users\yalbe\OneDrive\Escritorio\Analisis\HeadersPRHGE.xlsx"
df = pd.read_excel(file_path)

# Leer las URLs que están en la columna llamada 'URL'
urls = df['URL'].tolist()

# Función para generar recomendaciones basadas en OWASP
def generar_recomendaciones(header):
    recomendaciones = {
        'Strict-Transport-Security': (
            "Recomendación: Habilita Strict-Transport-Security para proteger contra ataques de tipo SSL stripping. "
            "Configura el header como 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
        ),
        'X-XSS-Protection': (
            "Recomendación: Habilita X-XSS-Protection para mitigar algunos ataques de cross-site scripting (XSS). "
            "Usa 'X-XSS-Protection: 1; mode=block'."
        ),
        'X-Content-Type-Options': (
            "Recomendación: Habilita X-Content-Type-Options para evitar que los navegadores interpreten archivos en un "
            "tipo MIME diferente al declarado. Usa 'X-Content-Type-Options: nosniff'."
        ),
        'X-Frame-Options': (
            "Recomendación: Usa X-Frame-Options para proteger contra ataques de clickjacking. "
            "Configura el header como 'X-Frame-Options: DENY' o 'X-Frame-Options: SAMEORIGIN'."
        ),
        'Public-Key-Pins': (
            "Recomendación: Debido a los riesgos y complejidad de la implementación, se recomienda no usar Public-Key-Pins (HPKP)."
        ),
        'Content-Security-Policy': (
            "Recomendación: Implementa una política de seguridad de contenido (CSP) para prevenir ataques de inyección, como XSS. "
            "Configura 'Content-Security-Policy: default-src 'self';'."
        ),
        'Referrer-Policy': (
            "Recomendación: Establece una política de referidos para controlar la información enviada en el encabezado Referer. "
            "Usa 'Referrer-Policy: no-referrer' o 'Referrer-Policy: strict-origin'."
        ),
        'X-Permitted-Cross-Domain-Policies': (
            "Recomendación: Habilita X-Permitted-Cross-Domain-Policies para evitar que se carguen archivos peligrosos. "
            "Usa 'X-Permitted-Cross-Domain-Policies: none'."
        ),
        'Cache-Control': (
            "Recomendación: Configura Cache-Control para prevenir la caché insegura de contenido sensible. "
            "Usa 'Cache-Control: no-store, no-cache, must-revalidate'."
        ),
        'Pragma': (
            "Recomendación: El header Pragma está obsoleto, pero para retrocompatibilidad puedes usar 'Pragma: no-cache'."
        )
    }
    return recomendaciones.get(header, "No se encontró una recomendación específica para este header.")

# Función para analizar los headers de cada URL con requests y shcheck
def analizar_headers(url):
    try:
        # Realizar análisis básico de headers con requests
        response = requests.get(url)
        headers = response.headers

        resultado = f"Resultados del análisis de {url}:\n"
        recomendaciones_texto = f"**Recomendaciones para {url}**:\n"

        # Verificar si cada header de seguridad está configurado y agregar recomendaciones
        headers_de_seguros = {
            'Strict-Transport-Security': "⚠ Alerta: **Strict-Transport-Security** no está configurado.",
            'X-XSS-Protection': "⚠ Alerta: **X-XSS-Protection** no está configurado.",
            'X-Content-Type-Options': "⚠ Alerta: **X-Content-Type-Options** no está configurado.",
            'X-Frame-Options': "⚠ Alerta: **X-Frame-Options** no está configurado.",
            'Public-Key-Pins': "⚠ Alerta: **Public-Key-Pins** no está configurado.",
            'Content-Security-Policy': "⚠ Alerta: **Content-Security-Policy** no está configurado.",
            'Referrer-Policy': "⚠ Alerta: **Referrer-Policy** no está configurado.",
            'X-Permitted-Cross-Domain-Policies': "⚠ Alerta: **X-Permitted-Cross-Domain-Policies** no está configurado.",
            'Cache-Control': "⚠ Alerta: **Cache-Control** no está configurado.",
            'Pragma': "⚠ Alerta: **Pragma** no está configurado."
        }

        for header, mensaje_alerta in headers_de_seguros.items():
            if header not in headers:
                resultado += mensaje_alerta + "\n"
                recomendaciones_texto += generar_recomendaciones(header) + "\n"
            else:
                resultado += f"✅ Correcto: **{header}** está configurado correctamente.\n"

        # Ejecutar shcheck para un análisis más completo de headers
        try:
            shcheck_result = subprocess.run(['python3', 'shcheck/shcheck.py', url], capture_output=True, text=True, timeout=15)  # Agregamos timeout de 15 segundos
            resultado += "\n**Resultado de SHCheck**:\n" + shcheck_result.stdout
        except subprocess.TimeoutExpired:
            resultado += "\n⚠ Alerta: **SHCheck** excedió el tiempo límite de análisis para {url}.\n"
        except Exception as e:
            resultado += f"\n❌ Error al ejecutar SHCheck: {e}"

        return resultado, recomendaciones_texto
    
    except requests.exceptions.RequestException as e:
        return f"❌ Error al analizar {url}: {e}", ""

# Analizar todas las URLs obtenidas desde el archivo Excel
resultados = []
recomendaciones = []
for url in urls:
    resultado, recomendaciones_texto = analizar_headers(url)
    print(f"Resultado para {url}: {resultado}")
    print(f"Recomendaciones para {url}: {recomendaciones_texto}")
    resultados.append({'URL': url, 'Resultado': resultado})
    recomendaciones.append({'URL': url, 'Recomendaciones': recomendaciones_texto})

# Crear un DataFrame con los resultados y recomendaciones
df_resultados = pd.DataFrame(resultados)
df_recomendaciones = pd.DataFrame(recomendaciones)

# Guardar los resultados en un nuevo archivo Excel
output_file = r"C:\Users\yalbe\OneDrive\Escritorio\Analisis\Headers_Report_With_Recommendations.xlsx"
with pd.ExcelWriter(output_file) as writer:
    df_resultados.to_excel(writer, sheet_name='Resultados', index=False)
    df_recomendaciones.to_excel(writer, sheet_name='Recomendaciones', index=False)

print(f"Informe generado en: {output_file}")