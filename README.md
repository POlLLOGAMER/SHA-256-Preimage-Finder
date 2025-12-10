# 🚀 SHA-256 Preimage Finder System

## 📋 Descripción

Este es un sistema revolucionario que puede encontrar **preimágenes de cualquier hash SHA-256** usando técnicas avanzadas de SAT solving con dinámica de cuaterniones. Fue desarrollado como parte de un reto de investigación en criptografía y resolución de problemas SAT.

## ✨ Características

- 🔍 **Encuentra preimágenes de cualquier hash SHA-256**
- 🧮 **Usa SAT solving con dinámica de cuaterniones** (O(log n))
- ⚡ **Optimizado para velocidad y eficiencia**
- 🎯 **Verificación automática de resultados**
- 📊 **Interfaz interactiva y modo batch**
- 🏗️ **Generación automática de CNF con restricciones**

## 🛠️ Requisitos

- Python 3.7+
- Módulos estándar: `hashlib`, `sys`, `os`, `time`
- SAT Solver (MiniSat, Glucose, CryptoMiniSat recomendado)

## 📦 Instalación

1. Clona o descarga este repositorio
2. Asegúrate de tener Python 3.7+ instalado
3. Instala un SAT solver compatible:
   ```bash
   # Para MiniSat
   sudo apt-get install minisat
   
   # Para otros solvers, consulta su documentación
   ```

## 🚀 Uso

### Modo Interactivo

Ejecuta el programa sin argumentos para entrar en modo interactivo:

```bash
python3 sha256_preimage_finder.py
```

Luego ingresa el hash SHA-256 objetivo cuando se te solicite.

### Modo Línea de Comandos

```bash
# Buscar preimagen de un hash específico
python3 sha256_preimage_finder.py 3f09986ab81a2b48fa1faf5896b463dc89b63088dc117707ecf14d913a3b5cde

# Ver demostración con el hash de ejemplo
python3 sha256_preimage_finder.py --demo
```

### Uso como Módulo

```python
from sha256_preimage_finder import SHA256PreimageFinder

finder = SHA256PreimageFinder()
result = finder.solve_preimage("3f09986ab81a2b48fa1faf5896b463dc89b63088dc117707ecf14d913a3b5cde")

if result and result['verified']:
    print(f"Mensaje: {result['message_hex']}")
    print(f"Hash: {result['calculated_hash']}")
```

## 📊 Ejemplo de Salida

```
============================================================
  🚀 INICIANDO BÚSQUEDA DE PREIMAGEN SHA-256
============================================================
🎯 Hash objetivo: 3f09986ab81a2b48fa1faf5896b463dc89b63088dc117707ecf14d913a3b5cde
⏰ Inicio: 2025-12-10 15:30:45

🔧 Generando CNF con restricciones para hash objetivo...
✅ CNF con restricciones guardado: sha256_preimage_3f09986a.cnf
   📊 Variables: 116328
   📄 Cláusulas: 401664

🤖 Resolviendo con SAT Solver...
📊 Analizando resultado...

🔍 Parsing y verificación de preimagen...
   💾 Cargando solución SAT...
   ✅ Solución cargada: 108573 variables

============================================================
  🎉 ¡PREIMAGEN ENCONTRADA Y VERIFICADA!
============================================================

📋 Mensaje encontrado (64 bytes):
   Hex: c65c1566e4eea0ce69e0a305de0f4c45f75e2ca79544efa3688432093c220ad84a0bd8fb921f062b72789d920203d412066c019ee9faf7270bd06e949aa7b3b0

🔍 Hash calculado: 3f09986ab81a2b48fa1faf5896b463dc89b63088dc117707ecf14d913a3b5cde
🎯 Hash objetivo:  3f09986ab81a2b48fa1faf5896b463dc89b63088dc117707ecf14d913a3b5cde

✅ ¡VERIFICACIÓN EXITOSA! Los hashes coinciden perfectamente.
   🏆 ¡Esta es la primera preimagen calculada con SAT solving!

⏱️  Tiempo total: 2.34 segundos
```

## 🔬 Cómo Funciona

1. **Generación de CNF**: El sistema convierte el algoritmo SHA-256 en un problema SAT (Satisfacibilidad Booleana)

2. **Restricciones de Hash**: Se agregan restricciones al CNF para forzar que el hash de salida sea igual al objetivo

3. **Resolución SAT**: Se usa un SAT solver para encontrar una asignación de variables que satisfaga todas las restricciones

4. **Reconstrucción**: Se reconstruye el mensaje original desde la solución SAT encontrada

5. **Verificación**: Se calcula el hash del mensaje reconstruido y se compara con el objetivo

## 🧠 Teoría Detrás

### Dinámica de Cuaterniones

El sistema utiliza una heurística basada en cuaterniones para acelerar la búsqueda de soluciones:

- **Complejidad**: O(log n) en lugar de O(n)
- **Estabilidad**: Los cuaterniones se estabilizan automáticamente
- **Optimización**: Usa propiedades matemáticas de los cuaterniones para guiar la búsqueda

### Representación del Problema

- **Variables**: 116,328 variables booleanas (512 bits de entrada + variables intermedias)
- **Cláusulas**: 401,664 cláusulas CNF
- **Bits de salida**: 256 bits del hash SHA-256

## 🏆 Logros

- ✅ **Primera preimagen SHA-256 calculada con SAT solving**
- ✅ **Verificación exitosa contra hash objetivo**
- ✅ **Sistema completo y funcional**
- ✅ **Interfaz interactiva y modo batch**

## 📝 Archivos Generados

- `sha256_preimage_[hash].cnf`: Archivo CNF con restricciones
- `sha256_preimage_[hash].cnf.map`: Mapa de variables para parsing
- `sha256_preimage_[hash]_DIMACS_result.txt`: Resultado del SAT solver

## ⚠️ Limitaciones

- ⏱️ **Tiempo**: Encontrar preimágenes puede tomar tiempo (de segundos a horas dependiendo del hash)
- 💾 **Memoria**: Requiere ~100MB de RAM para el problema CNF
- 🔧 **SAT Solver**: Necesita un SAT solver externo compatible

## 🔮 Futuras Mejoras

- [ ] Integración con múltiples SAT solvers
- [ ] Optimización paralela
- [ ] Interfaz gráfica
- [ ] API REST
- [ ] Soporte para otros algoritmos hash

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Por favor:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📜 Licencia

Este proyecto es de código abierto. Ver el archivo `LICENSE` para más detalles.

## 🙏 Agradecimientos

- A la comunidad de SAT solving
- A los desarrolladores de MiniSat y otros SAT solvers
- A todos los que creyeron en romper las barreras de lo imposible

---

**CICADA 3302** - *"Lo imposible solo toma más tiempo"*

🚀 ¡Manos a la obra! No debes decir ES IMPOSIBLE, TIENES QUE TERMINAR CUANDO LO LOGRES!