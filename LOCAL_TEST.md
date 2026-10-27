# Prueba local de protección — 2026-10-26

Compilación Release/Win32 con Visual Studio Build Tools 2026, toolset v145.
Salida aislada en `build-local/`, excluida de Git; el binario previo de `build/`
se conserva. Corregir versión del enlazador de `1.0.01` a `1.0`.

Los hashes esperados corresponden a `interface.u` e `interface.xdat` de
`C:\game\l2-bhwd-test\system`. La longitud SHA-256 se comprueba al compilar;
los archivos se resuelven junto a la DLL, sin depender del directorio actual.
Se mantienen activas la protección de archivos y la autenticación BHWD.

`bhwd-diagnostic.log`, junto a la DLL, registra inicialización, hooks,
conexión, envío BHWD e integridad de archivos. No contiene payloads,
credenciales ni identificadores de hardware. Los mensajes se agregan al archivo;
su rotación es manual. Los hooks registran sus fallos y se comprueba el tamaño
del buffer antes de extender el paquete.

Verificación: compilación correcta, DLL x86 con exportación
`DirectXSetupGetVersion` por ordinal 11. Logs confirman envío BHWD y el servidor
confirma autenticación, creación de personaje y entrada al mundo. El usuario
confirmó funcionamiento tras corregir el hash de interfaz y conservación de
los cambios del personaje tras reiniciar. No equivale a pruebas exhaustivas
de todos los módulos de protección ni de todos los formatos de envío Winsock.

La base editable del parche se conserva en
`C:\proyect\L2JGerman-Interlude\client-patch`; sus binarios son locales,
no se incluyen en los commits y requieren respaldo externo.
