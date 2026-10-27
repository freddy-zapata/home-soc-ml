# FEATURES — HomeSOC ML (v1, 2026-10-27)

Lista versionada de características. Fuente de verdad del **modelo principal**:
la constante `MODEL_FEATURES` en `build_features.py` debe coincidir con esta tabla.

## Unidad
- **Entidad** = `agent_id` (un Windows instrumentado). Nunca se mezclan equipos.
- **Ventana** = 5 min, alineada al reloj (00,05,10…), por **hora del evento**
  (`event_time`), no por hora de ingesta.
- `available_at` (hora de ingesta) se conserva en el crudo para la causalidad
  temporal (protocolo §9); **no** es una característica.

## Características del modelo (entran al IF / autoencoder)

| Columna | Qué mide | Fuente |
|---|---|---|
| `n_events` | eventos totales en la ventana | todas |
| `n_win_events` | eventos de host (EventChannel) | Windows |
| `n_suri_events` | eventos de red | Suricata |
| `proc_creates` | procesos creados (EventID 1 **en canal Sysmon**) | Sysmon |
| `img_unique` | imágenes de proceso distintas | Sysmon |
| `logon_fail` | logons fallidos (4625 **en canal Security**) | Security |
| `logon_ok` | logons exitosos (4624 **en canal Security**) | Security |
| `ps_blocks` | bloques de script PowerShell (4104) | PowerShell |
| `ps_len_max` | longitud máx. de scriptBlockText | PowerShell |
| `dst_ip_unique` | IPs destino distintas | Suricata |
| `dport_unique` | puertos destino distintos | Suricata |
| `dns_unique` | dominios consultados distintos (v2+v3) | Suricata |
| `tls_unique` | SNI TLS distintos | Suricata |
| `http_reqs` | peticiones HTTP | Suricata |
| `flow_out` | bytes salientes (**solo eventos `flow`**) | Suricata |
| `flow_in` | bytes entrantes (**solo eventos `flow`**) | Suricata |

## NO son características del modelo (protocolo §7)
- `entity`, `win` → claves de agrupación.
- `label` → etiqueta de evaluación (del registro de ataques, nunca de alertas).
- `diag_suri_alerts`, `diag_wazuh_alerts_lvl8plus` → derivadas de reglas; se
  guardan solo para diagnóstico/línea base. Un modelo híbrido que las use se
  reporta **aparte** y se declara así.
- `profile`, `session_id`, nombres de escenario de las sesiones benignas →
  **nunca** entran (serían un atajo para distinguir ataque de normal).

## Pendiente (cuando haya datos y manifiesto)
- Indicador de **cobertura por fuente** por ventana (sensor ausente ≠ 0):
  columna por fuente que marque si ese sensor estaba activo en la ventana.
- Entropía del dominio DNS y regularidad de intervalos (beaconing) — se añaden
  solo si aportan en calibración; cualquier alta de feature re-versiona este
  archivo.
