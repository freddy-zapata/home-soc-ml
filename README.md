# Home SOC + Deteccion de Anomalias con Machine Learning

Laboratorio de un SOC casero con **Wazuh (HIDS/SIEM)**, **Suricata (NIDS)** y **Sysmon**, al que se
anade una capa de **deteccion de anomalias con ML** para reducir los falsos positivos de las
reglas estaticas.

> Estado: en desarrollo. Recoleccion de telemetria y generacion de trafico normal funcionando;
> pipeline de ML y evaluacion con ataques etiquetados en curso.

## Arquitectura

| Componente | Rol |
|---|---|
| Ubuntu Server | Wazuh manager + indexer + dashboard (all-in-one) |
| Windows (victima) | Agente Wazuh, Sysmon y Suricata (Npcap) |
| Kali Linux | Generacion de ataques (Nmap, fuerza bruta, Atomic Red Team) |

Flujo: Sysmon/Windows + eve.json de Suricata -> agente Wazuh -> manager -> indices `wazuh-alerts-*` y
`wazuh-archives-*` -> features -> modelo de anomalias -> alerta.

## Contenido

- `docs/SOC-ML-Lab-Guia-Completa.md`: guia paso a paso para reproducir el laboratorio.
- `scripts/windows/`: tres generadores de trafico normal (limpio, variado con ritmo diurno y ruidoso que
  provoca falsos positivos de las reglas estaticas).
- `suricata/custom.rules`: regla propia para escaneo de puertos (MITRE T1046).
- `data/attack_windows_template.csv`: plantilla para registrar las ventanas de ataque (etiquetado).
- `ml/`: pipeline de ML (en desarrollo).

## Metodologia de etiquetado

Las etiquetas **no** salen de lo que Wazuh marca como alerta, sino de un registro manual de ventanas de
ataque (hora UTC de inicio y fin). Todo lo que ocurre fuera de esas ventanas se considera trafico normal.
Para los eventos de red se usa la hora del evento (`flow.start`), no la de ingesta, porque los flujos
se escriben con retraso.

## Aviso

Proyecto educativo. Los ataques se ejecutan unicamente contra maquinas propias dentro de un laboratorio
aislado. No uses estas tecnicas contra sistemas sin autorizacion expresa.

## Licencia

MIT
