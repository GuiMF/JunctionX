import pyshark
import uuid # Para gerar IDs únicos para o campo "id" exigido pelo schema

# 1. Atualizar o Registry para devolver os campos exatos do Schema
CIPHER_REGISTRY = {
    # Exemplo Clássico e Crítico (Vulnerável ao Algoritmo de Shor)
    "0x002f": {
        "nome": "TLS_RSA_WITH_AES_128_CBC_SHA",
        "quantum_status": "vulnerable",
        "challenge_tier": "critical",
        "usage": "key_establishment" # RSA usado para troca de chaves
    },
    # Exemplo Simétrico Forte (Seguro contra Shor, Enfraquecido por Grover mas considerado seguro se a chave for grande o suficiente)
    "0x1301": {
        "nome": "TLS_AES_128_GCM_SHA256",
        "quantum_status": "vulnerable", # AES-128 é vulnerável a Grover
        "challenge_tier": "medium",
        "usage": "encryption"
    }
}

def parse_pcap(file_path):
    capture = pyshark.FileCapture(file_path, keep_packets=False)
    
    for packet in capture:
        try:
            if 'TLS' in packet and hasattr(packet.tls, 'handshake_type'):
                handshake_type = packet.tls.handshake_type
                
                # ... (O teu código do ClientHello type == "1" fica aqui) ...
                
                if handshake_type == "2":
                    selecao = packet.tls.handshake_ciphersuite
                    frame_number = packet.number
                    capture_time = packet.sniff_time
                    tcp_stream = packet.tcp.stream
                    ip_src = packet.ip.src
                    ip_dst = packet.ip.dst

                    # 2. Consultar o Registo
                    cifra_info = CIPHER_REGISTRY.get(selecao, {
                        "nome": selecao, 
                        "quantum_status": "unknown", 
                        "challenge_tier": "unknown",
                        "usage": "unknown"
                    })
                    
                    # 3. Construir o "Finding" Exatamente como o Schema exige
                    finding = {
                        "id": str(uuid.uuid4()),  # ID único para esta descoberta
                        "asset_id": f"tcp-stream-{tcp_stream}-{ip_src}-{ip_dst}",
                        "source_type": "pcap",
                        "algorithm": cifra_info["nome"],
                        "usage": cifra_info["usage"],
                        "evidence_kind": "observed", # Visto numa seleção de servidor
                        "evidence": [
                            {
                                "file": file_path,
                                "locator": f"frame:{frame_number}",
                                "detail": f"ServerHello selected cipher suite {selecao}"
                            }
                        ],
                        "confidence": "high",
                        "quantum_status": cifra_info["quantum_status"],
                        "challenge_tier": cifra_info["challenge_tier"],
                        "observed_at": capture_time.isoformat() # Converte data para string ISO
                    }
                    
                    print("--- FINDING GERADO (HANDOFF HOUR 3) ---")
                    import json
                    print(json.dumps(finding, indent=2))
                    print("---------------------------------------\n")
                    
                    # Se só precisas de entregar UM para a Hora 3, podes fazer "break" aqui 
                    # para testar, ou deixar correr para processar todo o ficheiro.

        except AttributeError:
            pass

    capture.close()


if __name__ == "__main__":
    # Coloca o nome exato do ficheiro pcap que descarregaste
    caminho_do_pcap = "network.pcap" 
    parse_pcap(caminho_do_pcap)