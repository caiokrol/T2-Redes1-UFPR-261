from scapy.all import *
import time

# ---------------------------------------------------------
# 1. DEFINIÇÃO DO PROTOCOLO E LIGAÇÃO COM ETHERNET
# ---------------------------------------------------------
class Secret(Packet):
    name = "SecretHeader"
    fields_desc = [
        ByteField("msg_type", 1), 
        StrFixedLenField("token", b"MINHASENHASECRE1", 16) 
    ]

# Avisa o Scapy que o ether_type do nosso protocolo é 0x1234
bind_layers(Ether, Secret, type=0x1234)


# ---------------------------------------------------------
# 2. FUNÇÃO AUXILIAR PARA PRINTAR E ENVIAR BONITINHO
# ---------------------------------------------------------
def disparar(nome_teste, pacote, pausa=1.5):
    print(f"[>>>] {nome_teste}")
    sendp(pacote, iface="veth0", verbose=False)
    time.sleep(pausa)


# ---------------------------------------------------------
# 3. BATERIA DE TESTES
# ---------------------------------------------------------
print("="*60)
print(" INICIANDO TESTES FIREWALL P4 ")
print("="*60)
print(" tcpdump observando (veth8)! ")
print(" Apenas os pacotes [TESTE 1B] e [TESTE 5C] devem chegar.")
print("="*60 + "\n")

# --- TESTE 1: O Acesso Legítimo ---
pkt_gravar = Ether(dst="00:00:00:00:00:02", type=0x1234) / Secret(msg_type=1, token=b"MINHASENHASECRE1") / Raw(load="A" * 80)
pkt_msg_ok = Ether(dst="00:00:00:00:00:02", type=0x1234) / Secret(msg_type=2, token=b"MINHASENHASECRE1") / Raw(load="[TESTE 1B] MENSAGEM VIP AUTORIZADA! " + "B" * 60)

disparar("TESTE 1A: Gravando a senha oficial na SRAM (Dropado no switch)...", pkt_gravar, 1)
disparar("TESTE 1B: Enviando msg com a senha CORRETA (DEVE CHEGAR LÁ).", pkt_msg_ok)


# --- TESTE 2: O Hacker da Senha Errada ---
pkt_msg_errada = Ether(dst="00:00:00:00:00:02", type=0x1234) / Secret(msg_type=2, token=b"SENHAERRADAAAAAA") / Raw(load="[TESTE 2] Ataque Hacker! " + "C" * 60)
disparar("TESTE 2: Enviando msg com senha ERRADA (DEVE SER DROPADO).", pkt_msg_errada)


# --- TESTE 3: O Pacote de Internet Comum (IPv4) ---
# Simulando alguém que tentou dar um ping na porta de entrada do switch
pkt_ipv4 = Ether(dst="00:00:00:00:00:02", type=0x0800) / IP(dst="192.168.1.2") / ICMP() / Raw(load="[TESTE 3] Ping normal " + "D" * 60)
disparar("TESTE 3: Enviando ping IPv4 comum (DEVE CAIR NO ELSE DA MORTE).", pkt_ipv4)


# --- TESTE 4: Tipo de Mensagem Inválido ---
# Alguém tentou usar nosso protocolo, acertou o type 0x1234, mas botou um tipo de mensagem que não existe (tipo 9)
pkt_tipo_lixo = Ether(dst="00:00:00:00:00:02", type=0x1234) / Secret(msg_type=9, token=b"MINHASENHASECRE1") / Raw(load="[TESTE 4] Tipo Invalido " + "E" * 60)
disparar("TESTE 4: Enviando msg com msg_type 9 (DEVE CAIR NO ELSE DO TIPO).", pkt_tipo_lixo)


# --- TESTE 5: Troca de Senha em Tempo Real ---
# Vamos sobrescrever a SRAM com uma senha nova e ver se ele bloqueia a antiga
pkt_nova_senha = Ether(dst="00:00:00:00:00:02", type=0x1234) / Secret(msg_type=1, token=b"NOVASENHA_123456") / Raw(load="F" * 80)
pkt_msg_velha  = Ether(dst="00:00:00:00:00:02", type=0x1234) / Secret(msg_type=2, token=b"MINHASENHASECRE1") / Raw(load="[TESTE 5B] Tentando senha velha " + "G" * 60)
pkt_msg_nova   = Ether(dst="00:00:00:00:00:02", type=0x1234) / Secret(msg_type=2, token=b"NOVASENHA_123456") / Raw(load="[TESTE 5C] MENSAGEM COM NOVA SENHA VIP! " + "H" * 60)

print("\n--- INICIANDO TESTE DE RECONFIGURAÇÃO DA SRAM ---")
disparar("TESTE 5A: Sobrescrevendo a SRAM com a senha 'NOVASENHA_123456'...", pkt_nova_senha, 1)
disparar("TESTE 5B: Testando acesso com a senha antiga (DEVE SER DROPADO).", pkt_msg_velha)
disparar("TESTE 5C: Testando acesso com a senha NOVA (DEVE CHEGAR LÁ).", pkt_msg_nova)


print("\n" + "="*60)
print(" BATERIA DE TESTES CONCLUIDA! ")
print(" Olhe o seu tcpdump. Se o switch estiver perfeito, só")
print(" os pacotes com as strings [TESTE 1B] e [TESTE 5C] apareceram.")
print("="*60)