from scapy.all import *
import re

# Функция для модификации пакета
def modify_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')
        
        # Фрагментация первого пакета данных на уровне TCP
        if packet[TCP].seq == 0:
            fragments = fragment(payload, fragsize=8)
            for frag in fragments:
                send(frag)
            return
        
        # Замена Host заголовка на hoSt
        payload = re.sub(r'Host:', 'hoSt:', payload)
        
        # Удаление пробела между именем заголовка и значением в Host заголовке
        payload = re.sub(r'Host: ', 'Host:', payload)
        
        # Добавление дополнительного пространства между HTTP-методом и URI
        payload = re.sub(r'(GET|POST) /(.*)', r'\1  /\2', payload)
        
        packet[Raw].load = payload.encode()
        del packet[IP].len
        del packet[IP].chksum
        del packet[TCP].chksum
        send(packet)
        
# Захват и модификация пакетов
def packet_callback(packet):
    if packet.haslayer(TCP):
        modify_packet(packet)

# Установить правила iptables для перенаправления трафика на локальный порт 9999
import os
os.system('sudo iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 9999')

# Запуск захвата пакетов
sniff(prn=packet_callback, filter='tcp', store=0)
