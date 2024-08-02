from scapy.all import *
import re

# Функция для модификации пакета
def modify_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode(errors='ignore')

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

        # Проверка и фрагментация пакета, если его размер превышает MTU
        if len(packet) > 1500:  # Предполагается, что 1500 - это размер MTU
            fragments = fragment(packet, fragsize=1440)  # 1440 для учёта заголовков IP и TCP
            for frag in fragments:
                send(frag)
        else:
            send(packet)

# Захват и модификация пакетов
def packet_callback(packet):
    if packet.haslayer(TCP):
        modify_packet(packet)

# Установить правила iptables для перенаправления трафика на локальный порт 9999
import os
os.system('iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 9999')

# Запуск захвата пакетов
sniff(prn=packet_callback, filter='tcp', store=0)
