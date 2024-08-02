from scapy.all import *
import re
import os

# Функция для модификации пакета
def modify_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
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
            
            # Фрагментация пакета, если он слишком большой
            fragmented_packets = fragment(packet, fragsize=1400)
            for frag in fragmented_packets:
                send(frag, verbose=False)
        except Exception as e:
            print(f"Error modifying packet: {e}")

# Захват и модификация пакетов
def packet_callback(packet):
    if packet.haslayer(TCP):
        modify_packet(packet)

try:
    # Установить правила iptables для перенаправления трафика на локальный порт 9999
    os.system('sudo iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 9999')
    os.system('sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 9999')

    # Запуск захвата пакетов
    sniff(prn=packet_callback, filter='tcp', store=0)
except PermissionError:
    print("Ошибка: необходимо запустить скрипт с правами суперпользователя (sudo).")
except Exception as e:
    print(f"Произошла ошибка: {e}")
