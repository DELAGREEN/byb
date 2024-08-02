import pydivert
import re

# Функция для модификации пакета
def modify_packet(packet):
    payload = packet.tcp.payload.decode(errors='ignore')
    
    # Замена Host заголовка на hoSt
    payload = re.sub(r'Host:', 'hoSt:', payload)
    
    # Удаление пробела между именем заголовка и значением в Host заголовке
    payload = re.sub(r'Host: ', 'Host:', payload)
    
    # Добавление дополнительного пространства между HTTP-методом и URI
    payload = re.sub(r'(GET|POST) /(.*)', r'\1  /\2', payload)
    
    packet.tcp.payload = payload.encode()
    return packet

# Запуск перехвата и модификации пакетов
def main():
    with pydivert.WinDivert("tcp.DstPort == 80 or tcp.SrcPort == 80") as w:
        for packet in w:
            if packet.is_inbound:
                packet = modify_packet(packet)
            w.send(packet)

if __name__ == "__main__":
    main()
