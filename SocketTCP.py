import socket
import random

class SocketTCP:
    DEBUG = True

    # consideramos SEQ, SYN, ACK y FIN
    HEADER_SIZE = 4

    def __init__(self):
        # socket no orientado a conexión
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # direcciones (ip, puerto)
        self.address_dest = None
        self.address_local = None

        # proximo numero de la secuencia y el que se espera recibir para stop & wait
        self.seq_num_prox = 0
        self.seq_num_recv = 0

        self.timeout = 1.0
        self.max_package = 16

        # datos ya recibidos de la red pero aun no entregados a la aplicacion
        self.recv_buffer = bytearray()
        self.bytes_pend = 0

        self.package_pend = None

        # estados de la conexion
        self.is_connected = False
        self.is_closed = False


    def bugs(self, msg: str):
        if  self.DEBUG:
            print(f"[DEBUG] {msg}")


    @staticmethod
    def parse_segment(segment_tcp: bytes):
        if len(segment_tcp) < SocketTCP.HEADER_SIZE:
            print("error")
            return None
        else:
            seq = segment_tcp[0]
            syn = segment_tcp[1]
            ack = segment_tcp[2]
            fin = segment_tcp[3]

            package = segment_tcp[4:]

            dicc = {"seq": seq,
                    "syn": syn,
                    "ack": ack,
                    "fin": fin,
                    "data": package}

            return dicc


    @staticmethod
    def create_segment(seq, syn, ack, fin, data=b""):
        # pasamos todo a int para que no haya errores
        header = bytes([int(seq),
                        int(syn),
                        int(ack),
                        int(fin)])

        return header + data


    def bind(self, address):
        self.udp_socket.bind(address)
        self.address_local = self.udp_socket.getsockname()


    def connect(self, address):
        self.address_dest = address
        self.seq_num_prox = random.randint(0, 100)

        # enviamos el mensaje SYN
        syn_msg = self.create_segment(seq=self.seq_num_prox, syn=1, ack=0, fin=0)

        self.udp_socket.settimeout(self.timeout)

        self.bugs(f"3-Way Handshake en {address} con seq={self.seq_num_prox}")

        while True:
            self.udp_socket.sendto(syn_msg, self.address_dest)

            try:
                pkt, server_new_address = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
                segment = self.parse_segment(pkt)

                # esperamos SYN y ACK del servidor
                if segment and segment["syn"]==1 and segment["ack"]==1:
                    # actualizamos la direccion destino
                    self.address_dest = server_new_address
                    self.seq_num_recv = segment["seq"]

                    self.bugs(f"SYN+ACK recibido con seq={segment['seq']}")
                    break
                
            except socket.timeout:
                self.bugs(f"Timeout connect(): Esperando SYN+ACK, reenviando SYN")
                continue

        # enviamos el mensaje ack
        ack_msg = self.create_segment(seq=self.seq_num_prox, syn=0, ack=1, fin=0)
        self.udp_socket.sendto(ack_msg, self.address_dest)

        # siguinete seceuncia
        self.seq_num_prox = (self.seq_num_prox + 1) % 256
        self.seq_num_recv = (self.seq_num_recv + 1) % 256
        self.is_connected = True
        self.udp_socket.settimeout(None)

        self.bugs(f"3-Way Handshake finalizado en {self.address_dest}")


    def accept(self):
        self.udp_socket.settimeout(None)

        while True:
            pkt,client_address = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
            segment = self.parse_segment(pkt)

            if segment and segment["syn"]==1 and segment["ack"]==0:
                self.bugs(f"SYN en {client_address} con seq={segment['seq']}")
                break
            
        new_socket = SocketTCP()

        if self.address_local:
            ip_local = self.address_local[0] 
        else:
            ip_local= "localhost"  # al revisarlo gemini sugirió agregar este else
                    
        new_socket.bind((ip_local, 0))
        new_address = new_socket.address_local

        new_socket.address_dest = client_address
        new_socket.seq_num_recv = segment["seq"]
        new_socket.seq_num_prox = random.randint(0, 100)

        # se envia SYN y ACK al cliente
        syn_ack_msg = self.create_segment(seq=new_socket.seq_num_prox, syn=1, ack=1, fin=0)
        new_socket.udp_socket.settimeout(new_socket.timeout)

        while True:
            new_socket.udp_socket.sendto(syn_ack_msg, new_socket.address_dest)

            try:                
                ack_pkt, _ = new_socket.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
                ack_segment = self.parse_segment(ack_pkt)

                if not ack_segment:
                    continue

                # esperamos el ack del cliente
                if ack_segment["ack"]==1 and ack_segment["syn"]==0:
                    #siguiente secuencia
                    new_socket.seq_num_prox = (new_socket.seq_num_prox + 1) % 256
                    new_socket.seq_num_recv = (new_socket.seq_num_recv + 1) % 256
                    new_socket.is_connected = True
                    new_socket.udp_socket.settimeout(None)

                    self.bugs(f"Conexión establecida en {new_address} con {client_address}")
                    return new_socket, new_address

                # si el ack se perdio pero llego un segmento de datos, lo guardamos
                if ack_segment["ack"]==0 and ack_segment["syn"]==0:
                    self.bugs(f"--Caso Borde: Último ACK se perdió--")

                    #siguiente secuencia
                    new_socket.seq_num_prox = (new_socket.seq_num_prox + 1) % 256
                    new_socket.seq_num_recv = (new_socket.seq_num_recv + 1) % 256
                    new_socket.is_connected = True
                    new_socket.udp_socket.settimeout(None)

                    new_socket.package_pend = ack_segment
                    return new_socket, new_address
                
            except socket.timeout:
                self.bugs(f"Timeout accept(): Esperando ACK, reenviando SYN+ACK")
                continue


    def send_aux(self, data: bytes):  # funcion construida con ayuda de gemini
        self.udp_socket.settimeout(self.timeout)
        segment = self.create_segment(seq=self.seq_num_prox, syn=0, ack=0, fin=0, data=data)

        while True:
            self.udp_socket.sendto(segment, self.address_dest)

            try:
                ack_msg, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
                ack_segment = self.parse_segment(ack_msg)

                if not ack_segment:
                    continue
                
                # esperamos ACK de nuestro seq
                if (ack_segment["ack"]==1 and ack_segment["syn"]==0 and ack_segment["fin"]==0 and ack_segment["seq"]==self.seq_num_prox):
                    self.bugs(f"ACK recibido con seq={self.seq_num_prox}")

                    # avanza la secuencia
                    self.seq_num_prox = (self.seq_num_prox + 1) % 256
                    break
            except socket.timeout:
                self.bugs(f"Timeout: Esperando ACK y reenviando")
                continue


    def send(self, msg:bytes):
        # enviamos el segemento inicial con el largo
        length_bytes = str(len(msg)).encode()
        self.bugs("Iniciando envío...")
        self.send_aux(length_bytes)

        # enviamos el resto del mensaje
        for i in range(0, len(msg), self.max_package):
            msg_add = msg[i : i+self.max_package]
            self.send_aux(msg_add)


    def recv(self, buff_size: int):
        self.udp_socket.settimeout(None)

        # si no hay bytes pendiente por entregar, se lee el segemento 
        if self.bytes_pend == 0:
            while True:
                if self.package_pend:
                    segment = self.package_pend
                    self.package_pend = None
                else:
                    pkt, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
                    segment = self.parse_segment(pkt)

                if not segment:
                    continue

                if segment["syn"]==1 or segment["fin"]==1:
                    continue

                # enviamos ack
                ack_pkt = self.create_segment(seq=segment["seq"], syn=0, ack=1, fin=0)
                self.udp_socket.sendto(ack_pkt, self.address_dest)

                if segment["seq"] == self.seq_num_recv:
                    self.seq_num_recv = (self.seq_num_recv + 1) % 256
                    self.bytes_pend = int(segment["data"].decode())
                    break

        # bytes que se deben entregar
        bytes_to_read = min(self.bytes_pend, buff_size)

        # recibimos fragmentos y los acumulamos en recv_buffer
        while len(self.recv_buffer) < bytes_to_read:
            pkt, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
            segment = self.parse_segment(pkt)

            if not segment:
                continue

            if segment["syn"]==1 or segment["fin"]==1:
                continue

            # enviamos ack
            ack_pkt = self.create_segment(seq=segment["seq"], syn=0, ack=1, fin=0)
            self.udp_socket.sendto(ack_pkt, self.address_dest)

            if segment["seq"] == self.seq_num_recv:
                # extraemos los datos
                self.recv_buffer.extend(segment["data"])
                self.seq_num_recv = (self.seq_num_recv + 1) % 256

        result = bytes(self.recv_buffer[:bytes_to_read])
        self.recv_buffer = self.recv_buffer[bytes_to_read:]

        self.bytes_pend -= len(result)

        return result


    def close(self):
        if self.is_closed:
            return

        self.udp_socket.settimeout(self.timeout)
        fin_segment = self.create_segment(seq=self.seq_num_prox, syn=0, ack=0, fin=1)

        timeout_count = 0
        success = False

        self.bugs("Iniciando close()")

        while timeout_count < 3:
            self.udp_socket.sendto(fin_segment, self.address_dest)

            try:
                pkt, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
                segment = self.parse_segment(pkt)

                if not segment:
                    continue

                # si respondieron con fin y ack
                if segment["fin"]==1 and segment["ack"]==1:
                    self.seq_num_recv = segment["seq"]
                    self.seq_num_prox = (self.seq_num_prox + 1) % 256

                    success = True
                    break
                
            except socket.timeout:
                self.bugs(f"Timeout close(): Esperando FIN+ACK")
                timeout_count += 1

        if success:
                ack_fin_msg = self.create_segment(seq=self.seq_num_prox, syn=0, ack=1, fin=0)

                for _ in range(3):
                    self.udp_socket.sendto(ack_fin_msg, self.address_dest)

        self.udp_socket.close()
        self.is_connected = False
        self.is_closed = True
        print("Host A: Conexión cerrada\n")


    def recv_close(self):
        if self.is_closed:
            return

        self.udp_socket.settimeout(None)

        while True:
            pkt, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
            segment = self.parse_segment(pkt)

            if not segment:
                continue

            if segment["fin"] == 1:
                self.seq_num_recv = segment["seq"]
                break

        self.seq_num_recv = (self.seq_num_recv + 1) % 256
        
        ack_fin_msg = self.create_segment(seq=self.seq_num_prox, syn=0, ack=1, fin=1)
        self.udp_socket.settimeout(self.timeout)

        timeout_count = 0
        self.bugs("FIN+ACK en recv_close()")

        while timeout_count < 3:
            self.udp_socket.sendto(ack_fin_msg, self.address_dest)

            try:
                ack_msg, _ = self.udp_socket.recvfrom(self.HEADER_SIZE + self.max_package)
                ack_segment = self.parse_segment(ack_msg)

                if not ack_segment:
                    continue

                if ack_segment["ack"]==1 and ack_segment["fin"]==0:
                    break

            except socket.timeout:
                self.bugs("Timeout recv_close(): Esperando ACK")
                timeout_count += 1         

        self.udp_socket.close()
        self.is_connected = False
        self.is_closed = True
        print("Host B: Conexión cerrada\n")