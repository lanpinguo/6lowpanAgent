import lowpan.message as message
import lowpan.tunnel as tunnel 

if __name__ == '__main__':
	import lowpan.selftest as selftest
	buf = selftest.test_pkt
	raw_pkt = message.parse_pkt(buf)
	print(type(raw_pkt))
	print(raw_pkt)
	print(raw_pkt.layers)

	vt = tunnel.VirtualTunnel()
	vt.start()

	while True:
		data = input('>')
		print(data)
	vt.kill()
