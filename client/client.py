#
# Diogo Daniel Soares Ferreira N 76504
# Luis Davide Jesus Leira N 76514
#
# Segurity Messaging Repository System 2017-2018

import sys
import time
import threading
from socket import *
from select import *
from log import *
from users import Users
from client_server import Server
from client_actions import *
import getpass


# Server address
HOST = ""   # All available interfaces
PORT = 8080  # The server port

# Maximum buffer size for one chunk
CHUNKSIZE = 64 * 1024

# Flag to stop the execution loop
STOP_LOOP = 0

# Lock for synchronization of both threads
LOCK = threading.Lock()



class Client:
	def __init__(self, host, port, user):
		self.cs = socket(AF_INET, SOCK_STREAM)  # the client socket (IP \ TCP)
		self.cs.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
		address = (host, port)
		self.cs.connect(address)

		log(logging.INFO, "Client connected to server on %s" %
			str(self.cs.getsockname()))

		self.server = Server(self.cs, address)

		self.user = user
		# Actions available to the client
		self.client_actions = ClientActions(self.server, self.user)



	def close(self):
		'''
			Closes the client socket with the server
		'''
		log(logging.INFO, "Closing client")
		try:
			self.cs.close()
		except:
			logging.exception("Client was already closed")


	def flushout(self):
		'''
			Writes a chunk of data to the server
			If there is too much data, send only part of it 
			and send the data left on other chunk
		'''
		try:
			sent = self.cs.send(bytes(self.server.outbuffer[:CHUNKSIZE], "utf-8"))

			log(logging.DEBUG, "Sent %d bytes to %s. Message:\n%r" %
				(sent, self.cs.getsockname(), self.server.outbuffer[:sent]))

			# leave remaining to be sent later
			self.server.outbuffer = self.server.outbuffer[sent:]

		except Exception as e:
			logging.error("Cannot write to server %s. Client closing.." % str(self.cs.getsockname()))
			self.close()


	def flushin(self):
		'''
			Reads a chunk of data from the client
		'''
		try:
			data = self.cs.recv(CHUNKSIZE)
			log(logging.DEBUG,
				"Received data from %s. Message:\n%r" % (str(self.cs.getsockname()), data))
			
		except:
			logging.error("Cannot read from server %s. Closing...", str(self.cs.getsockname()))
			self.close()

		else:
			if len(data) > 0:
				try:
					messages, self.client_actions.sessionKey = self.server.parseMessages(data.decode("utf-8"), self.client_actions.sessionKey, self.client_actions.salt)
				except Exception as e:
					print(e)
					logging.error("Cannot parse message %s. Client closing.." % str(data))
					self.close()
					return

				
				for message in messages:
					self.client_actions.readMessage(message)

			else:
				log(logging.INFO, "Server %s sent 0 bytes to client. Client closing..." % str(self.cs.getsockname()))
				self.close()


	def chooseAction(self):
		'''
			Prints the menu to the user and waits for the response.
		'''

		# Wait for the client to establish connection and create client if needed
		while not self.client_actions.canCommunicate:
			pass

		while True:


			print (bcolors.HEADER  + 'Secure Messaging Repository System\n' + bcolors.ENDC)
			print (
				  bcolors.OKBLUE + '1 - List users\' messages boxes\n' + \
				  bcolors.OKBLUE + '2 - List new messages received\n' + \
				  bcolors.OKBLUE + '3 - List all messages received/sent\n' + \
				  bcolors.OKBLUE + '4 - Send message to a user\n' + \
				  bcolors.OKBLUE + '5 - Receive a message\n' + \
				  bcolors.OKBLUE + '6 - Check the reception status of a sent message\n' + bcolors.ENDC)

			num = int(input("From 1 to 6, choose your option: "))

			

			try:
				if num==1:
					tid = int(input("Insert target user id or type 0 if you want all: "))
					LOCK.acquire()
					if tid == 0:
						self.client_actions.processList()
					else:
						self.client_actions.processList(tid)
					LOCK.release()
				elif num==2:
					LOCK.acquire()
					self.client_actions.processNew()
					LOCK.release()
				elif num==3:
					LOCK.acquire()
					self.client_actions.processAll()
					LOCK.release()
				elif num==4:
					dst = int(input("Insert the destination id: "))
					msg = input("Insert the message: ")
					LOCK.acquire()
					self.client_actions.processGetPublicKey(dst, msg)
					LOCK.release()
				elif num==5:
					msg = input("Insert the message id: ")
					LOCK.acquire()
					self.client_actions.processRecv(msg)
					LOCK.release()
				elif num==6:
					msg = input("Insert the sent message id: ")
					LOCK.acquire()
					self.client_actions.processStatus(msg)
					LOCK.release()

			except Exception as e:
				print(e)
				if(LOCK.locked()):
					LOCK.release()
				return


	def loop(self):
		'''
			Main loop for client receiving and sending data to server
		'''
		while True:

			# Sockets to be read
			reading_slist = [self.cs]
			writing_slist = []

			LOCK.acquire()

			try:
				# If there is data in the buffer, send it to server
				if self.server.outbuffer:
					log(logging.INFO, "Out buffer is not empty.")
					writing_slist += [self.cs]

				(rslist, wslist, excslist) = select(reading_slist, writing_slist, reading_slist, 0)


				for s in rslist:
					log(logging.INFO, "Reading data from server %s." % str(s.getsockname()))
					self.flushin()

				for s in wslist:
					log(logging.INFO, "Sending data to server %s." % str(s.getsockname()))
					self.flushout()

				for s in excslist:
					log(logging.ERROR, "EXCEPTION in server %s." % str(s.getsockname()))

			except:
				if(LOCK.locked()):
					LOCK.release()

			if(LOCK.locked()):
				LOCK.release()

			if (STOP_LOOP==1):
				break



def startMenu():
	num = -1
	users = Users()
	
	while(num<1 or num>2):
		print (bcolors.HEADER  + '----- Welcome to the Secure Messaging Repository System -----' + bcolors.ENDC)
		print (bcolors.OKBLUE + '1 - Login\n' + \
			bcolors.OKBLUE + '2 - Register new user' + bcolors.ENDC)
		num = int(input("-> "))

		if(num==1):
			username = input("Username: ")
			password = getpass.getpass("Password: ")
			user = users.getUser(username, password)
			if not user or user==None:
				num = -1
				print("The user could not be logged in")

		elif(num==2):
			userValid = False
			while not userValid:
				username = input("New username: ")
				userValid = not users.checkIfUserExists(username)
				if userValid == False:
					print("User already exists")
			
			password = getpass.getpass("New password: ")
			
			user = users.createUser(username, password)
			if user==False:
				num = -1
				print("User could not be created")
			
	return user

if __name__ == "__main__":

	if len(sys.argv) > 1:
		PORT = int(sys.argv[1])

	logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
	user = startMenu()
	cl = None
	while True:
		try:
			t = None
			log(logging.INFO, "Starting Client to connect to server")
			cl = Client(HOST, PORT, user)
			t = threading.Thread(name='clientLoop', target=cl.loop)

			STOP_LOOP = 0
			t.start()
			cl.client_actions.initiateKeyExchange()
			cl.chooseAction()

		except KeyboardInterrupt:
			STOP_LOOP = 1
			if (t):
				t.join()
			if(cl):
				cl.close()
			try:
				log(logging.INFO, "Press CTRL-C again within 2 sec to quit")
				time.sleep(2)
			except KeyboardInterrupt:
				log(logging.INFO, "CTRL-C pressed twice: Quitting!")
				break
		except:
			logging.exception("Client ERROR")
			STOP_LOOP = 1
			if(t):
				t.join()
			if cl is not (None):
				cl.close()
			time.sleep(1)

