#!/usr/bin/python3

# Student name and No.:
# Student name and No.:
# Development platform:
# Python version:
# Version:


from tkinter import *
import sys
import socket
import threading
import collections

#
# Global variables
#

username = ""
roomname = ""
joined = False
ser_addr = ""#////////////S
ser_port = ""
local_port = ""
chatroom_list = {}
local_IP = ""
TheSoc =socket.socket()
MSID = 0
backward_list = {}
forward_list = {}


#
# This is the hash function for generating a unique
# Hash ID for each peer.
# Source: http://www.cse.yorku.ca/~oz/hash.html
#
# Concatenate the peer's username, str(IP address),
# and str(Port) to form the input to this hash function
#
def sdbm_hash(instr):
	hash = 0
	for c in instr:
		hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff

#
# Setup connection
#
def setupConn(): #//////////S
	global local_IP
	global TheSoc
	TheSoc.bind(("0.0.0.0", int(local_port)))
	try:
		TheSoc.connect((ser_addr, int(ser_port)))
	except socket.error as emsg:
		print("There is error with connecting: ", emsg)
		sys.exit(0)
	local_addr = TheSoc.getsockname()
	local_IP = local_addr[0]
	print(local_IP)

#
# Create userIP
#
def create_myHashID(): #////////S
	idDraft = username+str(local_addr[0])+local_port
	userID = sdbm_hash(idDraft)
	print(str(userID))
	return userID
#
# Sort a dictionary
#
def sort_list(list):#///////////S
	return collections.OrderedDict(sorted(list.items()))

#
# Find the index of the object in a dictionary -- chatroom_list
#
def index_of(key):
	return list(chatroom_list.keys()).index(key)

#
# Select a P2PChat peer ofr initiating forward link
#
def create_forwardlink():
	MyHashID = create_myHashID()
	start = int(index_of(MyHashID)) + 1
	items = list(chatroom_list.values()) # list of the value, which are the user's information [hashid,name,IP addr, port]
	while items[start][0] != MyHashID : # items[start][0] = the hashid of the users
		if items[start][0] in backward_list: # backward_list stores the hashid of the peers that have connection with the user (backward link)
			start = (start+1)%len(chatroom_list)
			continue
		else:
			TheSoc.connect()

#
# Keep Alive
#
def keepalive():
	global MSID
	global chatroom_list
	#Run the function every 20 seconds
	threading.Timer(20.0, keepalive).start()

	#Send Join message
	msg = "J:"+roomname+":"+username+":"+local_IP+":"+local_port+"::\r\n"
	TheSoc.send(msg.encode("ascii"))

	#Handle chatroom user list
	msg = TheSoc.recv(1000)
	rMsg = msg.decode("ascii")
	sMsg = rMsg.split(':')
	if sMsg[0] == 'M': #/////////////S
		#check if the user list changed
		if MSID == sMsg[1]:
			print("keepalive: There is no change in userlist")
		else:
			#update the userlist
			MSID = sMsg[1]
			i = 2
			user = [0,0,0,0]
			while sMsg[i] != '':
				k = i-2
				if k%3 == 0:
					user[1] = sMsg[i]
				if k%3 == 1:
					user[2] = sMsg[i]
				if k%3 == 2:
					user[3] = sMsg[i]
				if user[3] != 0:
					imsg = user[1]+user[2]+user[3]
					usr_id = sdbm_hash(imsg)
					user[0]=usr_id
					chatroom_list[usr_id]=user
					user = [0,0,0,0]
					MMsg = "\nname: "+chatroom_list[usr_id][1]+" user_ip: "+chatroom_list[usr_id][2]+" user_port: "+chatroom_list[usr_id][3]+"\n"
					CmdWin.insert(1.0,MMsg)
				i += 1
			chatroom_list = sort_list(chatroom_list)
			print("##Keepalive:: Sorted chatroom_list : ", chatroom_list)

#
# Threading Timer
#
t = threading.Timer(20.0, keepalive)



#
# Functions to handle user input
#

def do_User():
	print(str(joined))
	if joined == True:
		CmdWin.insert(1.0,"\nYou have joined a chatroom. You cannot change your username.")
		userentry.delete(0,END)
	else:
		global username
		username = userentry.get()
		if username != '':
			outstr = "\n[User] username: "+username
			CmdWin.insert(1.0, outstr)
			userentry.delete(0, END)
		else:
			CmdWin.insert(1.0,"\nPlease input your username")


def do_List():
	CmdWin.insert(1.0, "\nPress List")
	msg = "L::\r\n"
	TheSoc.send(msg.encode("ascii"))
	msg = TheSoc.recv(1000)
	rMsg = msg.decode("ascii")
	if rMsg == "G::\r\n":
		CmdWin.insert(1.0,"\nThere is no chatroom group")
	else:
		msg = rMsg.split(':')
		if msg[0] != 'F':
			CmdWin.insert(1.0,"\nNow listing the chatroom groups..............")
			i = 1
			while msg[i] != '':
				CmdWin.insert(1.0, "\n"+msg[i])
				i +=1
		else:
			CmdWin.insert(1.0,"\nThere is error:")
			CmdWin.insert(1.0, msg[1])


def do_Join():
	CmdWin.insert(1.0, "\nPress JOIN")
	global chatroom_list
	global joined
	global roomname
	global MSID
	roomname = userentry.get()
	if roomname == '' :
		CmdWin.insert(1.0, "Please input a chatroom name. If the chatroom you typed in does not exist, we will open up one for you. ")
	else:
		if joined == True:
			CmdWin.insert(1.0,"You have joined a chatroom already.")
		else:
			joined = True
			userentry.delete(0, END)
			msg = "J:"+roomname+":"+username+":"+local_IP+":"+local_port+"::\r\n"
			TheSoc.send(msg.encode("ascii"))
			msg = TheSoc.recv(1000)
			rMsg = msg.decode("ascii")
			sMsg = rMsg.split(':')
			if sMsg[0] == 'M':
				MSID = sMsg[1]
				## store the list of users in the chatroom
				# in the list chatroom_list
				i = 2
				#usr_num = 1///////S
				user = [0,0,0,0]
				while sMsg[i] != '':
					k = i-2
					if k%3 == 0:
						user[1] = sMsg[i]
					if k%3 == 1:
						user[2] = sMsg[i]
					if k%3 == 2:
						user[3] = sMsg[i]
					if user[3] != 0:
						imsg = user[1]+user[2]+user[3]
						usr_id = sdbm_hash(imsg)
						user[0]=usr_id
						chatroom_list[usr_id]=user
						user = [0,0,0,0]
						MMsg = "\n name: "+chatroom_list[usr_id][1]+" user_ip: "+chatroom_list[usr_id][2]+" user_port: "+chatroom_list[usr_id][3]+"\n"
						CmdWin.insert(1.0,MMsg)


					i += 1
				chatroom_list = sort_list(chatroom_list)
				print("##Sorted chatroom_list : ", chatroom_list)
				CmdWin.insert(1.0, "You have now joined the chatroom, "+ roomname )
				t.start()
			else:
				CmdWin.insert(1.0,"\nThere is error:")
				CmdWin.insert(1.0, sMsg[1])

def do_Send():
	CmdWin.insert(1.0, "\nPress Send")


def do_Quit():
	CmdWin.insert(1.0, "\nPress Quit")
	t.cancel()
	TheSoc.close()#/////
	sys.exit(0)
#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt01 = Button(topmidframe, width='8', relief=RAISED, text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8);
Butt02 = Button(topmidframe, width='8', relief=RAISED, text="List", command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='8', relief=RAISED, text="Join", command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='8', relief=RAISED, text="Send", command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='8', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)



def main():
	global ser_addr
	global ser_port
	global local_port
	if len(sys.argv) != 4:
		print("P2PChat.py <server address> <server port no.> <my port no.>")
		sys.exit(2)
	else:

		ser_addr = sys.argv[1]
		ser_port = sys.argv[2]
		local_port = sys.argv[3]
		setupConn()

	win.mainloop()

if __name__ == "__main__":
	main()
