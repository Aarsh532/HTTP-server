# Aarsh Dadan : and126
# Command to start server: python server.py 127.0.0.1 8080 accounts.json 5 accounts/
import socket, json, random, datetime, hashlib, sys

# Function to send time stamp logs server side
def TimeStamp_Msg(message):
    time = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    print(f"SERVER LOG: {time} {message}")
        
# Function to handle the two methods
def MethodHandler(one, two, accounts, timer, five, sSock):
    cStorage = {}
    
    # Msgs to send to client
    msg1 = "HTTP/1.0 200 OK\r\nContent-type: text/plain\r\n\r\nLogin Failed!"
    msg2 = "HTTP/1.0 401 Unauthorized\r\nContent-Type: text/plain\r\n\r\nUnauthorized"
    msg3 = "501 Not Implemented"
    msg4 = "404 NOT FOUND"
    
    while True:
            cSock, cAddy = sSock.accept()
            D = cSock.recv(1024).decode('utf-8')
            L = D.split('\r\n')
            M, P, V = L[0].split()
            httpHeader = {line.split(': ')[0]: line.split(': ')[1] for line in L[1:] if line}
            
            # Post 
            if M == "POST":
                if P == '/':
                    username = httpHeader.get('username')
                    password = httpHeader.get('password')
                    
                    if not username or not password:
                        cSock.sendall(msg3.encode('utf-8'))
                        TimeStamp_Msg("LOGIN FAILED")
                        cSock.close()
                        continue
                    
                    accountsList = accounts.get(username)
                    if not accountsList:
                        cSock.sendall(msg1.encode('utf-8'))
                        TimeStamp_Msg(f"LOGIN FAILED: {username} : {password}")
                        cSock.close()
                        continue

                    cPass, temp = accountsList
                    temp2 = password
                    temp2 += temp
                    m = hashlib.sha256()
                    m.update(temp2.strip().encode('utf-8'))
                    hPass = m.hexdigest()
                    
                    if cPass == hPass:
                        ID = random.getrandbits(64)
                        cookie = f"sessionID=0x{ID:x}"
                        cStorage[cookie] = [username, datetime.datetime.now()]
                        body = "Logged in!"
                        header = f"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: {cookie}\r\n\r\n"
                        sendToClient = header + body
                        cSock.sendall(sendToClient.encode('utf-8'))
                        TimeStamp_Msg(f"LOGIN SUCCESSFUL: {username} : {password}")
                        cSock.close()
                        continue
                    
                    cSock.sendall(msg1.encode('utf-8'))
                    TimeStamp_Msg(f"LOGIN FAILED: {username} : {password}")
                    cSock.close()
                    continue
            
            # Get  
            if M == "GET":
                accountsList = cStorage.get(httpHeader.get('Cookie').strip())
                if not accountsList:
                    TimeStamp_Msg(f"COOKIE INVALID: {P}")
                    cSock.sendall(msg2.encode('utf-8'))
                    cSock.close()
                    continue
                user, timestamp = accountsList
                if (datetime.datetime.now() - timestamp).seconds > timer:
                    TimeStamp_Msg(f"SESSION EXPIRED: {user} : {P}")
                    cSock.sendall(msg2.encode('utf-8'))
                    cSock.close()
                    continue
                try:
                    with open(f"{five}{user}{P}") as f:
                        line = f.readlines()[0].strip()
                        cSock.sendall(f"HTTP/1.0 200 OK\n\n{line}".encode('utf-8'))
                        TimeStamp_Msg(f"GET SUCCEEDED: {user} : {P}")
                except FileNotFoundError:
                    cSock.sendall(msg4.encode('utf-8'))
                    TimeStamp_Msg(f"GET FAILED: {user} : {P}")
                    cSock.close()
                    continue
            cSock.close()
    
# Function to Start Server      
def StartUpServer(one, two, accounts, timer, five):
    sSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sSock.bind((one, int(two)))
    sSock.listen(1)
    
    try:
        MethodHandler(one, two, accounts, timer, five, sSock)
                      
    except KeyboardInterrupt:
        sSock.close()

def main():
    if len(sys.argv) != 6:
        print("Invalid Command")
        sys.exit(1)
       
    accounts = json.loads(open(sys.argv[3]).readlines()[0])
    StartUpServer(sys.argv[1], sys.argv[2], accounts, int(sys.argv[4]), sys.argv[5])

if __name__ == "__main__":
    main()