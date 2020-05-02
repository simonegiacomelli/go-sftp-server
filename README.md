## go-sftp-server

Simple sftp server written in go - one source file

You need to feed the private key to the server. You can generate them with the following command:

ssh-keygen -t rsa -b 4096 -C "golang-sftp@example.com" -f  ./id_rsa


## Command line options
  -R    read-only server
  
  -e    debug to stderr (default true)
  
  -pass string
        password (default "tiger")
        
  -port int
        tcp port (default 2022)
        
  -user string
        username (default "testuser")
