o#!/bin/bash
mongod --dbpath db --bind_ip 127.0.0.1 --fork --syslog	#Starts the database
sudo npm start		#Starts the server
