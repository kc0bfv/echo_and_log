# Echo and Log

## Description
This is a small Python3 script that listens on TCP ports, echoes received data back to the sender, and logs connections and data.

The purpose is to characterize the data sent to arbitrary ports, enabling users to quickly determine what protocols they're seeing to ports on their honeypot.  Defenders could then place more relevant software listening on those ports to improve honeypot interactions.

## Usage
```sh
sudo ./echo\_and\_log.py -p "15,20,30,55"
```

Sudo is not necessary if you're using unprivileged ports, or have set capabilities correctly.  Echo\_and\_log's first steps, though, are to begin listening and drop root privileges, hopefully mitigating most problems with running as root.

You can also set this up to run at startup...  See Setup below.

# Requires
python3-logstash

# Setup
Edit the "ExecStart" line in echo\_and\_log.service to add whatever command line options you need.

```
sudo pip3 install python3-logstash
sudo cp echo_and_log.service /etc/systemd/system/
sudo mkdir /opt/echo_and_log
sudo cp echo_and_log.py /opt/echo_and_log/
sudo systemctl enable echo_and_log
sudo service echo_and_log restart
```

View any output from the running program with `journactl -u echo_and_log`.
